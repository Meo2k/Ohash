"""
Cryptography module for ohash.
Provides encryption and decryption classes for different modes.
"""

import os
import hashlib
from pathlib import Path
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import (
    SALT_SIZE, ROUNDS, KEY_SIZE, NONCE_SIZE, TAG_SIZE,
    CHUNK_DATA_SIZE, EncMode
)
from exceptions import (
    DecryptionError, 
    EncryptionError, 
    InvalidFileError, 
    InvalidModeError
)


class KeyDeriver:
    """Handles key derivation from passphrase using PBKDF2."""

    @staticmethod
    def derive(passphrase: str, salt: bytes, rounds: int = ROUNDS) -> bytes:
        """Derive encryption key from passphrase and salt."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            passphrase.encode('utf-8'),
            salt,
            rounds,
            dklen=KEY_SIZE
        )


class FileHeader:
    """Handles file header operations."""

    # Header structure: Magic(5) + Salt(16) + Rounds(4) + FileSize(8) + Nonce(12) + Mode(1)
    SIZE = 5 + 16 + 4 + 8 + 12 + 1  # 46 bytes

    @staticmethod
    def create(salt: bytes, rounds: int, file_size: int, nonce: bytes, mode: int) -> bytes:
        """Create header bytes."""
        return (
            b'OHASH' +
            salt +
            rounds.to_bytes(4, 'big') +
            file_size.to_bytes(8, 'big') +
            nonce +
            bytes([mode])
        )

    @staticmethod
    def parse(header_bytes: bytes) -> Tuple[bytes, int, int, bytes, int]:
        """Parse header bytes. Returns (salt, rounds, file_size, nonce, mode)."""
        pos = 0

        # Magic (skip, already verified)
        pos += 5

        # Salt
        salt = header_bytes[pos:pos + SALT_SIZE]
        pos += SALT_SIZE

        # Rounds
        rounds = int.from_bytes(header_bytes[pos:pos + 4], 'big')
        pos += 4

        # File size
        file_size = int.from_bytes(header_bytes[pos:pos + 8], 'big')
        pos += 8

        # Nonce
        nonce = header_bytes[pos:pos + NONCE_SIZE]
        pos += NONCE_SIZE

        # Mode
        mode = header_bytes[pos]

        return salt, rounds, file_size, nonce, mode


class BlockCipher:
    """
    Block-based encryption (--bck mode).
    Uses single nonce for entire file.
    """

    def __init__(self, key: bytes):
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
        """Encrypt plaintext with AES-GCM."""
        return self._aesgcm.encrypt(nonce, plaintext, None)

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """Decrypt ciphertext with AES-GCM."""
        return self._aesgcm.decrypt(nonce, ciphertext, None)


class ChunkCipher:
    """
    Chunked encryption (--cnk mode).
    Each chunk has its own nonce and authentication tag.
    """

    def __init__(self, key: bytes):
        self._aesgcm = AESGCM(key)

    def encrypt_chunk(self, plaintext: bytes, master_nonce: bytes, chunk_index: int) -> bytes:
        """Encrypt a single chunk with derived nonce."""
        # Nonce = master_nonce XOR'ed with chunk_index to keep it 12 bytes
        chunk_bytes = chunk_index.to_bytes(12, 'big')
        nonce = bytes(i ^ j for i, j in zip(master_nonce, chunk_bytes))
        return self._aesgcm.encrypt(nonce, plaintext, None)

    def decrypt_chunk(self, ciphertext: bytes, master_nonce: bytes, chunk_index: int) -> bytes:
        """Decrypt a single chunk with derived nonce."""
        chunk_bytes = chunk_index.to_bytes(12, 'big')
        nonce = bytes(i ^ j for i, j in zip(master_nonce, chunk_bytes))
        return self._aesgcm.decrypt(nonce, ciphertext, None)


class Encrypter:
    """
    Main encryption class that handles file encryption.
    Supports both block (--bck) and chunked (--cnk) modes.
    """

    def __init__(self, passphrase: str, salt: Optional[bytes] = None):
        self._salt = salt or os.urandom(SALT_SIZE)
        self._key = KeyDeriver.derive(passphrase, self._salt)
        self._master_nonce = os.urandom(NONCE_SIZE)

    @property
    def salt(self) -> bytes:
        return self._salt

    @property
    def rounds(self) -> int:
        return ROUNDS

    @property
    def nonce(self) -> bytes:
        return self._master_nonce

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt entire plaintext in block mode."""
        cipher = BlockCipher(self._key)
        return cipher.encrypt(plaintext, self._master_nonce)

    def encrypt_file(self, input_path: Path, output_path: Path, mode: int = EncMode.CNK,
                     progress_callback: Optional[callable] = None) -> int:
        """
        Encrypt file with specified mode.

        Args:
            input_path: Path to input file
            output_path: Path to output encrypted file
            mode: Encryption mode (EncMode.BCK or EncMode.CNK)
            progress_callback: Optional callback(current, total) for progress

        Returns:
            Number of chunks processed
        """
        file_size = input_path.stat().st_size

        if mode == EncMode.BCK:
            return self._encrypt_block_mode(input_path, output_path, file_size, progress_callback)
        elif mode == EncMode.CNK:
            return self._encrypt_chunk_mode(input_path, output_path, file_size, progress_callback)
        else:
            raise EncryptionError(f"Invalid encryption mode: {mode}")

    def _encrypt_block_mode(self, input_path: Path, output_path: Path, file_size: int,
                            progress_callback: Optional[callable]) -> int:
        """Encrypt using block mode (single nonce)."""
        cipher = BlockCipher(self._key)

        # Read entire file
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # Encrypt
        ciphertext = cipher.encrypt(plaintext, self._master_nonce)

        # Write header and ciphertext
        header = FileHeader.create(self._salt, ROUNDS, file_size, self._master_nonce, EncMode.BCK)

        is_inplace = (input_path.absolute() == output_path.absolute())
        temp_output = output_path.with_suffix('.ohash.tmp') if is_inplace else output_path

        try:
            with open(temp_output, 'wb') as f:
                f.write(header)
                f.write(ciphertext)

            if is_inplace:
                temp_output.replace(output_path)
        except Exception:
            if is_inplace and temp_output.exists():
                temp_output.unlink()
            raise

        if progress_callback:
            progress_callback(1, 1)

        return 1

    def _encrypt_chunk_mode(self, input_path: Path, output_path: Path, file_size: int,
                            progress_callback: Optional[callable]) -> int:
        """Encrypt using chunked mode (per-chunk nonce and tag)."""
        cipher = ChunkCipher(self._key)
        num_chunks = max(1, (file_size + CHUNK_DATA_SIZE - 1) // CHUNK_DATA_SIZE)

        # Write header first
        header = FileHeader.create(self._salt, ROUNDS, file_size, self._master_nonce, EncMode.CNK)

        is_inplace = (input_path.absolute() == output_path.absolute())
        temp_output = output_path.with_suffix('.ohash.tmp') if is_inplace else output_path

        try:
            with open(input_path, 'rb') as infile, open(temp_output, 'wb') as outfile:
                outfile.write(header)

                for i in range(num_chunks):
                    chunk_data = infile.read(CHUNK_DATA_SIZE)
                    encrypted = cipher.encrypt_chunk(chunk_data, self._master_nonce, i)
                    outfile.write(encrypted)

                    if progress_callback:
                        progress_callback(i + 1, num_chunks)

            if is_inplace:
                temp_output.replace(output_path)
        except Exception:
            if is_inplace and temp_output.exists():
                temp_output.unlink()
            raise

        return num_chunks


class Decrypter:
    """
    Main decryption class that handles file decryption.
    Automatically detects encryption mode from header.
    """

    def __init__(self, passphrase: str):
        self._passphrase = passphrase
        self._key: Optional[bytes] = None
        self._file_size: Optional[int] = None
        self._master_nonce: Optional[bytes] = None
        self._mode: Optional[int] = None

    @property
    def mode(self) -> int:
        return self._mode

    @property
    def file_size(self) -> int:
        return self._file_size

    def read_header(self, input_path: Path) -> None:
        """Read and parse header from encrypted file."""
        with open(input_path, 'rb') as f:
            header_bytes = f.read(FileHeader.SIZE)

        # Verify magic
        if not header_bytes.startswith(b'OHASH'):
            raise InvalidFileError("Not a valid ohash encrypted file")

        salt, rounds, file_size, nonce, mode = FileHeader.parse(header_bytes)

        # Derive key
        self._key = KeyDeriver.derive(self._passphrase, salt, rounds)
        self._file_size = file_size
        self._master_nonce = nonce
        self._mode = mode

    def decrypt_file(self, input_path: Path, output_path: Path,
                     progress_callback: Optional[callable] = None) -> int:
        """
        Decrypt file using mode detected from header.

        Returns:
            Number of chunks processed
        """
        if self._mode == EncMode.BCK:
            return self._decrypt_block_mode(input_path, output_path, progress_callback)
        elif self._mode == EncMode.CNK:
            return self._decrypt_chunk_mode(input_path, output_path, progress_callback)
        else:
            raise InvalidModeError(f"Unknown encryption mode: {self._mode}")

    def _decrypt_block_mode(self, input_path: Path, output_path: Path,
                             progress_callback: Optional[callable]) -> int:
        """Decrypt using block mode."""
        cipher = BlockCipher(self._key)

        # Read ciphertext (skip header)
        with open(input_path, 'rb') as f:
            f.seek(FileHeader.SIZE)
            ciphertext = f.read()

        # Decrypt
        try:
            plaintext = cipher.decrypt(ciphertext, self._master_nonce)
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")

        is_inplace = (input_path.absolute() == output_path.absolute())
        temp_output = output_path.with_suffix('.ohash.tmp') if is_inplace else output_path

        try:
            # Write output
            with open(temp_output, 'wb') as f:
                f.write(plaintext)

            if is_inplace:
                temp_output.replace(output_path)
        except Exception:
            if is_inplace and temp_output.exists():
                temp_output.unlink()
            raise

        if progress_callback:
            progress_callback(1, 1)

        return 1

    def _decrypt_chunk_mode(self, input_path: Path, output_path: Path,
                             progress_callback: Optional[callable]) -> int:
        """Decrypt using chunked mode."""
        cipher = ChunkCipher(self._key)
        num_chunks = max(1, (self._file_size + CHUNK_DATA_SIZE - 1) // CHUNK_DATA_SIZE)

        is_inplace = (input_path.absolute() == output_path.absolute())
        temp_output = output_path.with_suffix('.ohash.tmp') if is_inplace else output_path

        with open(input_path, 'rb') as infile, open(temp_output, 'wb') as outfile:
            # Skip header
            infile.seek(FileHeader.SIZE)

            for i in range(num_chunks):
                # Calculate chunk size
                if i < num_chunks - 1:
                    chunk_size = CHUNK_DATA_SIZE + TAG_SIZE
                else:
                    remaining = self._file_size - (i * CHUNK_DATA_SIZE)
                    chunk_size = remaining + TAG_SIZE

                # Read and decrypt
                ciphertext = infile.read(chunk_size)

                try:
                    plaintext = cipher.decrypt_chunk(ciphertext, self._master_nonce, i)
                except Exception as e:
                    # Clean up temp file on failure
                    if is_inplace and temp_output.exists():
                        temp_output.unlink()
                    raise DecryptionError(f"Decryption failed at chunk {i + 1}: {e}")

                outfile.write(plaintext)

                if progress_callback:
                    progress_callback(i + 1, num_chunks)

        if is_inplace:
            temp_output.replace(output_path)

        return num_chunks
