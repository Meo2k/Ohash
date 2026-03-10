import hashlib
import os
import sys
from pathlib import Path
from typing import Tuple, Optional

from .config import (
    SALT_SIZE, ROUNDS, KEY_SIZE, NONCE_SIZE, EncMode, PROGRESS_WIDTH
)
from .crypto import Encrypter, Decrypter
from .exceptions import OhashError

def derive_key(passphrase: str, salt: bytes, rounds: int = ROUNDS) -> bytes:
    """Derive encryption key from passphrase and salt."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        salt,
        rounds,
        dklen=KEY_SIZE
    )


# Header structure: Magic(5) + Salt(16) + Rounds(4) + FileSize(8) + Nonce(12) + Mode(1)
HEADER_SIZE = 5 + 16 + 4 + 8 + 12 + 1  # 46 bytes


def create_header(salt: bytes, rounds: int, file_size: int, nonce: bytes, mode: int) -> bytes:
    """Create header bytes."""
    return (
        b'OHASH' +
        salt +
        rounds.to_bytes(4, 'big') +
        file_size.to_bytes(8, 'big') +
        nonce +
        bytes([mode])
    )


def parse_header(header_bytes: bytes) -> Tuple[bytes, int, int, bytes, int]:
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


def get_passphrase(prompt: Optional[str] = None) -> str:
    """Get passphrase from env var or interactive input."""
    passphrase = os.environ.get('OHASH_PASS')
    if passphrase:
        return passphrase

    if prompt is None:
        prompt = "Enter passphrase (or set OHASH_PASS env var):"

    print(prompt)
    passphrase = input()

    if not passphrase:
        print("Error: Passphrase cannot be empty.")
        sys.exit(1)

    return passphrase


def show_progress(current: int, total: int, label: str = "") -> None:
    """Show progress bar."""
    if total == 0:
        percent = 100
    else:
        percent = int((current / total) * 100)

    filled = int((current / total) * PROGRESS_WIDTH) if total > 0 else PROGRESS_WIDTH
    bar = '#' * filled + ' ' * (PROGRESS_WIDTH - filled)

    sys.stdout.write(f"\r[{bar}] {percent}% {label}")
    sys.stdout.flush()

    if current >= total:
        print()


def encrypt_file(input_path: str | Path, output_path: Optional[str | Path] = None, mode: int = EncMode.CNK,
                 passphrase: Optional[str] = None) -> None:
    """Encrypt a file."""
    input_path_obj = Path(input_path)

    if not input_path_obj.exists():
        print(f"Error: File '{input_path_obj}' not found.")
        sys.exit(1)

    # Get passphrase
    if passphrase is None:
        passphrase = get_passphrase()

    # Determine output path
    if output_path is None:
        output_path_obj = input_path_obj
    else:
        output_path_obj = Path(output_path)

    # Create encrypter
    encrypter = Encrypter(passphrase)

    # Mode string
    mode_str = "Block" if mode == EncMode.BCK else "Chunk"
    print(f"Encrypting: {input_path} [{mode_str}ed ({'--bck' if mode == EncMode.BCK else '--cnk'})]")

    # Encrypt
    try:
        num_chunks = encrypter.encrypt_file(
            input_path_obj,
            output_path_obj,
            mode=mode,
            progress_callback=lambda c, t: show_progress(c, t, f"{mode_str} {c}/{t}" if mode == EncMode.CNK else "")
        )
    except OhashError as e:
        print(f"\nError: {e}")
        sys.exit(1)

    # Remove original if different output
    if output_path_obj != input_path_obj:
        input_path_obj.unlink()

    if mode == EncMode.CNK:
        print(f"Encrypted: '{input_path_obj}' -> '{output_path_obj}' ({num_chunks} chunks)")
    else:
        print(f"Encrypted: '{input_path_obj}' -> '{output_path_obj}'")


def decrypt_file(input_path: str | Path, output_path: Optional[str | Path] = None, passphrase: Optional[str] = None) -> None:
    """Decrypt a file."""
    input_path_obj = Path(input_path)

    if not input_path_obj.exists():
        print(f"Error: File '{input_path_obj}' not found.")
        sys.exit(1)

    # Get passphrase
    if passphrase is None:
        passphrase = get_passphrase()

    # Determine output path
    if output_path is None:
        output_path_obj = input_path_obj
    else:
        output_path_obj = Path(output_path)

    # Create decrypter and read header
    try:
        decrypter = Decrypter(passphrase)
        decrypter.read_header(input_path_obj)
    except OhashError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Mode string
    mode_str = "Block" if decrypter.mode == EncMode.BCK else "Chunk"
    print(f"Decrypting: {input_path_obj} [{mode_str}ed ({'--bck' if decrypter.mode == EncMode.BCK else '--cnk'})]")

    # Decrypt
    try:
        num_chunks = decrypter.decrypt_file(
            input_path_obj,
            output_path_obj,
            progress_callback=lambda c, t: show_progress(c, t, f"{mode_str} {c}/{t}" if decrypter.mode == EncMode.CNK else "")
        )
    except OhashError as e:
        print(f"\nError: {e}")
        sys.exit(1)

    # Remove encrypted file if different output
    if output_path_obj != input_path_obj:
        input_path_obj.unlink()

    if decrypter.mode == EncMode.CNK:
        print(f"Decrypted: '{input_path_obj}' -> '{output_path_obj}' ({num_chunks} chunks)")
    else:
        print(f"Decrypted: '{input_path_obj}' -> '{output_path_obj}'")
