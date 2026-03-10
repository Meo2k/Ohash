import hashlib
from typing import Tuple

from ..config import (
    SALT_SIZE, ROUNDS, KEY_SIZE, NONCE_SIZE
)

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
