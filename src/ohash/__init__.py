"""
ohash - File encryption/decryption tool

A secure file encryption tool using AES-256-GCM with PBKDF2 key derivation.
Supports both block mode (--bck) and chunked mode (--cnk) encryption.
"""

from .config import EncMode
from .crypto import Encrypter, Decrypter
from .exceptions import (
    OhashError,
    InvalidFileError,
    DecryptionError,
    EncryptionError,
    InvalidModeError
)

__version__ = '2.0.0'

__all__ = [
    '__version__',
    'EncMode',
    'Encrypter',
    'Decrypter',
    'OhashError',
    'InvalidFileError',
    'DecryptionError',
    'EncryptionError',
    'InvalidModeError',
]
