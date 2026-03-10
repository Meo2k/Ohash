"""Custom exceptions for ohash."""


class OhashError(Exception):
    """Base exception for ohash errors."""
    pass


class InvalidFileError(OhashError):
    """Raised when file is not a valid ohash encrypted file."""
    pass


class DecryptionError(OhashError):
    """Raised when decryption fails (wrong passphrase, corrupted data)."""
    pass


class EncryptionError(OhashError):
    """Raised when encryption fails."""
    pass


class InvalidModeError(OhashError):
    """Raised when encryption mode is invalid."""
    pass
