"""
Configuration constants for ohash encryption tool.
"""

# File identification
MAGIC = b'OHASH'  # 5 bytes - file identification
MAGIC_SIZE = 5

# Cryptography settings
SALT_SIZE = 16   # 16 bytes - random salt for PBKDF2
ROUNDS = 100000  # PBKDF2 iterations (use 100000+ for production)
KEY_SIZE = 32    # 256 bits for AES-256
NONCE_SIZE = 12  # 96 bits for AES-GCM
TAG_SIZE = 16    # 16 bytes - authentication tag per chunk

# Chunk settings
CHUNK_DATA_SIZE = 64 * 1024  # 64KB data per chunk (for chunked mode)
IO_CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file I/O

# Encryption modes
class EncMode:
    """Encryption mode constants."""
    BCK = 0x00  # Block mode - single nonce for entire file
    CNK = 0x01  # Chunked mode - per-chunk nonce and tag

# Header sizes
HEADER_SIZE_V1 = MAGIC_SIZE + SALT_SIZE + 4 + NONCE_SIZE  # Old format (no mode)
HEADER_SIZE_V2 = MAGIC_SIZE + SALT_SIZE + 4 + 8 + NONCE_SIZE  # V2: + file_size
HEADER_SIZE = HEADER_SIZE_V2 + 1  # Current: + mode (1 byte)

# Progress bar
PROGRESS_WIDTH = 40
