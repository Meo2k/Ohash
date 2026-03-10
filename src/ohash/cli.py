#!/usr/bin/env python3
"""
Command-line interface for ohash.
"""

import os
import sys
from pathlib import Path

from .config import EncMode, PROGRESS_WIDTH
from .crypto import Encrypter, Decrypter
from .exceptions import OhashError
import argparse


def get_passphrase(prompt: str = None) -> str:
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


def encrypt_file(input_path: str, output_path: str = None, mode: int = EncMode.CNK,
                 passphrase: str = None) -> None:
    """Encrypt a file."""
    input_path = Path(input_path)

    if not input_path.exists():
        print(f"Error: File '{input_path}' not found.")
        sys.exit(1)

    # Get passphrase
    if passphrase is None:
        passphrase = get_passphrase()

    # Determine output path
    if output_path is None:
        output_path = input_path
    output_path = Path(output_path)

    # Create encrypter
    encrypter = Encrypter(passphrase)

    # Mode string
    mode_str = "Block" if mode == EncMode.BCK else "Chunk"
    print(f"Encrypting: {input_path} [{mode_str}ed ({'--bck' if mode == EncMode.BCK else '--cnk'})]")

    # Encrypt
    try:
        num_chunks = encrypter.encrypt_file(
            input_path,
            output_path,
            mode=mode,
            progress_callback=lambda c, t: show_progress(c, t, f"{mode_str} {c}/{t}" if mode == EncMode.CNK else "")
        )
    except OhashError as e:
        print(f"\nError: {e}")
        sys.exit(1)

    # Remove original if different output
    if output_path != input_path:
        input_path.unlink()

    if mode == EncMode.CNK:
        print(f"Encrypted: '{input_path}' -> '{output_path}' ({num_chunks} chunks)")
    else:
        print(f"Encrypted: '{input_path}' -> '{output_path}'")


def decrypt_file(input_path: str, output_path: str = None, passphrase: str = None) -> None:
    """Decrypt a file."""
    input_path = Path(input_path)

    if not input_path.exists():
        print(f"Error: File '{input_path}' not found.")
        sys.exit(1)

    # Get passphrase
    if passphrase is None:
        passphrase = get_passphrase()

    # Determine output path
    if output_path is None:
        output_path = input_path
    output_path = Path(output_path)

    # Create decrypter and read header
    try:
        decrypter = Decrypter(passphrase)
        decrypter.read_header(input_path)
    except OhashError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Mode string
    mode_str = "Block" if decrypter.mode == EncMode.BCK else "Chunk"
    print(f"Decrypting: {input_path} [{mode_str}ed ({'--bck' if decrypter.mode == EncMode.BCK else '--cnk'})]")

    # Decrypt
    try:
        num_chunks = decrypter.decrypt_file(
            input_path,
            output_path,
            progress_callback=lambda c, t: show_progress(c, t, f"{mode_str} {c}/{t}" if decrypter.mode == EncMode.CNK else "")
        )
    except OhashError as e:
        print(f"\nError: {e}")
        sys.exit(1)

    # Remove encrypted file if different output
    if output_path != input_path:
        input_path.unlink()

    if decrypter.mode == EncMode.CNK:
        print(f"Decrypted: '{input_path}' -> '{output_path}' ({num_chunks} chunks)")
    else:
        print(f"Decrypted: '{input_path}' -> '{output_path}'")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='ohash',
        description='ohash - File encryption/decryption tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  ohash e test.txt              Encrypt with block mode (default)
  ohash e test.txt --cnk        Encrypt with chunked mode
  ohash e test.txt --bck        Encrypt with block mode
  ohash d test.txt.enc          Decrypt file
  ohash d test.txt.enc out.txt  Decrypt to specific output
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Encrypt command
    encrypt_parser = subparsers.add_parser('e', help='Encrypt file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    encrypt_parser.add_argument('output', nargs='?', help='Output file (optional)')
    encrypt_parser.add_argument('--bck', action='store_true', help='Block mode (single nonce)')
    encrypt_parser.add_argument('--cnk', action='store_true', help='Chunked mode (per-chunk nonce)')

    # Decrypt command
    decrypt_parser = subparsers.add_parser('d', help='Decrypt file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('output', nargs='?', help='Output file (optional)')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    passphrase = os.environ.get('OHASH_PASS')

    if args.command == 'e':
        # Determine encryption mode
        mode = EncMode.BCK  # Default
        if args.cnk:
            mode = EncMode.CNK
        elif args.bck:
            mode = EncMode.BCK

        encrypt_file(args.file, args.output, mode=mode, passphrase=passphrase)

    elif args.command == 'd':
        decrypt_file(args.file, args.output, passphrase=passphrase)


if __name__ == '__main__':
    main()
