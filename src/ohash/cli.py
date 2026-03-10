#!/usr/bin/env python3
"""
Command-line interface for ohash.
"""

import os
import sys

from .config import EncMode
from .helpers import encrypt_file, decrypt_file
import argparse




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
