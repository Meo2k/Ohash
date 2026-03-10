#!/usr/bin/env python3
"""
ohash - File encryption/decryption tool

Main entry point. Use as:
  python ohash.py e <file> [--bck|--cnk] [output]
  python ohash.py d <file> [output]

Or as module:
  python src/cli.py e <file> [--bck|--cnk] [output]
  python src/cli.py d <file> [output]
"""

import sys
import os

# Add src to path for direct execution
import pathlib
script_dir = pathlib.Path(__file__).parent.resolve()
sys.path.insert(0, str(script_dir / 'src'))

from cli import main

if __name__ == '__main__':
    main()
