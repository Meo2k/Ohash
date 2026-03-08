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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cli import main

if __name__ == '__main__':
    main()
