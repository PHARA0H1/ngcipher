"""
NGCipher - Next Generation Symmetric Block Cipher Library

This library implements a next-generation symmetric block cipher
that exceeds the security of AES-256, with a 256-bit block size,
SPN structure, and robust authenticated encryption.

Key Features:
- 256-bit block size (configurable)
- SPN structure with 16 rounds (configurable)
- Optimized S-boxes generated via genetic algorithms
- ARX-based key schedule
- Authenticated encryption with integrity verification
- Side-channel resistant implementations
- Key management with secure derivation and storage

"""

__version__ = '0.1.0'
__author__ = 'NGCipher Team'
