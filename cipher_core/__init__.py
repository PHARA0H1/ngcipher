"""
Cipher Core Package

This package implements the core components of the symmetric block cipher,
including the SPN structure, permutation layers, and encryption/decryption
operations.
"""

from .block_cipher import NGBlockCipher, encrypt_block, decrypt_block

__all__ = ['NGBlockCipher', 'encrypt_block', 'decrypt_block']
