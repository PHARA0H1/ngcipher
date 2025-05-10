"""
Authenticated Encryption with Associated Data (AEAD) Package

This package implements AEAD modes that provide both confidentiality and
authenticity, similar to AES-GCM but for our next-generation cipher.
"""

from .gcm_mode import NGCipherGCM, encrypt, decrypt

__all__ = ['NGCipherGCM', 'encrypt', 'decrypt']
