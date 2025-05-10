"""
Key Derivation Function and Key Management Package

This package implements key derivation functions and key management
tools for the next-generation cipher, including Argon2id for
password-based key derivation.
"""

from .key_management import KeyManager, derive_key, generate_salt, KDF_DEFAULT_PARAMS

__all__ = ['KeyManager', 'derive_key', 'generate_salt', 'KDF_DEFAULT_PARAMS']
