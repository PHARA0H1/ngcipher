"""
Key Schedule Package

This package implements the key expansion algorithm that transforms
a master key into multiple round keys for use in the block cipher.
"""

from .arx_key_schedule import expand_key, generate_key, derive_key_from_password

__all__ = ['expand_key', 'generate_key', 'derive_key_from_password']
