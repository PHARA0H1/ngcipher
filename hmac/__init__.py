"""
HMAC Authentication Package

This package implements HMAC-based authentication functions for
ensuring data integrity and authenticity.
"""

from .auth import hmac_authenticate, hmac_verify

__all__ = ['hmac_authenticate', 'hmac_verify']
