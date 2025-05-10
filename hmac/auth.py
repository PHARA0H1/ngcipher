"""
HMAC-based Authentication

This module implements HMAC functions for ensuring data integrity
and authenticity beyond what is provided by the AEAD mode.
"""

import hmac
import hashlib
from typing import Tuple, Optional, Union


def hmac_authenticate(data: bytes, key: bytes, hash_algo: str = 'sha512') -> bytes:
    """
    Generate an HMAC authentication tag for the provided data.
    
    Args:
        data: The data to authenticate
        key: The HMAC key
        hash_algo: Hash algorithm to use ('sha256', 'sha384', or 'sha512')
        
    Returns:
        The HMAC authentication tag
    """
    if hash_algo not in ('sha256', 'sha384', 'sha512'):
        raise ValueError("Hash algorithm must be sha256, sha384, or sha512")
    
    hash_func = getattr(hashlib, hash_algo)
    mac = hmac.new(key, data, hash_func)
    return mac.digest()


def hmac_verify(data: bytes, tag: bytes, key: bytes, hash_algo: str = 'sha512') -> bool:
    """
    Verify the HMAC authentication tag for the provided data.
    
    Args:
        data: The data to verify
        tag: The authentication tag to verify
        key: The HMAC key
        hash_algo: Hash algorithm used ('sha256', 'sha384', or 'sha512')
        
    Returns:
        True if verification succeeds, False otherwise
    """
    if hash_algo not in ('sha256', 'sha384', 'sha512'):
        raise ValueError("Hash algorithm must be sha256, sha384, or sha512")
    
    expected_tag = hmac_authenticate(data, key, hash_algo)
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(tag, expected_tag)


def authenticate_data(data: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Generate an HMAC-SHA-512 tag over (nonce ∥ data).
    
    Args:
        data: The data to authenticate (typically ciphertext)
        nonce: The nonce/IV used
        key: The HMAC key (can be derived from the encryption key)
        
    Returns:
        The authentication tag
    """
    return hmac_authenticate(nonce + data, key)


def verify_data(data: bytes, nonce: bytes, tag: bytes, key: bytes) -> bool:
    """
    Verify an HMAC-SHA-512 tag over (nonce ∥ data).
    
    Args:
        data: The data to verify (typically ciphertext)
        nonce: The nonce/IV used
        tag: The authentication tag to verify
        key: The HMAC key
        
    Returns:
        True if verification succeeds, False otherwise
    """
    return hmac_verify(nonce + data, tag, key)


if __name__ == "__main__":
    # Test HMAC functions
    import os
    
    # Generate a random key and data
    key = os.urandom(32)
    nonce = os.urandom(12)
    data = b"This is some data to authenticate"
    
    # Generate authentication tag
    tag = authenticate_data(data, nonce, key)
    print(f"Original data: {data}")
    print(f"Auth tag: {tag.hex()}")
    
    # Verify tag (should succeed)
    result = verify_data(data, nonce, tag, key)
    print(f"Verification result: {result}")
    assert result == True
    
    # Verify with modified data (should fail)
    modified_data = bytearray(data)
    modified_data[0] ^= 0x01
    result = verify_data(bytes(modified_data), nonce, tag, key)
    print(f"Verification with modified data: {result}")
    assert result == False
    
    # Verify with modified nonce (should fail)
    modified_nonce = bytearray(nonce)
    modified_nonce[0] ^= 0x01
    result = verify_data(data, bytes(modified_nonce), tag, key)
    print(f"Verification with modified nonce: {result}")
    assert result == False
    
    print("HMAC tests completed successfully!")
