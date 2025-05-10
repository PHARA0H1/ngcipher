"""
ARX-based Key Schedule Implementation

This module implements the key schedule based on ARX (Addition, Rotation, XOR)
operations to expand a master key into round keys.
"""

import os
import hashlib
import secrets
import struct
from typing import List, Tuple, Optional
import argon2

def rotate_left(value: int, shift: int, size: int = 32) -> int:
    """
    Rotate a value left by the specified number of bits.
    
    Args:
        value: The value to rotate
        shift: The number of bits to rotate by
        size: The bit size of the value
        
    Returns:
        The rotated value
    """
    return ((value << shift) | (value >> (size - shift))) & ((1 << size) - 1)


def rotate_right(value: int, shift: int, size: int = 32) -> int:
    """
    Rotate a value right by the specified number of bits.
    
    Args:
        value: The value to rotate
        shift: The number of bits to rotate by
        size: The bit size of the value
        
    Returns:
        The rotated value
    """
    return ((value >> shift) | (value << (size - shift))) & ((1 << size) - 1)


def generate_key(key_size: int = 32) -> bytes:
    """
    Generate a cryptographically secure random key.
    
    Args:
        key_size: Size of the key in bytes (default: 32)
        
    Returns:
        A random key as bytes
    """
    return secrets.token_bytes(key_size)


def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive a cryptographic key from a password using Argon2id.
    
    Args:
        password: The password to derive the key from
        salt: Optional salt (will be generated if not provided)
        
    Returns:
        A tuple of (key, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    
    # Use Argon2id with high memory and time cost for password-based KDF
    key = argon2.low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=4,  # Number of iterations
        memory_cost=65536,  # 64 MB
        parallelism=4,  # Number of parallel threads
        hash_len=32,  # 256-bit key
        type=argon2.low_level.Type.ID  # Argon2id variant
    )
    
    return key, salt


def expand_key(master_key: bytes, num_rounds: int, round_key_size: int) -> List[bytes]:
    """
    Expand a master key into round keys using ARX-based operations.
    
    Args:
        master_key: The master key (32 bytes)
        num_rounds: Number of rounds
        round_key_size: Size of each round key in bytes
        
    Returns:
        A list of round keys
    """
    if len(master_key) != 32:
        raise ValueError("Master key must be 32 bytes (256 bits)")
    
    # Constants for ARX operations
    # These are derived from fractional parts of square roots of primes
    # Similar to the approach in SHA-2
    constants = [
        0x9e3779b9, 0x243f6a88, 0xb7e15162, 0x3707344a, 
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
    ]
    
    # Break master key into 8 32-bit words
    key_words = [int.from_bytes(master_key[i:i+4], byteorder='big') 
                for i in range(0, len(master_key), 4)]
    
    # Number of 32-bit words in each round key
    words_per_round_key = round_key_size // 4
    
    # Initialize round keys array
    round_keys = []
    
    # Initial key state
    state = key_words.copy()
    
    # Generate round keys
    for r in range(num_rounds + 1):  # +1 for whitening key
        # Perform ARX operations to update state
        for i in range(8):
            # Addition
            state[i] = (state[i] + constants[(r + i) % 16]) & 0xFFFFFFFF
            
            # Rotation
            state[i] = rotate_left(state[i], (i + r) % 31 + 1)
            
            # XOR with another word
            state[i] ^= state[(i + 4) % 8]
            
            # Rotation again
            state[i] = rotate_right(state[i], (i + r + 2) % 29 + 1)
        
        # Create round key from current state
        round_key = bytearray()
        for i in range(words_per_round_key):
            word = state[i % 8]
            round_key.extend(word.to_bytes(4, byteorder='big'))
        
        round_keys.append(bytes(round_key[:round_key_size]))
    
    return round_keys


def test_key_schedule():
    """
    Test the key schedule implementation.
    """
    # Generate a random master key
    master_key = generate_key(32)
    
    # Expand it into round keys
    round_keys = expand_key(master_key, 16, 32)
    
    # Check if we have the correct number of round keys
    assert len(round_keys) == 17, f"Expected 17 round keys, got {len(round_keys)}"
    
    # Check if round keys have the correct size
    for i, rk in enumerate(round_keys):
        assert len(rk) == 32, f"Round key {i} has incorrect length: {len(rk)}"
    
    # Check for avalanche effect
    # Modify one bit of the master key
    modified_key = bytearray(master_key)
    modified_key[0] ^= 0x01
    modified_key = bytes(modified_key)
    
    # Expand the modified key
    modified_round_keys = expand_key(modified_key, 16, 32)
    
    # Count bit differences
    different_bits = 0
    total_bits = 0
    
    for rk1, rk2 in zip(round_keys, modified_round_keys):
        for b1, b2 in zip(rk1, rk2):
            xor = b1 ^ b2
            for i in range(8):
                if (xor >> i) & 1:
                    different_bits += 1
                total_bits += 1
    
    avalanche_percentage = (different_bits / total_bits) * 100
    print(f"Avalanche effect: {avalanche_percentage:.2f}% of bits changed")
    
    # Should be close to 50% for good avalanche
    assert avalanche_percentage > 45, f"Poor avalanche effect: {avalanche_percentage:.2f}%"
    
    print("Key schedule test passed!")


if __name__ == "__main__":
    test_key_schedule()
