"""
GCM-Style Authenticated Encryption Mode

This module implements a GCM-style authenticated encryption mode for 
the next-generation block cipher. It provides both confidentiality 
and authenticity.
"""

import os
import struct
import hmac
import hashlib
from typing import Tuple, Optional, Union, List, Dict

from ..cipher_core.block_cipher import NGBlockCipher
from ..key_schedule.arx_key_schedule import generate_key

# Field polynomial for GF(2^128)
POLYNOMIAL = 0xE1000000000000000000000000000000


def _bytes_to_int(data: bytes) -> int:
    """Convert bytes to an integer (big-endian)"""
    return int.from_bytes(data, byteorder='big')


def _int_to_bytes(value: int, length: int) -> bytes:
    """Convert an integer to bytes (big-endian)"""
    return value.to_bytes(length, byteorder='big')


def _multiply_in_gf2n(x: int, y: int) -> int:
    """
    Multiply two elements in GF(2^128) using the specified irreducible polynomial.
    
    Args:
        x: First operand
        y: Second operand
        
    Returns:
        Result of multiplication in the finite field
    """
    z = 0
    for i in range(128):
        if (y >> i) & 1:
            z ^= x
        # Check if we need to reduce
        if (x >> 127) & 1:
            x = (x << 1) ^ POLYNOMIAL
        else:
            x <<= 1
        # Ensure we stay within 128 bits
        x &= (1 << 128) - 1
        
    return z


class NGCipherGCM:
    """
    Galois/Counter Mode (GCM) for authenticated encryption using our
    next-generation block cipher.
    """
    
    def __init__(self, key: bytes, block_cipher: Optional[NGBlockCipher] = None):
        """
        Initialize the GCM mode with a key.
        
        Args:
            key: The secret key (32 bytes)
            block_cipher: Optional pre-initialized block cipher
        """
        if block_cipher is None:
            self.cipher = NGBlockCipher()
        else:
            self.cipher = block_cipher
            
        self.key = key
        
        # Pre-compute the hash subkey H (encrypt block of zeros)
        self.H = _bytes_to_int(self.cipher.encrypt_block(bytes(32), key))
    
    def _increment_counter(self, counter: bytes) -> bytes:
        """
        Increment the counter value (treating the rightmost 4 bytes as counter).
        
        Args:
            counter: The current counter value
            
        Returns:
            The incremented counter
        """
        # Convert counter to integer
        counter_int = _bytes_to_int(counter)
        
        # Increment the least significant 32 bits
        counter_int = (counter_int & ~0xFFFFFFFF) | ((counter_int + 1) & 0xFFFFFFFF)
        
        # Convert back to bytes
        return _int_to_bytes(counter_int, len(counter))
    
    def _ghash(self, aad: bytes, ciphertext: bytes) -> bytes:
        """
        Calculate the GHASH authentication tag.
        
        Args:
            aad: Additional authenticated data
            ciphertext: The encrypted message
            
        Returns:
            The GHASH tag
        """
        # Pad AAD and ciphertext to 16-byte blocks
        def pad16(data: bytes) -> bytes:
            if len(data) % 16 == 0:
                return data
            return data + bytes(16 - len(data) % 16)
        
        padded_aad = pad16(aad)
        padded_ciphertext = pad16(ciphertext)
        
        # Calculate lengths for final block
        aad_bit_len = len(aad) * 8
        ciphertext_bit_len = len(ciphertext) * 8
        
        # Create length block
        len_block = _int_to_bytes(aad_bit_len, 8) + _int_to_bytes(ciphertext_bit_len, 8)
        
        # Process all blocks
        X = 0
        
        # Process AAD blocks
        for i in range(0, len(padded_aad), 16):
            block = padded_aad[i:i+16]
            X ^= _bytes_to_int(block)
            X = _multiply_in_gf2n(X, self.H)
        
        # Process ciphertext blocks
        for i in range(0, len(padded_ciphertext), 16):
            block = padded_ciphertext[i:i+16]
            X ^= _bytes_to_int(block)
            X = _multiply_in_gf2n(X, self.H)
        
        # Process length block
        X ^= _bytes_to_int(len_block)
        X = _multiply_in_gf2n(X, self.H)
        
        # Convert back to bytes
        return _int_to_bytes(X, 16)
    
    def _gctr(self, counter: bytes, data: bytes) -> bytes:
        """
        Apply the GCTR mode encryption/decryption.
        
        Args:
            counter: Initial counter value
            data: Data to encrypt/decrypt
            
        Returns:
            The encrypted/decrypted data
        """
        if not data:
            return b''
        
        # Initialize result
        result = bytearray()
        
        # Process data in blocks - ensure we handle blocks of the right size (32 bytes)
        ctr = counter
        block_size = 32  # 256 bits = 32 bytes
        
        for i in range(0, len(data), block_size):
            # Get current data block
            block = data[i:i+block_size]
            
            # If block isn't full, pad it for processing (this is just for the encryption operation)
            processing_block = block
            if len(block) < block_size:
                processing_block = block + b'\x00' * (block_size - len(block))
            
            # Encrypt counter
            keystream = self.cipher.encrypt_block(ctr, self.key)
            
            # XOR with data (only use the actual data length)
            processed_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            
            # Append to result
            result.extend(processed_block)
            
            # Increment counter for next block
            ctr = self._increment_counter(ctr)
        
        return bytes(result)
    
    def encrypt(self, 
                plaintext: bytes, 
                nonce: Optional[bytes] = None, 
                aad: bytes = b'') -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt a message using GCM mode.
        
        Args:
            plaintext: The plaintext to encrypt
            nonce: Initialization vector (12 bytes recommended). If None, generates random.
            aad: Additional authenticated data
            
        Returns:
            A tuple of (ciphertext, tag, nonce)
        """
        # Generate random nonce if not provided
        if nonce is None:
            nonce = os.urandom(12)
        
        # Ensure nonce is 12 bytes
        if len(nonce) != 12:
            raise ValueError("Nonce should be 12 bytes")
        
        # Create initial counter (nonce || 0x00000001) padded to 32 bytes
        counter = (nonce + b'\x00\x00\x00\x01').ljust(32, b'\x00')
        
        # Encrypt plaintext using GCTR mode
        ciphertext = self._gctr(counter, plaintext)
        
        # Create J0 counter for tag, padded to 32 bytes
        j0 = (nonce + b'\x00\x00\x00\x01').ljust(32, b'\x00')
        
        # Calculate authentication tag
        ghash_tag = self._ghash(aad, ciphertext)
        
        # Encrypt the GHASH tag
        encrypted_tag = bytes(a ^ b for a, b in zip(
            ghash_tag, 
            self.cipher.encrypt_block(j0, self.key)[:16]
        ))
        
        # Create HMAC for additional integrity verification
        hmac_tag = hmac.new(
            self.key,
            nonce + ciphertext,
            hashlib.sha512
        ).digest()[:16]
        
        # Combine tags (16 bytes GHASH + 16 bytes HMAC = 32 bytes)
        tag = encrypted_tag + hmac_tag
        
        return ciphertext, tag, nonce
    
    def decrypt(self, 
                ciphertext: bytes, 
                tag: bytes, 
                nonce: bytes, 
                aad: bytes = b'') -> bytes:
        """
        Decrypt a message using GCM mode and verify its integrity.
        
        Args:
            ciphertext: The ciphertext to decrypt
            tag: The authentication tag
            nonce: The nonce used for encryption
            aad: Additional authenticated data
            
        Returns:
            The decrypted plaintext if verification succeeds
            
        Raises:
            ValueError: If authentication fails
        """
        # Verify HMAC tag first (timing-attack resistant comparison)
        expected_hmac = hmac.new(
            self.key,
            nonce + ciphertext,
            hashlib.sha512
        ).digest()[:16]
        
        # Split the tag into GHASH part and HMAC part
        ghash_part = tag[:16]
        hmac_part = tag[16:32]
        
        # Use constant-time comparison for HMAC
        if not hmac.compare_digest(hmac_part, expected_hmac):
            raise ValueError("Authentication failed: HMAC tag mismatch")
        
        # Create initial counter (nonce || 0x00000001) padded to 32 bytes
        counter = (nonce + b'\x00\x00\x00\x01').ljust(32, b'\x00')
        
        # Create J0 counter for tag, padded to 32 bytes
        j0 = (nonce + b'\x00\x00\x00\x01').ljust(32, b'\x00')
        
        # Calculate expected authentication tag
        expected_ghash = self._ghash(aad, ciphertext)
        
        # Encrypt the expected GHASH
        expected_encrypted_tag = bytes(a ^ b for a, b in zip(
            expected_ghash, 
            self.cipher.encrypt_block(j0, self.key)[:16]
        ))
        
        # Verify GHASH part (also constant-time)
        if not hmac.compare_digest(ghash_part, expected_encrypted_tag):
            raise ValueError("Authentication failed: GHASH tag mismatch")
        
        # Decrypt ciphertext using GCTR mode
        plaintext = self._gctr(counter, ciphertext)
        
        return plaintext


def encrypt(plaintext: bytes, 
           key: bytes, 
           nonce: Optional[bytes] = None, 
           aad: bytes = b'') -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data using NGCipherGCM mode.
    
    Args:
        plaintext: The plaintext to encrypt
        key: The encryption key
        nonce: Optional nonce/IV (will be generated if None)
        aad: Additional authenticated data
        
    Returns:
        A tuple of (ciphertext, tag, nonce)
    """
    gcm = NGCipherGCM(key)
    return gcm.encrypt(plaintext, nonce, aad)


def decrypt(ciphertext: bytes, 
           tag: bytes, 
           key: bytes, 
           nonce: bytes, 
           aad: bytes = b'') -> bytes:
    """
    Decrypt data using NGCipherGCM mode.
    
    Args:
        ciphertext: The ciphertext to decrypt
        tag: The authentication tag
        key: The encryption key
        nonce: The nonce/IV used during encryption
        aad: Additional authenticated data
        
    Returns:
        The decrypted plaintext
        
    Raises:
        ValueError: If authentication fails
    """
    gcm = NGCipherGCM(key)
    return gcm.decrypt(ciphertext, tag, nonce, aad)


if __name__ == "__main__":
    # Test the GCM mode
    key = generate_key(32)
    plaintext = b"This is a test message for authenticated encryption."
    aad = b"Additional data to authenticate"
    
    # Encrypt
    ciphertext, tag, nonce = encrypt(plaintext, key, aad=aad)
    
    print(f"Key: {key.hex()}")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag: {tag.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"AAD: {aad}")
    
    # Decrypt
    decrypted = decrypt(ciphertext, tag, key, nonce, aad)
    
    print(f"Decrypted: {decrypted}")
    assert decrypted == plaintext
    
    # Test with tampered ciphertext
    try:
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01
        decrypt(bytes(tampered), tag, key, nonce, aad)
        print("ERROR: Tampered ciphertext not detected!")
    except ValueError as e:
        print(f"Correctly detected tampered ciphertext: {e}")
    
    # Test with tampered tag
    try:
        tampered = bytearray(tag)
        tampered[0] ^= 0x01
        decrypt(ciphertext, bytes(tampered), key, nonce, aad)
        print("ERROR: Tampered tag not detected!")
    except ValueError as e:
        print(f"Correctly detected tampered tag: {e}")
    
    # Test with tampered AAD
    try:
        decrypt(ciphertext, tag, key, nonce, aad + b"tampered")
        print("ERROR: Tampered AAD not detected!")
    except ValueError as e:
        print(f"Correctly detected tampered AAD: {e}")
    
    print("GCM mode tests completed successfully!")
