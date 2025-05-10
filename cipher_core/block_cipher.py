"""
Block Cipher Implementation

This module provides the core implementation of the NGBlockCipher, 
a Substitution-Permutation Network (SPN) based symmetric block cipher
with a 256-bit block size.
"""

import os
import numpy as np
from typing import List, Tuple, Optional, Union

from ..sbox_gen.genetic_algorithm import generate_optimized_sbox
from ..key_schedule.arx_key_schedule import expand_key


class NGBlockCipher:
    """
    Next Generation Block Cipher implementation using SPN (Substitution-Permutation Network)
    with a 256-bit block size and configurable number of rounds.
    """
    
    def __init__(self, 
                 block_size: int = 256, 
                 num_rounds: int = 16,
                 sbox_size: int = 8,
                 key_size: int = 32):
        """
        Initialize the block cipher with specified parameters.
        
        Args:
            block_size: Block size in bits (default: 256)
            num_rounds: Number of SPN rounds (default: 16)
            sbox_size: Size of S-box input/output in bits (default: 8)
            key_size: Size of master key in bytes (default: 32)
        """
        self.block_size = block_size
        self.num_rounds = num_rounds
        self.sbox_size = sbox_size
        self.key_size = key_size
        
        # Calculate the number of S-boxes needed based on block size
        self.num_sboxes = block_size // sbox_size
        
        # Generate or load optimized S-box
        self.sbox = generate_optimized_sbox()
        
        # Create inverse S-box for decryption
        self.inv_sbox = self._create_inverse_sbox(self.sbox)
        
        # Initialize bit permutation table (will be optimized later using RL)
        self.perm_table = self._initialize_permutation_table()
        
        # Initialize inverse permutation table for decryption
        self.inv_perm_table = self._create_inverse_permutation(self.perm_table)
    
    def _create_inverse_sbox(self, sbox: List[int]) -> List[int]:
        """
        Create the inverse S-box for decryption.
        
        Args:
            sbox: The forward S-box
            
        Returns:
            List containing the inverse S-box
        """
        inv_sbox = [0] * 256
        for i, val in enumerate(sbox):
            inv_sbox[val] = i
        return inv_sbox
    
    def _initialize_permutation_table(self) -> List[int]:
        """
        Initialize the permutation table for bit diffusion.
        
        In a production implementation, this would be optimized for
        maximum bit diffusion using reinforcement learning.
        
        Returns:
            List containing the permutation table
        """
        # Simple bit permutation for now (will be replaced with RL-optimized version)
        perm = list(range(self.block_size))
        
        # Create a permutation that spreads bits for good diffusion
        # This is a simple model that can be replaced with a learned permutation
        half_size = self.block_size // 2
        result = []
        
        for i in range(half_size):
            result.append(i)
            result.append(i + half_size)
            
        return result
    
    def _create_inverse_permutation(self, perm_table: List[int]) -> List[int]:
        """
        Create the inverse permutation table for decryption.
        
        Args:
            perm_table: The forward permutation table
            
        Returns:
            List containing the inverse permutation
        """
        inv_perm = [0] * len(perm_table)
        for i, val in enumerate(perm_table):
            inv_perm[val] = i
        return inv_perm
    
    def _substitute_bytes(self, state: bytes, inverse: bool = False) -> bytes:
        """
        Apply the S-box substitution to each byte of the state.
        
        Args:
            state: The current state as bytes
            inverse: Whether to use the inverse S-box (for decryption)
            
        Returns:
            The state after substitution
        """
        sbox_table = self.inv_sbox if inverse else self.sbox
        return bytes(sbox_table[b] for b in state)
    
    def _permute_bits(self, state: bytes, inverse: bool = False) -> bytes:
        """
        Apply bit permutation to the state.
        
        Args:
            state: The current state as bytes
            inverse: Whether to use the inverse permutation (for decryption)
            
        Returns:
            The state after permutation
        """
        # Convert bytes to bits
        bits = []
        for byte in state:
            for i in range(8):
                bits.append((byte >> i) & 1)
        
        # Apply permutation
        perm_table = self.inv_perm_table if inverse else self.perm_table
        permuted_bits = [0] * len(bits)
        
        for i, bit_pos in enumerate(perm_table):
            if bit_pos < len(bits):  # Safety check
                permuted_bits[i] = bits[bit_pos]
        
        # Convert bits back to bytes
        result = bytearray(len(state))
        for i in range(len(permuted_bits)):
            byte_index = i // 8
            bit_index = i % 8
            result[byte_index] |= (permuted_bits[i] << bit_index)
        
        return bytes(result)
    
    def _add_round_key(self, state: bytes, round_key: bytes) -> bytes:
        """
        XOR the state with the round key.
        
        Args:
            state: The current state as bytes
            round_key: The round key to add
            
        Returns:
            The state after adding the round key
        """
        return bytes(a ^ b for a, b in zip(state, round_key))
    
    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        """
        Encrypt a single block of plaintext using the block cipher.
        
        Args:
            plaintext: The plaintext block to encrypt (must be block_size bits)
            key: The master key
            
        Returns:
            The encrypted ciphertext block
        """
        if len(plaintext) * 8 != self.block_size:
            raise ValueError(f"Plaintext must be exactly {self.block_size // 8} bytes")
        
        if len(key) != self.key_size:
            raise ValueError(f"Key must be exactly {self.key_size} bytes")
        
        # Generate round keys
        round_keys = expand_key(key, self.num_rounds, self.block_size // 8)
        
        # Initial round key addition
        state = self._add_round_key(plaintext, round_keys[0])
        
        # Main rounds
        for r in range(1, self.num_rounds):
            state = self._substitute_bytes(state)
            state = self._permute_bits(state)
            state = self._add_round_key(state, round_keys[r])
        
        # Final round (no permutation)
        state = self._substitute_bytes(state)
        state = self._add_round_key(state, round_keys[self.num_rounds])
        
        return state
    
    def decrypt_block(self, ciphertext: bytes, key: bytes) -> bytes:
        """
        Decrypt a single block of ciphertext using the block cipher.
        
        Args:
            ciphertext: The ciphertext block to decrypt (must be block_size bits)
            key: The master key
            
        Returns:
            The decrypted plaintext block
        """
        if len(ciphertext) * 8 != self.block_size:
            raise ValueError(f"Ciphertext must be exactly {self.block_size // 8} bytes")
        
        if len(key) != self.key_size:
            raise ValueError(f"Key must be exactly {self.key_size} bytes")
        
        # Generate round keys
        round_keys = expand_key(key, self.num_rounds, self.block_size // 8)
        
        # Initial round key addition
        state = self._add_round_key(ciphertext, round_keys[self.num_rounds])
        
        # Main rounds (in reverse)
        for r in range(self.num_rounds - 1, 0, -1):
            state = self._substitute_bytes(state, inverse=True)
            state = self._add_round_key(state, round_keys[r])
            state = self._permute_bits(state, inverse=True)
        
        # Final round (no permutation)
        state = self._substitute_bytes(state, inverse=True)
        state = self._add_round_key(state, round_keys[0])
        
        return state


def encrypt_block(plaintext: bytes, key: bytes, 
                 block_size: int = 256, 
                 num_rounds: int = 16) -> bytes:
    """
    Convenience function to encrypt a single block.
    
    Args:
        plaintext: The plaintext block to encrypt
        key: The master key
        block_size: Block size in bits (default: 256)
        num_rounds: Number of rounds (default: 16)
        
    Returns:
        The encrypted ciphertext block
    """
    cipher = NGBlockCipher(block_size=block_size, num_rounds=num_rounds)
    return cipher.encrypt_block(plaintext, key)


def decrypt_block(ciphertext: bytes, key: bytes,
                 block_size: int = 256,
                 num_rounds: int = 16) -> bytes:
    """
    Convenience function to decrypt a single block.
    
    Args:
        ciphertext: The ciphertext block to decrypt
        key: The master key
        block_size: Block size in bits (default: 256)
        num_rounds: Number of rounds (default: 16)
        
    Returns:
        The decrypted plaintext block
    """
    cipher = NGBlockCipher(block_size=block_size, num_rounds=num_rounds)
    return cipher.decrypt_block(ciphertext, key)
