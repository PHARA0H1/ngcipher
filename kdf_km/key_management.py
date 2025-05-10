"""
Key Management and Key Derivation Functions

This module implements key management and derivation functions for
securely handling cryptographic keys, including Argon2id for
password-based key derivation.
"""

import os
import json
import base64
import time
import secrets
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union, Any
import argon2
from argon2.low_level import Type
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# Default parameters for Argon2id
KDF_DEFAULT_PARAMS = {
    'time_cost': 4,       # Number of iterations
    'memory_cost': 65536, # 64 MB
    'parallelism': 4,     # Number of threads
    'hash_len': 32,       # Output size in bytes
    'salt_len': 16        # Salt size in bytes
}


def generate_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Args:
        length: Length of the salt in bytes
        
    Returns:
        Random salt as bytes
    """
    return secrets.token_bytes(length)


def derive_key(password: Union[str, bytes], 
               salt: bytes, 
               time_cost: int = KDF_DEFAULT_PARAMS['time_cost'],
               memory_cost: int = KDF_DEFAULT_PARAMS['memory_cost'],
               parallelism: int = KDF_DEFAULT_PARAMS['parallelism'],
               hash_len: int = KDF_DEFAULT_PARAMS['hash_len']) -> bytes:
    """
    Derive a cryptographic key from a password using Argon2id.
    
    Args:
        password: Password to derive the key from
        salt: Salt value
        time_cost: Number of iterations
        memory_cost: Memory usage in KiB
        parallelism: Degree of parallelism
        hash_len: Length of the derived key in bytes
        
    Returns:
        Derived key as bytes
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Use Argon2id with specified parameters
    derived_key = argon2.low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID  # Argon2id variant
    )
    
    return derived_key


@dataclass
class StoredKey:
    """Data class for storing key information."""
    id: str
    version: int
    created_at: int
    algorithm: str
    key_material: bytes
    metadata: Dict[str, Any]


class KeyManager:
    """
    Manages cryptographic keys, including generation, derivation,
    secure storage, and rotation.
    """
    
    def __init__(self, root_key_source: str = 'env', root_key: Optional[bytes] = None):
        """
        Initialize the key manager.
        
        Args:
            root_key_source: Source of the root key ('env' or 'provided')
            root_key: Root key if explicitly provided
        """
        self.keys = {}  # Store active keys in memory
        
        # Get the root key (used to protect other keys)
        if root_key_source == 'env':
            env_key = os.environ.get('NGCIPHER_ROOT_KEY')
            if env_key:
                # Derive a 256-bit key from the environment variable
                salt = b'NGCipher_ROOT_KEY_SALT_v1'
                self.root_key = hashlib.sha256(env_key.encode() + salt).digest()
            else:
                raise ValueError("Root key not found in environment variable NGCIPHER_ROOT_KEY")
        elif root_key_source == 'provided' and root_key is not None:
            if len(root_key) != 32:
                raise ValueError("Root key must be 32 bytes (256 bits)")
            self.root_key = root_key
        else:
            raise ValueError("Invalid root key source or missing provided key")
    
    def _encrypt_key_material(self, key_material: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt key material using AES-GCM with the root key.
        
        Args:
            key_material: Key material to encrypt
            
        Returns:
            Tuple of (ciphertext, tag, nonce)
        """
        nonce = secrets.token_bytes(12)
        cipher = AES.new(self.root_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(key_material)
        return ciphertext, tag, nonce
    
    def _decrypt_key_material(self, ciphertext: bytes, tag: bytes, nonce: bytes) -> bytes:
        """
        Decrypt key material using AES-GCM with the root key.
        
        Args:
            ciphertext: Encrypted key material
            tag: Authentication tag
            nonce: Nonce used for encryption
            
        Returns:
            Decrypted key material
            
        Raises:
            ValueError: If authentication fails
        """
        cipher = AES.new(self.root_key, AES.MODE_GCM, nonce=nonce)
        try:
            key_material = cipher.decrypt_and_verify(ciphertext, tag)
            return key_material
        except (ValueError, KeyError) as e:
            raise ValueError(f"Failed to decrypt key material: {e}")
    
    def generate_key(self, key_id: str, algorithm: str = "ngcipher", metadata: Dict[str, Any] = None) -> bytes:
        """
        Generate a new random key and store it securely.
        
        Args:
            key_id: Identifier for the key
            algorithm: Algorithm this key is for
            metadata: Optional metadata for the key
            
        Returns:
            The generated key
        """
        # Generate a new random key
        key_material = secrets.token_bytes(32)  # 256-bit key
        
        # Store the key
        self.store_key(key_id, key_material, algorithm, metadata)
        
        return key_material
    
    def store_key(self, key_id: str, key_material: bytes, algorithm: str = "ngcipher", 
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Store a key securely.
        
        Args:
            key_id: Identifier for the key
            key_material: The key to store
            algorithm: Algorithm this key is for
            metadata: Optional metadata for the key
        """
        if not metadata:
            metadata = {}
        
        # Encrypt the key material with the root key
        ciphertext, tag, nonce = self._encrypt_key_material(key_material)
        
        # Create key object
        key = StoredKey(
            id=key_id,
            version=1,
            created_at=int(time.time()),
            algorithm=algorithm,
            key_material=key_material,  # Store decrypted in memory
            metadata=metadata
        )
        
        # Store in memory
        self.keys[key_id] = key
        
        # Store encrypted to persistent storage (not implemented here)
        # In a real implementation, you would serialize:
        # {
        #     "id": key_id,
        #     "version": 1,
        #     "created_at": key.created_at,
        #     "algorithm": algorithm,
        #     "key_material_encrypted": base64.b64encode(ciphertext).decode('utf-8'),
        #     "key_material_tag": base64.b64encode(tag).decode('utf-8'),
        #     "key_material_nonce": base64.b64encode(nonce).decode('utf-8'),
        #     "metadata": metadata
        # }
    
    def get_key(self, key_id: str) -> bytes:
        """
        Retrieve a key by its identifier.
        
        Args:
            key_id: Identifier for the key
            
        Returns:
            The key material
            
        Raises:
            KeyError: If the key is not found
        """
        if key_id in self.keys:
            return self.keys[key_id].key_material
        
        # In a real implementation, you would:
        # 1. Load the encrypted key from persistent storage
        # 2. Decrypt it using the root key
        # 3. Store it in the in-memory cache
        # 4. Return the decrypted key material
        
        raise KeyError(f"Key '{key_id}' not found")
    
    def rotate_key(self, key_id: str) -> str:
        """
        Rotate a key by generating a new version and keeping the old one.
        
        Args:
            key_id: Identifier for the key to rotate
            
        Returns:
            The new key ID (typically key_id.v2)
            
        Raises:
            KeyError: If the key is not found
        """
        # Get the current key
        if key_id not in self.keys:
            raise KeyError(f"Key '{key_id}' not found")
        
        current_key = self.keys[key_id]
        
        # Generate a new key ID with version
        new_version = current_key.version + 1
        new_key_id = f"{key_id}.v{new_version}"
        
        # Generate a new key with the same metadata
        new_key_material = secrets.token_bytes(32)
        
        # Add version info to metadata
        metadata = current_key.metadata.copy()
        metadata["previous_version"] = key_id
        metadata["rotated_from"] = key_id
        metadata["rotated_at"] = int(time.time())
        
        # Store the new key
        self.store_key(new_key_id, new_key_material, current_key.algorithm, metadata)
        
        # Update the old key's metadata to link to the new version
        self.keys[key_id].metadata["next_version"] = new_key_id
        self.keys[key_id].metadata["rotated_to"] = new_key_id
        self.keys[key_id].metadata["deprecated"] = True
        
        return new_key_id
    
    def derive_key_from_password(self, 
                                password: str, 
                                key_id: str, 
                                salt: Optional[bytes] = None,
                                params: Optional[Dict[str, int]] = None) -> Tuple[bytes, bytes]:
        """
        Derive a key from a password using Argon2id and store it.
        
        Args:
            password: Password to derive the key from
            key_id: Identifier for the key
            salt: Optional salt (will be generated if not provided)
            params: Optional parameters for Argon2id
            
        Returns:
            Tuple of (derived_key, salt)
        """
        # Generate salt if not provided
        if salt is None:
            salt = generate_salt(KDF_DEFAULT_PARAMS['salt_len'])
        
        # Use default params if not provided
        if params is None:
            params = KDF_DEFAULT_PARAMS
        
        # Derive the key
        derived_key = derive_key(
            password, 
            salt, 
            time_cost=params.get('time_cost', KDF_DEFAULT_PARAMS['time_cost']),
            memory_cost=params.get('memory_cost', KDF_DEFAULT_PARAMS['memory_cost']),
            parallelism=params.get('parallelism', KDF_DEFAULT_PARAMS['parallelism']),
            hash_len=params.get('hash_len', KDF_DEFAULT_PARAMS['hash_len'])
        )
        
        # Store the key with salt in metadata
        metadata = {
            'derived': True,
            'salt': base64.b64encode(salt).decode('utf-8'),
            'kdf': 'argon2id',
            'kdf_params': params
        }
        
        self.store_key(key_id, derived_key, "ngcipher", metadata)
        
        return derived_key, salt


if __name__ == "__main__":
    # Test the key manager
    # Set a test root key in the environment
    os.environ['NGCIPHER_ROOT_KEY'] = 'test_root_key_for_development_only'
    
    # Create a key manager
    km = KeyManager(root_key_source='env')
    
    # Generate a new key
    key = km.generate_key('test_key', metadata={'purpose': 'testing'})
    print(f"Generated key: {key.hex()}")
    
    # Retrieve the key
    retrieved_key = km.get_key('test_key')
    print(f"Retrieved key: {retrieved_key.hex()}")
    assert key == retrieved_key
    
    # Rotate the key
    new_key_id = km.rotate_key('test_key')
    print(f"Rotated key ID: {new_key_id}")
    
    # Get the new key
    new_key = km.get_key(new_key_id)
    print(f"New key: {new_key.hex()}")
    
    # Derive a key from password
    password = "secure_password_example"
    derived_key, salt = km.derive_key_from_password(password, 'password_derived_key')
    print(f"Derived key: {derived_key.hex()}")
    print(f"Salt: {salt.hex()}")
    
    # Verify we can get the same key again with the same salt
    test_key = derive_key(password, salt)
    print(f"Test derived: {test_key.hex()}")
    assert derived_key == test_key
    
    print("Key management tests completed successfully!")
