# NGCipher

Next-Generation Symmetric Block Cipher Library exceeding AES-256 security with research prototypes, key management, and authenticated encryption.

## Features

- 256-bit block size (configurable)
- SPN structure with 16 rounds (configurable)
- Optimized S-boxes generated via genetic algorithms
- ARX-based key schedule
- Authenticated encryption with integrity verification
- Side-channel resistant implementations
- Key management with secure derivation and storage

## Installation

```bash
pip install ngcipher
```

Or install directly from GitHub:

```bash
pip install git+https://github.com/yourusername/ngcipher.git
```

## Quick Start

### Basic Encryption/Decryption

```python
from ngcipher.aead_mode.gcm_mode import encrypt, decrypt
from ngcipher.key_schedule.arx_key_schedule import generate_key

# Generate a random key
key = generate_key(32)  # 32 bytes = 256 bits

# Encrypt data
plaintext = b"This is a secret message"
ciphertext, tag, nonce = encrypt(plaintext, key)

# Decrypt data
decrypted = decrypt(ciphertext, tag, key, nonce)
print(decrypted.decode('utf-8'))  # "This is a secret message"
```

### Password-Based Encryption

```python
from ngcipher.key_schedule.arx_key_schedule import derive_key_from_password
from ngcipher.aead_mode.gcm_mode import encrypt, decrypt

# Generate a salt
import os
salt = os.urandom(16)

# Derive key from password
password = "your-strong-password"
key, _ = derive_key_from_password(password, salt)

# Encrypt data
plaintext = b"This is a secret message"
ciphertext, tag, nonce = encrypt(plaintext, key)

# To decrypt later, you'll need the password, salt, ciphertext, tag, and nonce
```

## Documentation

For detailed documentation, visit [https://github.com/yourusername/ngcipher/wiki](https://github.com/PHARA0H1/ngcipher/wiki).

## Security Considerations

- This is a research-grade implementation; use for learning and experimentation.
- The library aims to exceed AES-256 security but has not undergone formal security audits.
- Always follow best practices for key management.

## License

MIT License
