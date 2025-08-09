# Secretbox Scrypt Passphrase Tool

A small Python CLI utility for encrypting and decrypting short secrets using a passphrase.  
Uses **scrypt** as the key derivation function (KDF) and **Fernet** (AES + HMAC) for authenticated encryption.

## Features
- **Scrypt KDF** with configurable parameters (stored in envelope).
- **Authenticated encryption** via the [cryptography](https://cryptography.io/) library’s `Fernet` class.
- Self-describing JSON envelope containing:
  - KDF parameters (name, salt, N, r, p, length)
  - Ciphertext token
  - Encryption scheme identifier

## Usage

### Encrypt a secret

```bash
python secretbox_scrypt_passphrase.py encrypt \
    --secret-plaintext "your secret" \
    --passphrase "0123456789abcdef..." \
    --envelope-out secret.enc
```

### Decrypt a secret

```bash
python secretbox_scrypt_passphrase.py decrypt \
    --envelope-file secret.enc \
    --passphrase "0123456789abcdef..."
```

## Envelope Format

The output envelope is UTF-8 JSON with this structure:

```json
{
  "enc": { "scheme": "fernet" },
  "kdf": {
    "name": "scrypt",
    "salt": "<base64>",
    "salt_len": 16,
    "n": 16384,
    "r": 8,
    "p": 1,
    "length": 32
  },
  "ciphertext": "<Fernet token, URL-safe base64>"
}
```

All parameters needed for key derivation and decryption are included.
