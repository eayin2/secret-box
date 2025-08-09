#!/usr/bin/env python3
"""
secretbox_scrypt_passphrase.py

- Provide the secret string to encrypt via --secret-plaintext
- Provide the passphrase via --passphrase (128-char hex, but not named as such here)
- KDF: scrypt (n/r/p/length + salt are stored in the envelope)
- AEAD: Fernet
- Envelope JSON is self-describing and contains all KDF params + salt

Usage:
  # Encrypt to an envelope JSON file
  python secretbox_scrypt_passphrase.py encrypt \
      --secret-plaintext "super secret" \
      --passphrase "0123...abcdef" \
      --envelope-out secret.enc

  # Decrypt from the envelope (prints secret to stdout)
  python secretbox_scrypt_passphrase.py decrypt \
      --envelope-file secret.enc \
      --passphrase "0123...abcdef"
"""

import argparse
import json
import os
import sys
from base64 import urlsafe_b64encode, urlsafe_b64decode
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Default scrypt params (stored in envelope)
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32  # Fernet requires 32 bytes


# --- I/O helpers

def read_bytes(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        return f.read()

def write_bytes(filepath: str, data: bytes, *, force: bool = True) -> None:
    if not force and os.path.exists(filepath):
        raise FileExistsError(f"{filepath} already exists. Use --force to overwrite.")
    with open(filepath, "wb") as f:
        f.write(data)


# --- KDF & crypto

def derive_fernet_key_scrypt(passphrase_bytes: bytes, salt: bytes,
                             n: int, r: int, p: int, length: int) -> bytes:
    """scrypt(passphrase_bytes, salt, n,r,p,length) -- urlsafe base64 Fernet key."""
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    raw_key = kdf.derive(passphrase_bytes)
    return urlsafe_b64encode(raw_key)

def fernet_encrypt(secret_plaintext: bytes, fernet_key: bytes) -> bytes:
    return Fernet(fernet_key).encrypt(secret_plaintext)

def fernet_decrypt(ciphertext_token: bytes, fernet_key: bytes) -> bytes:
    return Fernet(fernet_key).decrypt(ciphertext_token)


# --- Envelope (JSON)

def build_envelope_bytes(*, salt: bytes, n: int, r: int, p: int,
                         length: int, ciphertext_token: bytes) -> bytes:
    env = {
        "enc": {"scheme": "fernet"},
        "kdf": {
            "name": "scrypt",
            "salt": urlsafe_b64encode(salt).decode("ascii"),
            "salt_len": len(salt),
            "n": n,
            "r": r,
            "p": p,
            "length": length,
        },
        "ciphertext": ciphertext_token.decode("ascii"),
    }
    return json.dumps(env, separators=(",", ":")).encode("utf-8")

def parse_envelope_bytes(data: bytes) -> Tuple[bytes, int, int, int, int, bytes]:
    """Return (salt, n, r, p, length, ciphertext_token)."""
    try:
        env = json.loads(data.decode("utf-8"))
        kdf = env["kdf"]
        salt = urlsafe_b64decode(kdf["salt"].encode("ascii"))
        n = int(kdf["n"]); r = int(kdf["r"]); p = int(kdf["p"])
        length = int(kdf["length"])
        ciphertext_token = env["ciphertext"].encode("ascii")
        return salt, n, r, p, length, ciphertext_token
    except Exception as e:
        raise ValueError(f"Invalid envelope: {e}")

# --- Commands

def encrypt_command(secret_plaintext: str, passphrase: str,
                    envelope_out: str, *, force: bool) -> None:
    salt = os.urandom(16)
    fkey = derive_fernet_key_scrypt(passphrase.encode("utf-8"), salt,
                                    SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LENGTH)
    token = fernet_encrypt(secret_plaintext.encode("utf-8"), fkey)
    envelope = build_envelope_bytes(salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                                    length=KEY_LENGTH, ciphertext_token=token)
    write_bytes(envelope_out, envelope, force=force)
    print(f"Encrypted → {envelope_out}")

def decrypt_command(envelope_file: str, passphrase: str) -> None:
    salt, n, r, p, length, token = parse_envelope_bytes(read_bytes(envelope_file))
    fkey = derive_fernet_key_scrypt(passphrase.encode("utf-8"), salt, n, r, p, length)
    try:
        secret_plaintext = fernet_decrypt(token, fkey)
    except Exception:
        raise SystemExit("Decryption failed (wrong passphrase or corrupted envelope).")
    sys.stdout.write(secret_plaintext.decode("utf-8"))
    sys.stdout.flush()


# --- CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Encrypt/decrypt a secret string using a passphrase (scrypt → Fernet).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encrypt", help="Encrypt a secret string into an envelope JSON.")
    pe.add_argument("--secret-plaintext", required=True,
                    help="Secret plaintext string to encrypt.")
    pe.add_argument("--passphrase", required=True,
                    help="Passphrase to derive encryption key.")
    pe.add_argument("--envelope-out", required=True,
                    help="Output envelope path (JSON).")
    pe.add_argument("--force", action="store_true",
                    help="Overwrite existing envelope file.")
    pe.set_defaults(func=lambda args: encrypt_command(
        secret_plaintext=args.secret_plaintext,
        passphrase=args.passphrase,
        envelope_out=args.envelope_out,
        force=args.force,
    ))

    pd = sub.add_parser("decrypt", help="Decrypt an envelope JSON back to secret plaintext.")
    pd.add_argument("--envelope-file", required=True,
                    help="Input envelope path (JSON).")
    pd.add_argument("--passphrase", required=True,
                    help="Passphrase to derive encryption key.")
    pd.set_defaults(func=lambda args: decrypt_command(
        envelope_file=args.envelope_file,
        passphrase=args.passphrase,
    ))

    return p

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
