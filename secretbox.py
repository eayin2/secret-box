#!/usr/bin/env python3
"""
secretbox.py

- Provide the secret via --secret-plaintext or hidden input with --secret-prompt
- Repeat --passphrase to allow any one of several passphrases to unlock a secret
- KDF: scrypt (n/r/p/length + salt are stored in the envelope)
- Authenticated encryption: Fernet
- Envelope JSON is self-describing and contains all KDF params + salt

Usage:
  # Encrypt to an envelope JSON file
  python secretbox.py encrypt \
      --secret-plaintext "super secret" \
      --passphrase "0123...abcdef" \
      --passphrase "another independent passphrase" \
      --envelope-out secret.enc

  # Decrypt from the envelope (prints secret to stdout)
  python secretbox.py decrypt \
      --envelope-file secret.enc \
      --passphrase "0123...abcdef"
"""

import argparse
import getpass
import json
import os
import sys
import warnings
from base64 import b64decode, urlsafe_b64encode
from typing import Sequence, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Default scrypt params (stored in envelope)
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32  # Fernet requires 32 bytes
MAX_PASSPHRASES = 32
# Bound work requested by envelope metadata before running scrypt.
MAX_SCRYPT_MEMORY = 256 * 1024 * 1024
MAX_SCRYPT_WORK = 2**24  # Sum of n*r*p across all key slots


# --- I/O helpers

def prompt_secret() -> str:
    """Read one line without shell interpretation or terminal echo."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("Secret plaintext (hidden): ")
    except getpass.GetPassWarning:
        raise ValueError("Hidden input is unavailable. Run --secret-prompt from an interactive terminal.") from None


def read_bytes(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        return f.read()

def write_bytes(filepath: str, data: bytes, *, force: bool = True) -> None:
    try:
        with open(filepath, "wb" if force else "xb") as f:
            f.write(data)
    except FileExistsError:
        raise FileExistsError(f"{filepath} already exists. Use --force to overwrite.") from None


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

def build_kdf_metadata(salt: bytes, n: int, r: int, p: int, length: int) -> dict:
    return {
        "name": "scrypt",
        "salt": urlsafe_b64encode(salt).decode("ascii"),
        "salt_len": len(salt),
        "n": n,
        "r": r,
        "p": p,
        "length": length,
    }


def build_envelope_bytes(*, salt: bytes, n: int, r: int, p: int,
                         length: int, ciphertext_token: bytes) -> bytes:
    """Build the original single-passphrase format for compatibility."""
    env = {
        "enc": {"scheme": "fernet"},
        "kdf": build_kdf_metadata(salt, n, r, p, length),
        "ciphertext": ciphertext_token.decode("ascii"),
    }
    return json.dumps(env, separators=(",", ":")).encode("utf-8")

def parse_kdf_metadata(kdf: dict) -> Tuple[bytes, int, int, int, int]:
    if kdf["name"] != "scrypt":
        raise ValueError("Unsupported KDF")
    salt = b64decode(kdf["salt"].encode("ascii"), altchars=b"-_", validate=True)
    n, r, p, length = (kdf[field] for field in ("n", "r", "p", "length"))
    if any(type(value) is not int for value in (n, r, p, length)):
        raise ValueError("Invalid scrypt parameters")
    if n < 2 or n & (n - 1) or r < 1 or p < 1 or length != KEY_LENGTH:
        raise ValueError("Invalid scrypt parameters")
    if not salt or kdf["salt_len"] != len(salt):
        raise ValueError("Invalid salt")
    if 128 * n * r > MAX_SCRYPT_MEMORY or n * r * p > MAX_SCRYPT_WORK:
        raise ValueError("Scrypt resource limit exceeded")
    return salt, n, r, p, length


def parse_envelope_bytes(data: bytes) -> dict:
    """Validate both formats, including the total KDF cost, before deriving keys."""
    try:
        env = json.loads(data.decode("utf-8"))
        if env["enc"]["scheme"] != "fernet":
            raise ValueError("Unsupported encryption scheme")
        env["ciphertext"].encode("ascii")
        if "version" not in env:
            if "key_slots" in env:
                raise ValueError("Missing envelope version")
            parse_kdf_metadata(env["kdf"])
        else:
            if type(env["version"]) is not int or env["version"] != 2:
                raise ValueError("Unsupported envelope version")
            if "kdf" in env:
                raise ValueError("Ambiguous envelope format")
            slots = env["key_slots"]
            if not isinstance(slots, list) or not 1 <= len(slots) <= MAX_PASSPHRASES:
                raise ValueError("Invalid key slots")
            work = 0
            for slot in slots:
                _, n, r, p, _ = parse_kdf_metadata(slot["kdf"])
                slot["wrapped_key"].encode("ascii")
                work += n * r * p
            if work > MAX_SCRYPT_WORK:
                raise ValueError("Scrypt resource limit exceeded")
        return env
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("Invalid or unsupported envelope.") from None


def encrypt_envelope(secret_plaintext: bytes, passphrases: Sequence[str]) -> bytes:
    if isinstance(passphrases, str):
        passphrases = [passphrases]
    if not 1 <= len(passphrases) <= MAX_PASSPHRASES:
        raise ValueError(f"Provide between 1 and {MAX_PASSPHRASES} passphrases.")
    if any(not isinstance(phrase, str) or not phrase for phrase in passphrases):
        raise ValueError("Passphrases must be non-empty strings.")
    if len(set(passphrases)) != len(passphrases):
        raise ValueError("Passphrases must be distinct.")

    # Preserve the existing format when only one passphrase is supplied.
    if len(passphrases) == 1:
        salt = os.urandom(16)
        fkey = derive_fernet_key_scrypt(passphrases[0].encode("utf-8"), salt,
                                      SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LENGTH)
        return build_envelope_bytes(
            salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, length=KEY_LENGTH,
            ciphertext_token=fernet_encrypt(secret_plaintext, fkey),
        )

    data_key = Fernet.generate_key()
    slots = []
    for phrase in passphrases:
        salt = os.urandom(16)
        wrapping_key = derive_fernet_key_scrypt(phrase.encode("utf-8"), salt,
                                              SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LENGTH)
        slots.append({
            "kdf": build_kdf_metadata(salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LENGTH),
            "wrapped_key": fernet_encrypt(data_key, wrapping_key).decode("ascii"),
        })
    env = {
        "version": 2,
        "enc": {"scheme": "fernet"},
        "key_slots": slots,
        "ciphertext": fernet_encrypt(secret_plaintext, data_key).decode("ascii"),
    }
    return json.dumps(env, separators=(",", ":")).encode("utf-8")


def decrypt_envelope(data: bytes, passphrase: str) -> bytes:
    env = parse_envelope_bytes(data)
    token = env["ciphertext"].encode("ascii")
    passphrase_bytes = passphrase.encode("utf-8")
    if "version" not in env:
        fkey = derive_fernet_key_scrypt(passphrase_bytes, *parse_kdf_metadata(env["kdf"]))
        return fernet_decrypt(token, fkey)

    for slot in env["key_slots"]:
        wrapping_key = derive_fernet_key_scrypt(
            passphrase_bytes, *parse_kdf_metadata(slot["kdf"])
        )
        try:
            data_key = fernet_decrypt(slot["wrapped_key"].encode("ascii"), wrapping_key)
            return fernet_decrypt(token, data_key)
        except (InvalidToken, ValueError):
            continue
    raise InvalidToken

# --- Commands

def encrypt_command(secret_plaintext: str, passphrase: str | Sequence[str],
                    envelope_out: str, *, force: bool) -> None:
    envelope = encrypt_envelope(secret_plaintext.encode("utf-8"), passphrase)
    write_bytes(envelope_out, envelope, force=force)
    print(f"Encrypted → {envelope_out}")

def decrypt_command(envelope_file: str, passphrase: str) -> None:
    try:
        secret_plaintext = decrypt_envelope(read_bytes(envelope_file), passphrase).decode("utf-8")
    except (InvalidToken, ValueError):
        raise SystemExit("Decryption failed (wrong passphrase or corrupted/unsupported envelope).") from None
    sys.stdout.write(secret_plaintext)
    sys.stdout.flush()


# --- CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Encrypt a secret for one or more passphrases; decrypt with any one (scrypt → Fernet).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encrypt", help="Encrypt a secret string into an envelope JSON.")
    secret_input = pe.add_mutually_exclusive_group(required=True)
    secret_input.add_argument("--secret-plaintext",
                              help="Secret plaintext string to encrypt (requires shell quoting).")
    secret_input.add_argument("--secret-prompt", action="store_true",
                              help="Enter the secret at a hidden prompt; special characters are literal.")
    pe.add_argument("--passphrase", required=True, action="append",
                    help=f"Passphrase allowed to unlock the secret. Repeat for up to {MAX_PASSPHRASES} distinct passphrases.")
    pe.add_argument("--envelope-out", required=True,
                    help="Output envelope path (JSON).")
    pe.add_argument("--force", action="store_true",
                    help="Overwrite existing envelope file.")
    pe.set_defaults(func=lambda args: encrypt_command(
        secret_plaintext=prompt_secret() if args.secret_prompt else args.secret_plaintext,
        passphrase=args.passphrase,
        envelope_out=args.envelope_out,
        force=args.force,
    ))

    pd = sub.add_parser("decrypt", help="Decrypt an envelope JSON back to secret plaintext.")
    pd.add_argument("--envelope-file", required=True,
                    help="Input envelope path (JSON).")
    pd.add_argument("--passphrase", required=True,
                    help="Any one of the passphrases used when encrypting.")
    pd.set_defaults(func=lambda args: decrypt_command(
        envelope_file=args.envelope_file,
        passphrase=args.passphrase,
    ))

    return p

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except (EOFError, KeyboardInterrupt):
        parser.exit(1, "\nInput cancelled.\n")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")

if __name__ == "__main__":
    main()
