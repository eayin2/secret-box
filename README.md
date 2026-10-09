# Secretbox Scrypt Passphrase Tool

A small Python CLI utility for encrypting short secrets so that **any one of
several passphrases** can decrypt them. Uses scrypt for key derivation and
[Fernet](https://cryptography.io/en/latest/fernet/) for authenticated encryption.

## Setup

Requires Python 3.10 or later. Install the dependencies with `uv sync`, then run
the commands below with `uv run python` in place of `python`, or activate the
project's virtual environment first.

## Usage

### Enter a secret without shell quoting

Use `--secret-prompt` to type or paste a single-line secret at a hidden prompt:

```bash
python secretbox.py encrypt \
    --secret-prompt \
    --passphrase 'first independent passphrase' \
    --passphrase 'second independent passphrase' \
    --envelope-out secret.enc
```

After `Secret plaintext (hidden):` appears, enter the secret exactly as it is,
without adding surrounding quotes, and press Enter. Characters such as `!`,
`$`, quotes, and backticks are treated literally. Input is not displayed or
included in the shell command history. The prompt requires a terminal with
hidden input support; it will stop rather than fall back to visible input.
Press Ctrl+C to cancel. Use either `--secret-prompt` or `--secret-plaintext`.

### Encrypt for multiple passphrases

Repeat `--passphrase` for each person or recovery passphrase that should have
access. Between 1 and 32 distinct, non-empty passphrases are accepted. Unicode
passphrases are supported and matched exactly, including whitespace.

```bash
python secretbox.py encrypt \
    --secret-plaintext 'your secret' \
    --passphrase 'first independent passphrase' \
    --passphrase 'second independent passphrase' \
    --envelope-out secret.enc
```

### Decrypt with either passphrase

Supply just one of the passphrases used during encryption:

```bash
python secretbox.py decrypt \
    --envelope-file secret.enc \
    --passphrase 'second independent passphrase'
```

The secret is written to standard output without an added newline. An incorrect
passphrase or an unreadable envelope produces a nonzero exit status and no secret
output.

### Single-passphrase compatibility

The original command still works:

```bash
python secretbox.py encrypt \
    --secret-plaintext 'your secret' \
    --passphrase 'one passphrase' \
    --envelope-out secret.enc
```

Single-passphrase encryption retains the original envelope format, so older
versions can still read these files. Existing envelopes remain readable by this
version. Multiple-passphrase envelopes use version 2 and require this version of
the tool. To give an existing secret multiple passphrases, decrypt it and encrypt
it again with the desired passphrases. Use `--force` to overwrite an output file.

### Shell quoting errors (`!`, `dquote>`)

In interactive zsh, `!` can trigger history expansion even inside double quotes,
before Python starts. For a value containing `!`, use straight single quotes:
`--secret-plaintext 'example!secret'`. The same rule applies to passphrases.
If the terminal shows `dquote>`, it is waiting for a closing double quote;
press Ctrl+C to cancel the unfinished command and re-enter it with matched quotes.
If the secret contains both kinds of quotes, use `--secret-prompt` to avoid shell
quoting entirely. See the [zsh history expansion documentation](https://zsh.sourceforge.io/Doc/Release/Expansion.html#History-Expansion).

## How multiple passphrases work

The tool generates a random Fernet data key and encrypts the secret once. For
each passphrase, it derives a separate wrapping key with scrypt and a fresh
16-byte random salt, then encrypts the data key with that wrapping key. These
encrypted copies of the data key are stored in `key_slots`.

Decryption tries the supplied passphrase against each slot until it can recover
the data key and authenticate the secret. The envelope stores neither the
passphrases nor the unencrypted data key. Encryption and worst-case decryption
cost grow with the number of slots.

This grants every listed passphrase full access. Security against guessing is
limited by the weakest passphrase. Changing or removing a passphrase requires
creating a fresh envelope; it cannot revoke access to old copies someone has
already saved. As in the original CLI, command-line secrets and passphrases may
appear in shell history and process arguments.

## Envelope formats

Multiple-passphrase envelopes have this structure (one slot shown):

```json
{
  "version": 2,
  "enc": { "scheme": "fernet" },
  "key_slots": [
    {
      "kdf": {
        "name": "scrypt",
        "salt": "<URL-safe base64>",
        "salt_len": 16,
        "n": 16384,
        "r": 8,
        "p": 1,
        "length": 32
      },
      "wrapped_key": "<Fernet-encrypted data key>"
    }
  ],
  "ciphertext": "<Fernet-encrypted secret>"
}
```

Each `wrapped_key` encrypts the same 44-byte URL-safe base64 Fernet data key.
The original single-passphrase format has no `version` or `key_slots`; its `kdf`
is at the top level and derives the key that encrypts `ciphertext` directly.
Scrypt parameters are stored in each envelope; new encryptions use the defaults
shown above. The reader validates the format and bounds scrypt's estimated main
memory (`128*n*r`, at most 256 MiB) and total work (sum of `n*r*p`, at most 2^24)
before attempting decryption. Manually customized older envelopes beyond those
limits are rejected.

Fernet authenticates each encrypted token. The slot list itself is not signed;
damaging or removing a slot can deny its holder access without affecting other
valid slots.

## Tests

```bash
uv run python -m unittest discover -s tests -v
```
