import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings

from cryptography.fernet import Fernet, InvalidToken

import secretbox


# Produced by the unmodified upstream script, commit cc8b911.
LEGACY_ENVELOPE = b'{"enc":{"scheme":"fernet"},"kdf":{"name":"scrypt","salt":"V6G4sGd0YO7w6WK4lmuGow==","salt_len":16,"n":16384,"r":8,"p":1,"length":32},"ciphertext":"gAAAAABqyTYlNhGRNyRyQfDUvALcnN4VVMG4arLoftvz71oqdR3vL_nPtZC5ElkkyYnwDheFMfre8Cn-NeGK1kY6xSRdoKtN3W0HlRFRayD6IO-yb40UsEo="}'
SCRIPT = Path(secretbox.__file__).resolve()


def encode(envelope):
    return json.dumps(envelope).encode("utf-8")


def tamper(token):
    # Change authenticated content while retaining a valid base64 token.
    return token[:30] + ("A" if token[30] != "A" else "B") + token[31:]


class EnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secret = "A secret with Unicode 🔐\nAnd a second line.".encode("utf-8")
        cls.phrases = ["first independent passphrase", " recovery phrase ", "秘密🔑"]
        cls.data = secretbox.encrypt_envelope(cls.secret, cls.phrases)
        cls.envelope = json.loads(cls.data)

    def test_every_passphrase_unlocks_independently(self):
        for phrase in self.phrases:
            with self.subTest(phrase=phrase):
                self.assertEqual(secretbox.decrypt_envelope(self.data, phrase), self.secret)

    def test_wrong_passphrase_and_whitespace_changes_fail(self):
        for phrase in ("unrelated passphrase", "recovery phrase", ""):
            with self.subTest(phrase=phrase), self.assertRaises(InvalidToken):
                secretbox.decrypt_envelope(self.data, phrase)

    def test_original_envelope_remains_readable(self):
        self.assertEqual(
            secretbox.decrypt_envelope(LEGACY_ENVELOPE, "legacy-test-passphrase"),
            "Existing secret 🔐".encode("utf-8"),
        )

    def test_wrong_legacy_passphrase_fails(self):
        with self.assertRaises(InvalidToken):
            secretbox.decrypt_envelope(LEGACY_ENVELOPE, "wrong")

    def test_single_passphrase_retains_original_format(self):
        data = secretbox.encrypt_envelope(self.secret, [self.phrases[0]])
        env = json.loads(data)
        self.assertNotIn("version", env)
        self.assertNotIn("key_slots", env)
        self.assertEqual(secretbox.decrypt_envelope(data, self.phrases[0]), self.secret)

    def test_single_string_is_not_split_into_characters(self):
        data = secretbox.encrypt_envelope(self.secret, self.phrases[0])
        self.assertNotIn("version", json.loads(data))
        self.assertEqual(secretbox.decrypt_envelope(data, self.phrases[0]), self.secret)

    def test_empty_secret_round_trips(self):
        data = secretbox.encrypt_envelope(b"", self.phrases)
        self.assertEqual(secretbox.decrypt_envelope(data, self.phrases[-1]), b"")

    def test_slots_use_independent_salts_and_wrap_one_random_key(self):
        slots = self.envelope["key_slots"]
        self.assertEqual(len({slot["kdf"]["salt"] for slot in slots}), len(self.phrases))
        keys = []
        for phrase, slot in zip(self.phrases, slots):
            wrapping_key = secretbox.derive_fernet_key_scrypt(
                phrase.encode("utf-8"), *secretbox.parse_kdf_metadata(slot["kdf"])
            )
            keys.append(Fernet(wrapping_key).decrypt(slot["wrapped_key"]))
            with self.assertRaises(InvalidToken):
                Fernet(wrapping_key).decrypt(self.envelope["ciphertext"])
        self.assertEqual(len(set(keys)), 1)
        self.assertEqual(Fernet(keys[0]).decrypt(self.envelope["ciphertext"]), self.secret)
        self.assertNotIn(keys[0], self.data)
        self.assertNotIn(self.secret, self.data)
        for phrase in self.phrases:
            self.assertNotIn(phrase.encode("utf-8"), self.data)

    def test_repeated_encryption_uses_fresh_keys_and_salts(self):
        another = json.loads(secretbox.encrypt_envelope(self.secret, self.phrases))
        self.assertNotEqual(self.envelope["ciphertext"], another["ciphertext"])
        self.assertTrue(
            {slot["kdf"]["salt"] for slot in self.envelope["key_slots"]}.isdisjoint(
                slot["kdf"]["salt"] for slot in another["key_slots"]
            )
        )

    def test_modified_ciphertext_is_rejected_for_every_passphrase(self):
        env = copy.deepcopy(self.envelope)
        env["ciphertext"] = tamper(env["ciphertext"])
        for phrase in self.phrases:
            with self.subTest(phrase=phrase), self.assertRaises(InvalidToken):
                secretbox.decrypt_envelope(encode(env), phrase)

    def test_damaged_slot_does_not_block_other_passphrases(self):
        env = copy.deepcopy(self.envelope)
        env["key_slots"][0]["wrapped_key"] = tamper(env["key_slots"][0]["wrapped_key"])
        with self.assertRaises(InvalidToken):
            secretbox.decrypt_envelope(encode(env), self.phrases[0])
        for phrase in self.phrases[1:]:
            self.assertEqual(secretbox.decrypt_envelope(encode(env), phrase), self.secret)

    def test_foreign_slot_cannot_unlock_other_envelope(self):
        other = json.loads(secretbox.encrypt_envelope(b"different secret", ["foreign", "other"]))
        env = copy.deepcopy(self.envelope)
        env["key_slots"].insert(0, other["key_slots"][0])
        with self.assertRaises(InvalidToken):
            secretbox.decrypt_envelope(encode(env), "foreign")
        self.assertEqual(secretbox.decrypt_envelope(encode(env), self.phrases[0]), self.secret)

    def test_invalid_passphrase_lists_rejected_before_kdf(self):
        cases = ([], [""], ["ok", ""], ["same", "same"], ["ok", 3],
                 [str(i) for i in range(secretbox.MAX_PASSPHRASES + 1)])
        with patch.object(secretbox, "derive_fernet_key_scrypt") as derive:
            for phrases in cases:
                with self.subTest(phrases=phrases), self.assertRaises(ValueError):
                    secretbox.encrypt_envelope(self.secret, phrases)
            derive.assert_not_called()

    def test_malformed_and_unsupported_envelopes_rejected_before_kdf(self):
        cases = [b"not json", b"null", b"[]", b"{}", b"\xff"]
        changes = [
            ("version", 3), ("version", True), ("version", 2.0),
            ("enc", {"scheme": "unknown"}), ("ciphertext", 4),
            ("key_slots", []), ("key_slots", {}), ("key_slots", [None]),
            ("key_slots", self.envelope["key_slots"] * 33),
            ("kdf", self.envelope["key_slots"][0]["kdf"]),
        ]
        for key, value in changes:
            env = copy.deepcopy(self.envelope)
            env[key] = value
            cases.append(encode(env))
        env = copy.deepcopy(self.envelope)
        del env["version"]
        cases.append(encode(env))
        for field, value in [
            ("name", "unknown"), ("salt", "***"), ("salt_len", 1),
            ("n", 3), ("n", True), ("n", "16384"), ("n", 2**30),
            ("r", 0), ("p", -1), ("p", 2**20), ("length", 31),
        ]:
            env = copy.deepcopy(self.envelope)
            env["key_slots"][0]["kdf"][field] = value
            cases.append(encode(env))
        env = copy.deepcopy(self.envelope)
        for slot in env["key_slots"]:
            slot["kdf"]["p"] = 64  # Individually allowed, collectively excessive.
        cases.append(encode(env))
        with patch.object(secretbox, "derive_fernet_key_scrypt") as derive:
            for data in cases:
                with self.subTest(data=data), self.assertRaises(ValueError):
                    secretbox.decrypt_envelope(data, self.phrases[0])
            derive.assert_not_called()


class CLITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "secret.enc"

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )

    def encrypt(self, *phrases, extra=()):
        args = ["encrypt", "--secret-plaintext", "CLI secret 🔐", "--envelope-out", self.output]
        for phrase in phrases:
            args.extend(["--passphrase", phrase])
        return self.run_cli(*args, *extra)

    def test_repeated_flags_and_any_one_passphrase(self):
        result = self.encrypt("first", "second", "third")
        self.assertEqual(result.returncode, 0, result.stderr)
        for phrase in ("first", "second", "third"):
            result = self.run_cli("decrypt", "--envelope-file", self.output, "--passphrase", phrase)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "CLI secret 🔐")
            self.assertEqual(result.stderr, "")

    def test_hidden_prompt_preserves_special_characters_and_whitespace(self):
        secret = "  secret!$HOME $(example) `example` 'single' \"double\" \\ 🔐  "
        args = secretbox.build_parser().parse_args([
            "encrypt", "--secret-prompt", "--passphrase", "first",
            "--passphrase", "second", "--envelope-out", str(self.output),
        ])
        stdout = io.StringIO()
        with patch.object(secretbox.getpass, "getpass", return_value=secret), redirect_stdout(stdout):
            args.func(args)
        self.assertNotIn(secret, stdout.getvalue())
        for phrase in ("first", "second"):
            self.assertEqual(secretbox.decrypt_envelope(self.output.read_bytes(), phrase), secret.encode("utf-8"))

    def test_hidden_prompt_refuses_visible_input_fallback(self):
        def unavailable_prompt(*args):
            warnings.warn("Cannot hide input", secretbox.getpass.GetPassWarning)
            self.fail("Prompt must stop before reading visible input")

        with patch.object(secretbox.getpass, "getpass", side_effect=unavailable_prompt):
            with self.assertRaisesRegex(ValueError, "Hidden input is unavailable"):
                secretbox.prompt_secret()

    def test_cancelled_prompt_does_not_create_envelope(self):
        argv = [str(SCRIPT), "encrypt", "--secret-prompt", "--passphrase", "first",
                "--envelope-out", str(self.output)]
        for exception in (EOFError, KeyboardInterrupt):
            stderr = io.StringIO()
            with self.subTest(exception=exception), patch.object(sys, "argv", argv):
                with patch.object(secretbox.getpass, "getpass", side_effect=exception):
                    with redirect_stderr(stderr), self.assertRaises(SystemExit) as result:
                        secretbox.main()
                self.assertEqual(result.exception.code, 1)
                self.assertIn("Input cancelled", stderr.getvalue())
                self.assertFalse(self.output.exists())

    def test_prompt_and_plaintext_are_mutually_exclusive(self):
        result = self.encrypt("first", extra=["--secret-prompt"])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())

    def test_literal_special_characters_in_plaintext_argument(self):
        secret = "quotes ' \" ! $ ` \\ and spaces"
        result = self.run_cli("encrypt", "--secret-plaintext", secret,
                              "--passphrase", "first", "--envelope-out", self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(secretbox.decrypt_envelope(self.output.read_bytes(), "first"), secret.encode())

    def test_wrong_passphrase_outputs_no_plaintext_or_traceback(self):
        self.assertEqual(self.encrypt("first", "second").returncode, 0)
        result = self.run_cli("decrypt", "--envelope-file", self.output, "--passphrase", "wrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("Decryption failed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_corrupt_file_outputs_no_plaintext_or_traceback(self):
        self.output.write_text('{"version": 2}', encoding="utf-8")
        result = self.run_cli("decrypt", "--envelope-file", self.output, "--passphrase", "test")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)

    def test_existing_file_requires_force(self):
        self.output.write_bytes(b"existing contents")
        result = self.encrypt("first", "second")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--force", result.stderr)
        self.assertEqual(self.output.read_bytes(), b"existing contents")
        result = self.encrypt("first", "second", extra=["--force"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(secretbox.decrypt_envelope(self.output.read_bytes(), "second"), "CLI secret 🔐".encode())

    def test_empty_or_duplicate_passphrases_do_not_create_output(self):
        for phrases in (("",), ("same", "same")):
            with self.subTest(phrases=phrases):
                result = self.encrypt(*phrases)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(self.output.exists())

    def test_missing_passphrase_is_usage_error(self):
        result = self.encrypt()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
