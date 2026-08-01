"""Tests for Authy / Aegis / otpauth URI source parsers (fixture data only)."""

import base64
import csv
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure project root is importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ga_to_bitwarden as m  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"

# Clearly synthetic base32 placeholders (valid alphabet, low-entropy, not real credentials).
# Do not use well-known demo seeds that secret scanners flag as high-entropy secrets.
DEMO_SECRET_B32 = "EXAMPLENOTREALAA"
DEMO_SECRET_BYTES = base64.b32decode(DEMO_SECRET_B32)

DEMO_SECRET_B32_2 = "EXAMPLENOTREALBB"


class TestOtpauthUri(unittest.TestCase):
    def test_basic_totp(self):
        uri = f"otpauth://totp/Example:user@example.com?secret={DEMO_SECRET_B32}&issuer=Example"
        acct = m.parse_otpauth_uri(uri)
        self.assertIsNotNone(acct)
        self.assertEqual(acct["name"], "user@example.com")
        self.assertEqual(acct["issuer"], "Example")
        self.assertEqual(m.secret_to_b32(acct["secret"]), DEMO_SECRET_B32)
        self.assertEqual(acct["type"], "totp")
        self.assertEqual(acct["digits"], 6)
        self.assertEqual(acct["source"], "otpauth-uri")

    def test_non_default_params(self):
        uri = (
            f"otpauth://totp/GitHub:octocat?secret={DEMO_SECRET_B32_2}"
            f"&issuer=GitHub&algorithm=SHA256&digits=8&period=60"
        )
        acct = m.parse_otpauth_uri(uri)
        self.assertEqual(acct["algorithm"], "SHA256")
        self.assertEqual(acct["digits"], 8)
        self.assertEqual(acct["period"], 60)

    def test_hotp(self):
        uri = f"otpauth://hotp/Counter:acct?secret={DEMO_SECRET_B32}&counter=3&issuer=Counter"
        acct = m.parse_otpauth_uri(uri)
        self.assertEqual(acct["type"], "hotp")
        self.assertEqual(acct["counter"], 3)

    def test_missing_secret(self):
        self.assertIsNone(m.parse_otpauth_uri("otpauth://totp/NoSecret?issuer=X"))

    def test_text_file_multiple_uris(self):
        text = f"""
        # comments ignored
        otpauth://totp/A:one?secret={DEMO_SECRET_B32}&issuer=A
        otpauth://totp/B:two?secret={DEMO_SECRET_B32_2}&issuer=B
        """
        accounts = m.parse_otpauth_text(text)
        self.assertEqual(len(accounts), 2)
        self.assertEqual(accounts[0]["issuer"], "A")
        self.assertEqual(accounts[1]["issuer"], "B")

    def test_fixture_file(self):
        path = FIXTURES / "otpauth_uris.txt"
        accounts = m.load_accounts_from_file(str(path), fmt="otpauth")
        self.assertGreaterEqual(len(accounts), 2)
        names = {a["name"] for a in accounts}
        self.assertIn("alice@example.com", names)


class TestAegis(unittest.TestCase):
    def test_fixture_aegis_export(self):
        path = FIXTURES / "aegis_export.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue(m.is_aegis_export(data))
        accounts = m.parse_aegis_export(data)
        self.assertEqual(len(accounts), 2)
        by_issuer = {a["issuer"]: a for a in accounts}
        self.assertIn("Example", by_issuer)
        self.assertEqual(m.secret_to_b32(by_issuer["Example"]["secret"]), DEMO_SECRET_B32)
        self.assertEqual(by_issuer["GitHub"]["digits"], 8)
        self.assertEqual(by_issuer["GitHub"]["algorithm"], "SHA256")
        self.assertEqual(accounts[0]["source"], "aegis")

    def test_encrypted_rejected(self):
        data = {
            "version": 1,
            "header": {"slots": [{"type": "raw", "key": "x"}], "params": {}},
            "db": "ciphertext",
        }
        with self.assertRaises(ValueError) as ctx:
            m.parse_aegis_export(data)
        self.assertIn("encrypted", str(ctx.exception).lower())

    def test_auto_detect(self):
        path = FIXTURES / "aegis_export.json"
        fmt = m.detect_format(str(path))
        self.assertEqual(fmt, "aegis")


class TestAuthy(unittest.TestCase):
    def test_authenticator_tokens_shape(self):
        path = FIXTURES / "authy_export.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue(m.is_authy_export(data))
        accounts = m.parse_authy_export(data)
        self.assertEqual(len(accounts), 2)
        self.assertEqual(accounts[0]["source"], "authy")
        secrets = {m.secret_to_b32(a["secret"]) for a in accounts}
        self.assertIn(DEMO_SECRET_B32, secrets)

    def test_simple_array_shape(self):
        data = [
            {"name": "ServiceA", "secret": DEMO_SECRET_B32, "issuer": "SvcA", "digits": 6},
            {"name": "ServiceB", "seed": DEMO_SECRET_B32_2, "digits": 7},
        ]
        accounts = m.parse_authy_export(data)
        self.assertEqual(len(accounts), 2)
        self.assertEqual(accounts[1]["digits"], 7)

    def test_encrypted_only_raises(self):
        data = {"authenticator_tokens": [{"name": "X", "encrypted_seed": "abc"}]}
        with self.assertRaises(ValueError) as ctx:
            m.parse_authy_export(data)
        self.assertIn("encrypted", str(ctx.exception).lower())

    def test_auto_detect(self):
        path = FIXTURES / "authy_export.json"
        self.assertEqual(m.detect_format(str(path)), "authy")


class TestGaMigrationBridge(unittest.TestCase):
    def test_ga_params_to_account(self):
        params = {
            "secret": DEMO_SECRET_BYTES,
            "name": "user",
            "issuer": "GA",
            "algorithm": 1,
            "digits": 1,
            "type": 2,
        }
        acct = m.ga_params_to_account(params)
        self.assertEqual(acct["source"], "google-authenticator")
        self.assertEqual(acct["algorithm"], "SHA1")
        self.assertEqual(acct["digits"], 6)


class TestCsvExport(unittest.TestCase):
    def test_export_default_and_nondefault(self):
        accounts = [
            m.make_account(DEMO_SECRET_B32, name="a", issuer="Ex", source="otpauth-uri"),
            m.make_account(
                DEMO_SECRET_B32_2, name="b", issuer="Gh",
                algorithm="SHA256", digits=8, period=60, source="aegis",
            ),
        ]
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out.csv")
            m.export_bitwarden_csv(accounts, out)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            # default params → bare secret
            self.assertEqual(rows[0]["login_totp"], DEMO_SECRET_B32)
            # non-default → full otpauth URI
            self.assertTrue(rows[1]["login_totp"].startswith("otpauth://totp/"))
            self.assertIn("algorithm=SHA256", rows[1]["login_totp"])
            self.assertIn("digits=8", rows[1]["login_totp"])


class TestCliEndToEnd(unittest.TestCase):
    def test_cli_otpauth_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "bw.csv")
            rc = m.main([str(FIXTURES / "otpauth_uris.txt"), "-o", out, "-q"])
            self.assertEqual(rc, 0)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertGreaterEqual(len(rows), 2)

    def test_cli_aegis_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "bw.csv")
            rc = m.main([str(FIXTURES / "aegis_export.json"), "-o", out, "-q", "-f", "aegis"])
            self.assertEqual(rc, 0)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)

    def test_cli_authy_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "bw.csv")
            rc = m.main([str(FIXTURES / "authy_export.json"), "-o", out, "-q"])
            self.assertEqual(rc, 0)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
