"""Tests for Authy / Aegis / otpauth URI source parsers (fixture data only)."""

import base64
import contextlib
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure project root is importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ga_to_bitwarden as m

FIXTURES = Path(__file__).parent / "fixtures"

# Clearly synthetic base32 placeholders (valid alphabet, low-entropy, not real credentials).
# Do not use well-known demo seeds that secret scanners flag as high-entropy secrets.
DEMO_SECRET_B32 = "EXAMPLENOTREALAA"
DEMO_SECRET_BYTES = base64.b32decode(DEMO_SECRET_B32)

DEMO_SECRET_B32_2 = "EXAMPLENOTREALBB"
DEMO_SECRET_B32_3 = "EXAMPLENOTREALCC"


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

    def test_fixture_hotp(self):
        accounts = m.parse_otpauth_text((FIXTURES / "otpauth_uris.txt").read_text())
        hotp = next(a for a in accounts if a["type"] == "hotp")
        self.assertEqual(hotp["issuer"], "Example HOTP")
        self.assertEqual(hotp["algorithm"], "SHA512")
        self.assertEqual(hotp["digits"], 8)
        self.assertEqual(hotp["counter"], 5)

    def test_hotp(self):
        uri = f"otpauth://hotp/Counter:acct?secret={DEMO_SECRET_B32}&counter=3&issuer=Counter"
        acct = m.parse_otpauth_uri(uri)
        self.assertEqual(acct["type"], "hotp")
        self.assertEqual(acct["counter"], 3)

    def test_missing_secret(self):
        self.assertIsNone(m.parse_otpauth_uri("otpauth://totp/NoSecret?issuer=X"))

    def test_invalid_secret_rejected_with_account_name(self):
        uri = "otpauth://totp/BadAccount?secret=NOT-BASE32-!!"
        with self.assertRaisesRegex(ValueError, "Invalid secret for BadAccount"):
            m.parse_otpauth_uri(uri)

    def test_hex_looking_secret_warns_before_legacy_conversion(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            account = m.make_account("0123456789abcdef", name="Hex account")
        self.assertEqual(account["secret"], bytes.fromhex("0123456789abcdef"))
        self.assertIn("interpreting a hex-looking secret as hexadecimal", stderr.getvalue())
        self.assertNotIn("0123456789abcdef", stderr.getvalue())

    def test_invalid_digits_and_period_warn_when_using_defaults(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            account = m.make_account(
                DEMO_SECRET_B32, name="Odd parameters", digits="abc", period="xyz"
            )
        self.assertEqual(account["digits"], 6)
        self.assertEqual(account["period"], 30)
        self.assertIn("Invalid digits for Odd parameters", stderr.getvalue())
        self.assertIn("Invalid period for Odd parameters", stderr.getvalue())

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
        self.assertEqual(len(accounts), 3)
        by_issuer = {a["issuer"]: a for a in accounts}
        self.assertIn("Example", by_issuer)
        self.assertEqual(m.secret_to_b32(by_issuer["Example"]["secret"]), DEMO_SECRET_B32)
        self.assertEqual(by_issuer["GitHub"]["digits"], 8)
        self.assertEqual(by_issuer["GitHub"]["algorithm"], "SHA256")
        hotp = by_issuer["Example HOTP"]
        self.assertEqual(hotp["type"], "hotp")
        self.assertEqual(hotp["algorithm"], "SHA512")
        self.assertEqual(hotp["counter"], 5)
        self.assertEqual(m.secret_to_b32(hotp["secret"]), DEMO_SECRET_B32_3)
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

    def test_invalid_secret_rejected_with_entry_name(self):
        data = {"db": {"entries": [{"name": "Bad Aegis", "info": {"secret": "BAD!!"}}]}}
        with self.assertRaisesRegex(ValueError, "Invalid secret for Bad Aegis"):
            m.parse_aegis_export(data)

    def test_encrypted_auto_detection_and_cli_error(self):
        data = {"header": {"slots": [{"type": "raw"}]}, "db": "ciphertext"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "encrypted.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(m.detect_format(str(path)), "aegis")
            stdout = io.StringIO()
            stderr = io.StringIO()
            output = Path(tmp) / "out.csv"
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = m.main([str(path), "-o", str(output), "-q"])
            self.assertNotEqual(rc, 0)
            self.assertIn("appears encrypted", stdout.getvalue())
            self.assertFalse(output.exists())


class TestAuthy(unittest.TestCase):
    def test_authenticator_tokens_shape(self):
        path = FIXTURES / "authy_export.json"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue(m.is_authy_export(data))
        accounts = m.parse_authy_export(data)
        self.assertEqual(len(accounts), 3)
        self.assertEqual(accounts[0]["source"], "authy")
        hotp = next(a for a in accounts if a["type"] == "hotp")
        self.assertEqual(hotp["counter"], 5)
        self.assertEqual(hotp["algorithm"], "SHA512")
        self.assertEqual(m.secret_to_b32(hotp["secret"]), DEMO_SECRET_B32_3)
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

    def test_invalid_secret_rejected_with_token_name(self):
        data = [{"name": "Bad Authy", "secret": "BAD!!"}]
        with self.assertRaisesRegex(ValueError, "Invalid secret for Bad Authy"):
            m.parse_authy_export(data)

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
    def test_empty_secret_is_rejected_before_csv_is_opened(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.csv"
            with self.assertRaisesRegex(ValueError, "Invalid secret for Broken account"):
                m.export_accounts_to_csv(
                    [{"name": "Broken account", "secret": b""}], str(out)
                )
            self.assertFalse(out.exists())

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
            self.assertEqual(len(rows), 3)

    def test_cli_authy_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "bw.csv")
            rc = m.main([str(FIXTURES / "authy_export.json"), "-o", out, "-q"])
            self.assertEqual(rc, 0)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 3)

    def test_cli_auto_detects_extensionless_otpauth_text(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "accounts"
            source.write_text(
                f"otpauth://hotp/Example:counter-user?secret={DEMO_SECRET_B32_3}&counter=5",
                encoding="utf-8",
            )
            out = Path(td) / "bw.csv"
            rc = m.main([str(source), "-o", str(out), "-q"])
            self.assertEqual(rc, 0)
            with out.open(newline="", encoding="utf-8") as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["login_username"], "counter-user")
            self.assertTrue(row["login_totp"].startswith("otpauth://hotp/"))
            self.assertIn("counter=5", row["login_totp"])

    def test_cli_auto_detects_each_file_in_directory(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "imports"
            directory.mkdir()
            (directory / "aegis.json").write_text(
                (FIXTURES / "aegis_export.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (directory / "authy.json").write_text(
                (FIXTURES / "authy_export.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (directory / "uris.txt").write_text(
                f"otpauth://totp/Example:directory?secret={DEMO_SECRET_B32}",
                encoding="utf-8",
            )
            output = Path(td) / "out.csv"
            rc = m.main([str(directory), "-o", str(output), "-q"])
            self.assertEqual(rc, 0)
            with output.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 7)

    def test_invalid_cli_secret_fails_without_empty_totp_or_success(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "invalid.txt"
            source.write_text(
                "otpauth://totp/BadAccount?secret=NOT-BASE32-!!", encoding="utf-8"
            )
            output = Path(td) / "out.csv"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = m.main([str(source), "-o", str(output), "-q"])
            self.assertNotEqual(rc, 0)
            self.assertIn("Invalid secret for BadAccount", stdout.getvalue())
            self.assertNotIn("Successfully exported", stdout.getvalue())
            self.assertFalse(output.exists())

    def test_cli_exports_hotp_metadata_for_each_source(self):
        fixtures = [
            ("aegis_export.json", "Aegis Migration"),
            ("authy_export.json", "Authy Migration"),
            ("otpauth_uris.txt", "otpauth URI Import"),
        ]
        with tempfile.TemporaryDirectory() as td:
            for filename, folder in fixtures:
                with self.subTest(filename=filename):
                    out = os.path.join(td, filename + ".csv")
                    rc = m.main([str(FIXTURES / filename), "-o", out, "-q"])
                    self.assertEqual(rc, 0)
                    with open(out, newline="", encoding="utf-8") as f:
                        rows = list(csv.DictReader(f))
                    row = next(row for row in rows if row["login_username"] == "counter-user")
                    self.assertEqual(row["issuer"], "Example HOTP")
                    self.assertEqual(row["algorithm"], "SHA512")
                    self.assertEqual(row["digits"], "8")
                    self.assertEqual(row["counter"], "5")
                    self.assertEqual(row["folder"], folder)
                    self.assertTrue(row["login_totp"].startswith("otpauth://hotp/"))
                    self.assertIn("counter=5", row["login_totp"])

    def test_cli_default_output_no_output_flag(self):
        with tempfile.TemporaryDirectory() as td:
            orig_cwd = os.getcwd()
            try:
                os.chdir(td)
                rc = m.main([str(FIXTURES / "otpauth_uris.txt"), "-q"])
                self.assertEqual(rc, 0)
                csv_path = Path(td) / "bitwarden_import.csv"
                self.assertTrue(csv_path.exists())
                with open(csv_path, newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    self.assertEqual(reader.fieldnames, m.CSV_HEADERS)
                    rows = list(reader)
                self.assertGreaterEqual(len(rows), 2)
                for row in rows:
                    totp = row["login_totp"]
                    self.assertTrue(
                        totp.startswith("otpauth://")
                        or bool(base64.b32decode(totp, casefold=True)),
                        f"Expected valid login_totp row, got: {totp}",
                    )
            finally:
                os.chdir(orig_cwd)


if __name__ == "__main__":
    unittest.main()
