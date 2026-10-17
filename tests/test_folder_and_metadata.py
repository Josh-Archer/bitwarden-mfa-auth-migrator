"""Folder override and OTP metadata kept on Bitwarden CSV rows (#15)."""

from __future__ import annotations

import csv
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Ensure project root is importable when running pytest from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import ga_to_bitwarden as m  # noqa: E402
from tests.protobuf_fixtures import sample_accounts_payload  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
DEMO_SECRET_B32 = "EXAMPLENOTREALAA"
DEMO_SECRET_B32_2 = "EXAMPLENOTREALBB"

METADATA_COLUMNS = ("issuer", "algorithm", "digits", "period", "counter")


class TestOtpToCsvRowMetadata(unittest.TestCase):
    def test_default_folder_and_protobuf_enums(self):
        row = m.otp_to_csv_row(
            {
                "secret": b"\x01\x02\x03\x04\x05",
                "name": "user",
                "issuer": "GitHub",
                "algorithm": 2,  # SHA256
                "digits": 2,  # 8
                "type": 1,  # HOTP
                "counter": 7,
            }
        )
        self.assertEqual(row["folder"], m.DEFAULT_BW_FOLDER)
        self.assertEqual(row["folder"], "Google Authenticator Migration")
        self.assertEqual(row["type"], "login")
        self.assertEqual(row["issuer"], "GitHub")
        self.assertEqual(row["algorithm"], "SHA256")
        self.assertEqual(row["digits"], "8")
        self.assertEqual(row["period"], "30")
        self.assertEqual(row["counter"], "7")
        self.assertTrue(row["login_totp"].startswith("otpauth://hotp/"))
        self.assertIn("algorithm=SHA256", row["login_totp"])
        self.assertIn("digits=8", row["login_totp"])
        self.assertIn("counter=7", row["login_totp"])
        self.assertIn("issuer=GitHub", row["login_totp"])

    def test_custom_and_blank_folder(self):
        otp = {"secret": b"abc", "name": "only-name", "period": 45}
        custom = m.otp_to_csv_row(otp, folder="Ops")
        self.assertEqual(custom["folder"], "Ops")
        blank = m.otp_to_csv_row(otp, folder="")
        self.assertEqual(blank["folder"], "")
        self.assertEqual(blank["issuer"], "")
        self.assertEqual(blank["algorithm"], "SHA1")
        self.assertEqual(blank["digits"], "6")
        self.assertEqual(blank["period"], "45")
        self.assertEqual(blank["counter"], "0")

    def test_normalized_account_keeps_period(self):
        account = m.make_account(
            DEMO_SECRET_B32,
            name="bob",
            issuer="Bank",
            algorithm="sha-512",
            digits=8,
            period=60,
            source="aegis",
        )
        row = m.otp_to_csv_row(account, folder="Vault")
        self.assertEqual(row["folder"], "Vault")
        self.assertEqual(row["issuer"], "Bank")
        self.assertEqual(row["algorithm"], "SHA512")
        self.assertEqual(row["digits"], "8")
        self.assertEqual(row["period"], "60")
        self.assertEqual(row["counter"], "0")
        self.assertIn("algorithm=SHA512", row["login_totp"])
        self.assertIn("period=60", row["login_totp"])

    def test_unspecified_enums_use_defaults(self):
        row = m.otp_to_csv_row(
            {
                "secret": b"\x55" * 10,
                "name": "plain",
                "algorithm": 0,
                "digits": 0,
                "type": 2,
            }
        )
        self.assertEqual(row["issuer"], "")
        self.assertEqual(row["algorithm"], "SHA1")
        self.assertEqual(row["digits"], "6")
        self.assertEqual(row["period"], "30")
        self.assertEqual(row["counter"], "0")


class TestCsvWritersKeepMetadata(unittest.TestCase):
    def test_export_accounts_to_csv_folder_and_columns(self):
        payload, _expected = sample_accounts_payload()
        accounts = m.parse_migration_payload(payload)
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.csv")
            count = m.export_accounts_to_csv(accounts, out, folder="Imported")
            self.assertEqual(count, 2)
            with open(out, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                self.assertEqual(reader.fieldnames, m.CSV_HEADERS)
                rows = list(reader)

        self.assertEqual(rows[0]["folder"], "Imported")
        self.assertEqual(rows[0]["issuer"], "GitHub")
        self.assertEqual(rows[0]["algorithm"], "SHA1")
        self.assertEqual(rows[0]["digits"], "6")
        self.assertEqual(rows[0]["period"], "30")
        self.assertEqual(rows[0]["counter"], "0")
        self.assertEqual(rows[1]["issuer"], "Example Corp")
        for column in METADATA_COLUMNS:
            self.assertIn(column, m.CSV_HEADERS)

    def test_export_bitwarden_csv_source_default_and_override(self):
        accounts = [
            m.make_account(
                DEMO_SECRET_B32, name="alice", issuer="Example", source="aegis",
            ),
            m.make_account(
                DEMO_SECRET_B32_2,
                name="bob",
                issuer="GitHub",
                algorithm="SHA256",
                digits=8,
                period=60,
                source="aegis",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            default_path = os.path.join(tmp, "default.csv")
            custom_path = os.path.join(tmp, "custom.csv")
            blank_path = os.path.join(tmp, "blank.csv")
            m.export_bitwarden_csv(accounts, default_path)
            m.export_bitwarden_csv(accounts, custom_path, folder="Shared")
            m.export_bitwarden_csv(accounts, blank_path, folder="")

            with open(default_path, newline="", encoding="utf-8") as f:
                default_rows = list(csv.DictReader(f))
            with open(custom_path, newline="", encoding="utf-8") as f:
                custom_rows = list(csv.DictReader(f))
            with open(blank_path, newline="", encoding="utf-8") as f:
                blank_rows = list(csv.DictReader(f))

        self.assertEqual(default_rows[0]["folder"], "Aegis Migration")
        self.assertEqual(default_rows[0]["issuer"], "Example")
        self.assertEqual(default_rows[0]["algorithm"], "SHA1")
        self.assertEqual(default_rows[0]["digits"], "6")
        self.assertEqual(default_rows[0]["period"], "30")
        self.assertEqual(default_rows[0]["counter"], "0")
        # Default params still use a bare secret; metadata stays on the row.
        self.assertEqual(default_rows[0]["login_totp"], DEMO_SECRET_B32)

        self.assertEqual(default_rows[1]["issuer"], "GitHub")
        self.assertEqual(default_rows[1]["algorithm"], "SHA256")
        self.assertEqual(default_rows[1]["digits"], "8")
        self.assertEqual(default_rows[1]["period"], "60")
        self.assertIn("algorithm=SHA256", default_rows[1]["login_totp"])
        self.assertIn("digits=8", default_rows[1]["login_totp"])
        self.assertIn("period=60", default_rows[1]["login_totp"])

        for row in custom_rows:
            self.assertEqual(row["folder"], "Shared")
        for row in blank_rows:
            self.assertEqual(row["folder"], "")

    def test_write_bitwarden_csv_uses_folder_argument(self):
        otp = {
            "secret": b"\x66" * 10,
            "name": "hotp-csv",
            "issuer": "OldSys",
            "algorithm": 1,
            "digits": 1,
            "type": 1,
            "counter": 7,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hotp.csv")
            m.write_bitwarden_csv([otp], path, folder="Legacy")
            with open(path, newline="", encoding="utf-8") as f:
                row = next(csv.DictReader(f))
        self.assertEqual(row["folder"], "Legacy")
        self.assertEqual(row["issuer"], "OldSys")
        self.assertEqual(row["algorithm"], "SHA1")
        self.assertEqual(row["digits"], "6")
        self.assertEqual(row["counter"], "7")
        self.assertTrue(row["login_totp"].startswith("otpauth://hotp/"))


class TestCliFolderFlag(unittest.TestCase):
    def test_cli_bw_folder_override_on_otpauth_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bw.csv")
            rc = m.main(
                [
                    str(FIXTURES / "otpauth_uris.txt"),
                    "-o",
                    out,
                    "-q",
                    "--bw-folder",
                    "Custom Vault",
                ]
            )
            self.assertEqual(rc, 0)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertGreaterEqual(len(rows), 2)
        by_issuer = {row["issuer"]: row for row in rows}
        self.assertEqual(by_issuer["Example"]["folder"], "Custom Vault")
        self.assertEqual(by_issuer["Example"]["algorithm"], "SHA1")
        self.assertEqual(by_issuer["Example"]["digits"], "6")
        self.assertEqual(by_issuer["Example"]["period"], "30")
        self.assertEqual(by_issuer["GitHub"]["algorithm"], "SHA256")
        self.assertEqual(by_issuer["GitHub"]["digits"], "8")
        self.assertEqual(by_issuer["GitHub"]["period"], "60")
        self.assertEqual(by_issuer["GitHub"]["counter"], "0")

    def test_cli_blank_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bw.csv")
            rc = m.main(
                [
                    str(FIXTURES / "aegis_export.json"),
                    "-o",
                    out,
                    "-q",
                    "--bw-folder",
                    "",
                ]
            )
            self.assertEqual(rc, 0)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["folder"], "")
            for column in METADATA_COLUMNS:
                self.assertIn(column, row)

    def test_cli_source_folder_when_flag_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bw.csv")
            rc = m.main([str(FIXTURES / "authy_export.json"), "-o", out, "-q"])
            self.assertEqual(rc, 0)
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["folder"], "Authy Migration")

    @mock.patch("ga_to_bitwarden.live_scan")
    def test_cli_live_scan_folder_override(self, mock_live):
        mock_live.return_value = [
            {
                "secret": b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n",
                "name": "live-user@example.com",
                "issuer": "LiveService",
                "algorithm": 3,  # SHA512
                "digits": 2,  # 8
                "type": 2,
                "period": 45,
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            orig = os.getcwd()
            try:
                os.chdir(tmp)
                rc = m.main(["--live", "-q", "--bw-folder", "Webcam Imports"])
                self.assertEqual(rc, 0)
                with open("bitwarden_import.csv", newline="", encoding="utf-8") as f:
                    rows = list(csv.DictReader(f))
            finally:
                os.chdir(orig)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["folder"], "Webcam Imports")
        self.assertEqual(rows[0]["issuer"], "LiveService")
        self.assertEqual(rows[0]["algorithm"], "SHA512")
        self.assertEqual(rows[0]["digits"], "8")
        self.assertEqual(rows[0]["period"], "45")
        self.assertEqual(rows[0]["counter"], "0")
        self.assertIn("algorithm=SHA512", rows[0]["login_totp"])
        self.assertIn("period=45", rows[0]["login_totp"])


if __name__ == "__main__":
    unittest.main()
