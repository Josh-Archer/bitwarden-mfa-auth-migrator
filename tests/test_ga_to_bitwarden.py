"""Unit tests for parse/export paths and distinct soft-fail errors."""

from __future__ import annotations

import base64
import csv
import io
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
from tests.protobuf_fixtures import (  # noqa: E402
    make_migration_payload,
    make_otp_parameters,
    migration_url_from_payload,
    sample_accounts_payload,
)


class TestParseMigrationPayload(unittest.TestCase):
    def test_parses_sample_accounts(self):
        payload, expected = sample_accounts_payload()
        got = m.parse_migration_payload(payload)
        self.assertEqual(len(got), 2)
        for actual, exp in zip(got, expected):
            self.assertEqual(actual.get("secret"), exp["secret"])
            self.assertEqual(actual.get("name"), exp["name"])
            self.assertEqual(actual.get("issuer"), exp["issuer"])

    def test_empty_bytes_raises_empty_payload(self):
        with self.assertRaises(m.EmptyPayloadError) as ctx:
            m.parse_migration_payload(b"")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_no_otp_fields_raises_empty_payload(self):
        # version-only payload (field 2 varint), no otp_parameters
        from tests.protobuf_fixtures import encode_varint_field

        payload = encode_varint_field(2, 1)
        with self.assertRaises(m.EmptyPayloadError) as ctx:
            m.parse_migration_payload(payload)
        self.assertIn("no OTP", str(ctx.exception))


class TestDecodeMigrationUrl(unittest.TestCase):
    def test_valid_url(self):
        payload, _ = sample_accounts_payload()
        url = migration_url_from_payload(payload)
        decoded = m.decode_migration_url(url, strict=True)
        self.assertEqual(decoded, payload)

    def test_missing_data_param_strict(self):
        with self.assertRaises(m.EmptyPayloadError) as ctx:
            m.decode_migration_url("otpauth-migration://offline", strict=True)
        self.assertIn("data", str(ctx.exception).lower())

    def test_wrong_scheme_strict(self):
        with self.assertRaises(m.EmptyPayloadError) as ctx:
            m.decode_migration_url("otpauth://totp/Example", strict=True)
        self.assertIn("scheme", str(ctx.exception).lower())

    def test_soft_fail_returns_none(self):
        self.assertIsNone(
            m.decode_migration_url("otpauth://totp/Example", strict=False)
        )

    def test_empty_base64_payload_strict(self):
        # data= with empty base64-decodable content
        with self.assertRaises(m.EmptyPayloadError):
            m.decode_migration_url("otpauth-migration://offline?data=", strict=True)


class TestExportAccountsToCsv(unittest.TestCase):
    def test_export_writes_bitwarden_rows(self):
        payload, expected = sample_accounts_payload()
        accounts = m.parse_migration_payload(payload)

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.csv")
            count = m.export_accounts_to_csv(accounts, out)
            self.assertEqual(count, 2)

            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))

            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["type"], "login")
            self.assertEqual(rows[0]["folder"], "Google Authenticator Migration")
            self.assertEqual(rows[0]["name"], "GitHub: user@example.com")
            self.assertEqual(rows[0]["login_username"], "user@example.com")
            # TOTP is base32 of secret without padding
            secret_b32 = base64.b32encode(expected[0]["secret"]).decode().strip("=")
            self.assertEqual(rows[0]["login_totp"], secret_b32)
            self.assertEqual(rows[1]["name"], "Example Corp: alice")

    def test_export_empty_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "empty.csv")
            with self.assertRaises(m.EmptyPayloadError) as ctx:
                m.export_accounts_to_csv([], out)
            self.assertIn("No accounts to export", str(ctx.exception))
            self.assertFalse(os.path.exists(out))

    def test_otp_to_csv_row_without_issuer(self):
        row = m.otp_to_csv_row({"secret": b"abc", "name": "only-name"})
        self.assertEqual(row["name"], "only-name")
        self.assertEqual(row["login_username"], "only-name")


class TestDistinctErrorClassification(unittest.TestCase):
    def test_missing_deps_when_no_qr_and_no_zbar(self):
        with mock.patch.object(m, "HAS_ZBAR", False):
            err = m.classify_empty_export(
                has_images=True,
                unreadable_images=0,
                urls_seen=0,
                decode_failures=0,
            )
        self.assertIsInstance(err, m.MissingDependencyError)
        self.assertIn("pyzbar", str(err).lower())

    def test_unreadable_qr_when_zbar_present_but_no_urls(self):
        with mock.patch.object(m, "HAS_ZBAR", True):
            err = m.classify_empty_export(
                has_images=True,
                unreadable_images=0,
                urls_seen=0,
                decode_failures=0,
            )
        self.assertIsInstance(err, m.UnreadableQRError)
        self.assertNotIsInstance(err, m.MissingDependencyError)

    def test_empty_payload_when_urls_but_decode_failed(self):
        err = m.classify_empty_export(
            has_images=True,
            unreadable_images=0,
            urls_seen=2,
            decode_failures=2,
        )
        self.assertIsInstance(err, m.EmptyPayloadError)
        self.assertIn("payload", str(err).lower())

    def test_unreadable_images(self):
        err = m.classify_empty_export(
            has_images=True,
            unreadable_images=3,
            urls_seen=0,
            decode_failures=0,
        )
        self.assertIsInstance(err, m.UnreadableQRError)
        self.assertIn("read image", str(err).lower())

    def test_no_images(self):
        err = m.classify_empty_export(
            has_images=False,
            unreadable_images=0,
            urls_seen=0,
            decode_failures=0,
        )
        self.assertIsInstance(err, m.UnreadableQRError)

    def test_check_qr_dependencies_require_zbar(self):
        with mock.patch.object(m, "HAS_ZBAR", False):
            with self.assertRaises(m.MissingDependencyError) as ctx:
                m.check_qr_dependencies(require_zbar=True)
            self.assertIn("pyzbar", str(ctx.exception).lower())

        with mock.patch.object(m, "HAS_ZBAR", True):
            info = m.check_qr_dependencies(require_zbar=True)
            self.assertTrue(info["has_zbar"])


class TestEndToEndParseExportFixture(unittest.TestCase):
    """Parse fixture URL -> export CSV without touching QR libraries."""

    def test_url_to_csv_roundtrip(self):
        payload, expected = sample_accounts_payload()
        url = migration_url_from_payload(payload)
        raw = m.decode_migration_url(url)
        accounts = m.parse_migration_payload(raw)

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bitwarden_import.csv")
            m.export_accounts_to_csv(accounts, out)
            with open(out, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("login_totp", content)
            self.assertIn(expected[0]["name"], content)
            self.assertIn(expected[1]["issuer"], content)


class TestErrorHierarchy(unittest.TestCase):
    def test_all_errors_are_migration_errors(self):
        for exc in (
            m.MissingDependencyError("x"),
            m.UnreadableQRError("x"),
            m.EmptyPayloadError("x"),
        ):
            self.assertIsInstance(exc, m.MigrationError)


if __name__ == "__main__":
    unittest.main()
