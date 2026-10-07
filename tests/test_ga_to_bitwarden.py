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

import numpy as np

# Ensure project root is importable when running pytest from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import ga_to_bitwarden as m  # noqa: E402
from tests.protobuf_fixtures import (  # noqa: E402
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
            # TOTP is full importable otpauth:// URI
            secret_b32 = base64.b32encode(
                expected[0]["secret"]
            ).decode().strip("=")
            self.assertEqual(
                rows[0]["login_totp"], m.build_otpauth_uri(accounts[0])
            )
            self.assertTrue(rows[0]["login_totp"].startswith("otpauth://totp/"))
            self.assertIn(f"secret={secret_b32}", rows[0]["login_totp"])
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
        self.assertTrue(row["login_totp"].startswith("otpauth://totp/only-name?"))
        self.assertIn("secret=MFRGG", row["login_totp"])


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


class TestLiveScan(unittest.TestCase):
    @mock.patch("cv2.VideoCapture")
    def test_live_scan_webcam_unavailable(self, mock_vc):
        mock_cap = mock.MagicMock()
        mock_cap.isOpened.return_value = False
        mock_vc.return_value = mock_cap

        results = m.live_scan()
        self.assertEqual(results, [])

    @mock.patch("cv2.destroyAllWindows")
    @mock.patch("cv2.imshow")
    @mock.patch("cv2.waitKey", side_effect=[0, ord("q")])
    @mock.patch("cv2.VideoCapture")
    @mock.patch("ga_to_bitwarden.get_qr_payloads")
    def test_live_scan_captures_and_deduplicates(
        self, mock_qr, mock_vc, mock_key, mock_show, mock_destroy
    ):
        mock_cap = mock.MagicMock()
        mock_cap.isOpened.return_value = True
        fake_frame = np.zeros((50, 50, 3), dtype=np.uint8)
        mock_cap.read.return_value = (True, fake_frame)
        mock_vc.return_value = mock_cap

        payload, _ = sample_accounts_payload()
        mig_url = migration_url_from_payload(payload)
        otpauth_uri = (
            "otpauth://totp/Example:user"
            "?secret=EXAMPLENOTREALAA&issuer=Example"
        )

        # Frame 1: mig_url and otpauth_uri. Frame 2: duplicate mig_url.
        mock_qr.side_effect = [[mig_url, otpauth_uri], [mig_url]]

        results = m.live_scan(quiet=False)
        self.assertEqual(len(results), 3)
        mock_cap.release.assert_called_once()
        mock_destroy.assert_called_once()

    @mock.patch("cv2.destroyAllWindows")
    @mock.patch("cv2.imshow")
    @mock.patch("cv2.waitKey", side_effect=[ord("q")])
    @mock.patch("cv2.VideoCapture")
    @mock.patch("ga_to_bitwarden.get_qr_payloads")
    def test_live_scan_handles_invalid_payloads_without_error(
        self, mock_qr, mock_vc, mock_key, mock_show, mock_destroy
    ):
        mock_cap = mock.MagicMock()
        mock_cap.isOpened.return_value = True
        fake_frame = np.zeros((50, 50, 3), dtype=np.uint8)
        mock_cap.read.return_value = (True, fake_frame)
        mock_vc.return_value = mock_cap

        mock_qr.return_value = [
            "otpauth-migration://offline?data=",
            "https://example.com",
        ]
        results = m.live_scan(quiet=True)
        self.assertEqual(results, [])

    @mock.patch("cv2.destroyAllWindows")
    @mock.patch("cv2.imshow")
    @mock.patch("cv2.waitKey", side_effect=[ord("q")])
    @mock.patch("cv2.VideoCapture")
    @mock.patch("ga_to_bitwarden.get_qr_payloads")
    def test_live_scan_quiet_suppresses_captured_output(
        self, mock_qr, mock_vc, mock_key, mock_show, mock_destroy
    ):
        mock_cap = mock.MagicMock()
        mock_cap.isOpened.return_value = True
        fake_frame = np.zeros((50, 50, 3), dtype=np.uint8)
        mock_cap.read.return_value = (True, fake_frame)
        mock_vc.return_value = mock_cap

        otpauth_uri = (
            "otpauth://totp/Example:user"
            "?secret=EXAMPLENOTREALAA&issuer=Example"
        )
        mock_qr.return_value = [otpauth_uri]

        with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            results = m.live_scan(quiet=True)
            output = mock_out.getvalue()

        self.assertEqual(len(results), 1)
        self.assertNotIn("[Captured]", output)

    @mock.patch("cv2.destroyAllWindows")
    @mock.patch("cv2.imshow")
    @mock.patch("cv2.waitKey", side_effect=[ord("q")])
    @mock.patch("cv2.VideoCapture")
    @mock.patch("ga_to_bitwarden.get_qr_payloads")
    def test_live_scan_does_not_leak_secret_on_invalid_otpauth_uri(
        self, mock_qr, mock_vc, mock_key, mock_show, mock_destroy
    ):
        mock_cap = mock.MagicMock()
        mock_cap.isOpened.return_value = True
        fake_frame = np.zeros((50, 50, 3), dtype=np.uint8)
        mock_cap.read.return_value = (True, fake_frame)
        mock_vc.return_value = mock_cap

        placeholder_secret = "EXAMPLENOTREALAA"
        invalid_uri = (
            f"otpauth://invalid/Example:user?secret={placeholder_secret}"
        )
        mock_qr.return_value = [invalid_uri]

        with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            with mock.patch(
                "sys.stderr", new_callable=io.StringIO
            ) as mock_err:
                results = m.live_scan(quiet=False)
                stdout = mock_out.getvalue()
                stderr = mock_err.getvalue()

        self.assertEqual(results, [])
        self.assertNotIn(placeholder_secret, stdout)
        self.assertNotIn(placeholder_secret, stderr)
        self.assertIn("Empty/invalid QR payload; skipping", stdout)

    @mock.patch("cv2.destroyAllWindows")
    @mock.patch("cv2.imshow")
    @mock.patch("cv2.waitKey", side_effect=[ord("q")])
    @mock.patch("cv2.VideoCapture")
    @mock.patch("ga_to_bitwarden.get_qr_payloads")
    def test_live_scan_does_not_leak_secret_on_corrupt_migration_payload(
        self, mock_qr, mock_vc, mock_key, mock_show, mock_destroy
    ):
        mock_cap = mock.MagicMock()
        mock_cap.isOpened.return_value = True
        fake_frame = np.zeros((50, 50, 3), dtype=np.uint8)
        mock_cap.read.return_value = (True, fake_frame)
        mock_vc.return_value = mock_cap

        placeholder_secret = "EXAMPLENOTREALAA"
        corrupt_uri = (
            "otpauth-migration://offline?data=corrupted"
            f"&secret={placeholder_secret}"
        )
        mock_qr.return_value = [corrupt_uri]

        with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            with mock.patch(
                "sys.stderr", new_callable=io.StringIO
            ) as mock_err:
                results = m.live_scan(quiet=False)
                stdout = mock_out.getvalue()
                stderr = mock_err.getvalue()

        self.assertEqual(results, [])
        self.assertNotIn(placeholder_secret, stdout)
        self.assertNotIn(placeholder_secret, stderr)
        self.assertIn("Empty/invalid QR payload; skipping", stdout)


class TestNonLivePathsMalformedPayload(unittest.TestCase):
    def test_accounts_from_qr_payloads_raises_on_empty_migration_payload(self):
        with self.assertRaises(m.EmptyPayloadError):
            m.accounts_from_qr_payloads(["otpauth-migration://offline?data="])

    def test_accounts_from_qr_payloads_raises_on_corrupt_protobuf(self):
        with self.assertRaises((m.EmptyPayloadError, m.ProtobufParseError)):
            m.accounts_from_qr_payloads(
                ["otpauth-migration://offline?data=AQIDBA=="]
            )

    def test_parse_otpauth_text_raises_on_malformed_migration_payload(self):
        with self.assertRaises(m.EmptyPayloadError):
            m.parse_otpauth_text("otpauth-migration://offline?data=")

    @mock.patch("ga_to_bitwarden.get_qr_payloads")
    @mock.patch("cv2.imread")
    def test_load_accounts_from_image_raises_on_malformed_migration(
        self, mock_imread, mock_qr
    ):
        mock_imread.return_value = np.zeros((50, 50, 3), dtype=np.uint8)
        mock_qr.return_value = ["otpauth-migration://offline?data="]
        with self.assertRaises(m.EmptyPayloadError):
            m.load_accounts_from_image("dummy_screenshot.png")

    @mock.patch("ga_to_bitwarden.get_qr_payloads")
    @mock.patch("cv2.imread")
    def test_load_accounts_from_file_qr_raises_on_malformed_migration(
        self, mock_imread, mock_qr
    ):
        mock_imread.return_value = np.zeros((50, 50, 3), dtype=np.uint8)
        mock_qr.return_value = ["otpauth-migration://offline?data="]
        with self.assertRaises(m.EmptyPayloadError):
            m.load_accounts_from_file("dummy.png", fmt="qr")

    def test_load_accounts_from_file_text_raises_on_malformed_migration(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False
        ) as f:
            f.write("otpauth-migration://offline?data=\n")
            f.flush()
            temp_path = f.name
        try:
            with self.assertRaises(m.EmptyPayloadError):
                m.load_accounts_from_file(temp_path, fmt="otpauth")
        finally:
            os.unlink(temp_path)


class TestCliEndToEndFixtureDefaultOutput(unittest.TestCase):
    def test_main_fixture_no_output_in_temp_cwd(self):
        fixture_path = ROOT / "tests" / "fixtures" / "otpauth_uris.txt"
        with tempfile.TemporaryDirectory() as td:
            orig_cwd = os.getcwd()
            try:
                os.chdir(td)
                rc = m.main([str(fixture_path), "-q"])
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

    def test_main_ga_migration_fixture_no_output_in_temp_cwd(self):
        fixture_path = ROOT / "tests" / "fixtures" / "multi_batch_urls.txt"
        with tempfile.TemporaryDirectory() as td:
            orig_cwd = os.getcwd()
            try:
                os.chdir(td)
                rc = m.main([str(fixture_path), "-q"])
                self.assertEqual(rc, 0)
                csv_path = Path(td) / "bitwarden_import.csv"
                self.assertTrue(csv_path.exists())
                with open(csv_path, newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    self.assertEqual(reader.fieldnames, m.CSV_HEADERS)
                    rows = list(reader)
                self.assertEqual(len(rows), 3)
                for row in rows:
                    totp = row["login_totp"]
                    self.assertTrue(
                        totp.startswith("otpauth://")
                        or bool(base64.b32decode(totp, casefold=True)),
                        f"Expected valid login_totp row, got: {totp}",
                    )
            finally:
                os.chdir(orig_cwd)

    @mock.patch("ga_to_bitwarden.live_scan")
    def test_main_live_scan_successful_decode_writes_csv(self, mock_live):
        mock_live.return_value = [
            {
                "secret": b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n",
                "name": "live-user@example.com",
                "issuer": "LiveService",
                "algorithm": 1,
                "digits": 1,
                "type": 2,
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            orig_cwd = os.getcwd()
            try:
                os.chdir(td)
                rc = m.main(["--live", "-q"])
                self.assertEqual(rc, 0)
                csv_path = Path(td) / "bitwarden_import.csv"
                self.assertTrue(csv_path.exists())
                with open(csv_path, newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    self.assertEqual(reader.fieldnames, m.CSV_HEADERS)
                    rows = list(reader)
                self.assertEqual(len(rows), 1)
                self.assertTrue(
                    rows[0]["login_totp"].startswith("otpauth://totp/")
                )
            finally:
                os.chdir(orig_cwd)


if __name__ == "__main__":
    unittest.main()
