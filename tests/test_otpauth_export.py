"""Tests for preserving algorithm, digits, and type in Bitwarden export (#3)."""
import base64
import csv
import os
import sys
import tempfile
import unittest
import urllib.parse

# Allow importing the module from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ga_to_bitwarden import (
    ALGORITHM_MAP,
    DIGITS_MAP,
    build_otpauth_uri,
    parse_otp_parameters,
    parse_migration_payload,
    secret_to_base32,
    write_bitwarden_csv,
)


def encode_varint(value):
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        out.append(bits | (0x80 if value else 0))
        if not value:
            break
    return bytes(out)


def encode_key(field_number, wire_type):
    return encode_varint((field_number << 3) | wire_type)


def encode_bytes_field(field_number, data):
    return encode_key(field_number, 2) + encode_varint(len(data)) + data


def encode_string_field(field_number, text):
    return encode_bytes_field(field_number, text.encode("utf-8"))


def encode_varint_field(field_number, value):
    return encode_key(field_number, 0) + encode_varint(value)


def build_otp_parameters_bytes(
    secret=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a",
    name="user@example.com",
    issuer="Example",
    algorithm=1,
    digits=1,
    otp_type=2,
    counter=None,
):
    """Build a serialized MigrationPayload.OtpParameters message."""
    parts = [
        encode_bytes_field(1, secret),
        encode_string_field(2, name),
        encode_string_field(3, issuer),
        encode_varint_field(4, algorithm),
        encode_varint_field(5, digits),
        encode_varint_field(6, otp_type),
    ]
    if counter is not None:
        parts.append(encode_varint_field(7, counter))
    return b"".join(parts)


def build_migration_payload(otp_messages):
    parts = [encode_bytes_field(1, msg) for msg in otp_messages]
    return b"".join(parts)


class TestEnumMaps(unittest.TestCase):
    def test_algorithm_map_covers_ga_enums(self):
        self.assertEqual(ALGORITHM_MAP[1], "SHA1")
        self.assertEqual(ALGORITHM_MAP[2], "SHA256")
        self.assertEqual(ALGORITHM_MAP[3], "SHA512")
        self.assertEqual(ALGORITHM_MAP[4], "MD5")
        self.assertEqual(ALGORITHM_MAP[0], "SHA1")

    def test_digits_map_covers_ga_enums(self):
        self.assertEqual(DIGITS_MAP[1], 6)
        self.assertEqual(DIGITS_MAP[2], 8)
        self.assertEqual(DIGITS_MAP[0], 6)


class TestBuildOtpauthUri(unittest.TestCase):
    def test_default_totp_sha1_six_digits(self):
        secret = b"EXAMPLE_NOT_A_SECRET"
        otp = {
            "secret": secret,
            "name": "alice@example.com",
            "issuer": "GitHub",
            "algorithm": 1,  # SHA1
            "digits": 1,  # 6
            "type": 2,  # TOTP
        }
        uri = build_otpauth_uri(otp)
        parsed = urllib.parse.urlparse(uri)
        self.assertEqual(parsed.scheme, "otpauth")
        self.assertEqual(parsed.netloc, "totp")
        qs = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(qs["secret"][0], secret_to_base32(secret))
        self.assertEqual(qs["algorithm"][0], "SHA1")
        self.assertEqual(qs["digits"][0], "6")
        self.assertEqual(qs["period"][0], "30")
        self.assertEqual(qs["issuer"][0], "GitHub")
        self.assertIn("GitHub", urllib.parse.unquote(parsed.path))

    def test_sha256_eight_digits_preserved(self):
        otp = {
            "secret": b"\x11" * 20,
            "name": "bob",
            "issuer": "SecureApp",
            "algorithm": 2,  # SHA256
            "digits": 2,  # 8
            "type": 2,  # TOTP
        }
        uri = build_otpauth_uri(otp)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)
        self.assertEqual(qs["algorithm"][0], "SHA256")
        self.assertEqual(qs["digits"][0], "8")
        self.assertTrue(uri.startswith("otpauth://totp/"))

    def test_sha512_preserved(self):
        otp = {
            "secret": b"\x22" * 20,
            "name": "carol",
            "issuer": "Bank",
            "algorithm": 3,
            "digits": 1,
            "type": 2,
        }
        uri = build_otpauth_uri(otp)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)
        self.assertEqual(qs["algorithm"][0], "SHA512")

    def test_hotp_with_counter(self):
        otp = {
            "secret": b"\x33" * 10,
            "name": "hotp-user",
            "issuer": "Legacy",
            "algorithm": 1,
            "digits": 2,  # 8
            "type": 1,  # HOTP
            "counter": 42,
        }
        uri = build_otpauth_uri(otp)
        parsed = urllib.parse.urlparse(uri)
        self.assertEqual(parsed.netloc, "hotp")
        qs = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(qs["counter"][0], "42")
        self.assertEqual(qs["digits"][0], "8")
        self.assertNotIn("period", qs)

    def test_unspecified_enums_use_defaults(self):
        otp = {
            "secret": b"\x44" * 10,
            "name": "default-user",
            "issuer": "",
            "algorithm": 0,
            "digits": 0,
            "type": 0,
        }
        uri = build_otpauth_uri(otp)
        parsed = urllib.parse.urlparse(uri)
        self.assertEqual(parsed.netloc, "totp")
        qs = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(qs["algorithm"][0], "SHA1")
        self.assertEqual(qs["digits"][0], "6")
        self.assertNotIn("issuer", qs)


class TestParsePreservesParams(unittest.TestCase):
    def test_parse_otp_parameters_non_default(self):
        raw = build_otp_parameters_bytes(
            secret=b"\xaa\xbb\xcc",
            name="parsed@test",
            issuer="IssuerX",
            algorithm=2,  # SHA256
            digits=2,  # 8
            otp_type=2,  # TOTP
        )
        params = parse_otp_parameters(raw)
        self.assertEqual(params["secret"], b"\xaa\xbb\xcc")
        self.assertEqual(params["name"], "parsed@test")
        self.assertEqual(params["issuer"], "IssuerX")
        self.assertEqual(params["algorithm"], 2)
        self.assertEqual(params["digits"], 2)
        self.assertEqual(params["type"], 2)

    def test_parse_hotp_counter(self):
        raw = build_otp_parameters_bytes(
            algorithm=1,
            digits=1,
            otp_type=1,
            counter=99,
        )
        params = parse_otp_parameters(raw)
        self.assertEqual(params["type"], 1)
        self.assertEqual(params["counter"], 99)

    def test_parse_migration_payload_roundtrip_uri(self):
        otp_msg = build_otp_parameters_bytes(
            secret=b"\x01\x02\x03\x04\x05",
            name="roundtrip",
            issuer="RT",
            algorithm=3,  # SHA512
            digits=2,  # 8
            otp_type=2,
        )
        payload = build_migration_payload([otp_msg])
        results = parse_migration_payload(payload)
        self.assertEqual(len(results), 1)
        uri = build_otpauth_uri(results[0])
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)
        self.assertEqual(qs["algorithm"][0], "SHA512")
        self.assertEqual(qs["digits"][0], "8")
        self.assertEqual(qs["secret"][0], secret_to_base32(b"\x01\x02\x03\x04\x05"))


class TestCsvExport(unittest.TestCase):
    def test_csv_login_totp_is_otpauth_with_params(self):
        results = [
            {
                "secret": b"\x55" * 16,
                "name": "csv-user",
                "issuer": "CSVApp",
                "algorithm": 2,
                "digits": 2,
                "type": 2,
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            write_bitwarden_csv(results, path)
            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 1)
        totp = rows[0]["login_totp"]
        self.assertTrue(totp.startswith("otpauth://totp/"))
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(totp).query)
        self.assertEqual(qs["algorithm"][0], "SHA256")
        self.assertEqual(qs["digits"][0], "8")
        self.assertEqual(rows[0]["name"], "CSVApp: csv-user")

    def test_csv_hotp_row(self):
        results = [
            {
                "secret": b"\x66" * 10,
                "name": "hotp-csv",
                "issuer": "OldSys",
                "algorithm": 1,
                "digits": 1,
                "type": 1,
                "counter": 7,
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hotp.csv")
            write_bitwarden_csv(results, path)
            with open(path, newline="", encoding="utf-8") as f:
                row = next(csv.DictReader(f))
        self.assertTrue(row["login_totp"].startswith("otpauth://hotp/"))
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(row["login_totp"]).query)
        self.assertEqual(qs["counter"][0], "7")


if __name__ == "__main__":
    unittest.main()
