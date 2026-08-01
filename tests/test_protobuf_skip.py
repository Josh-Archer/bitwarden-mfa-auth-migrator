"""
Tests for hardened protobuf skip / multi-batch migration payload parsing.

Covers acceptance criteria for issue #4:
- Harden skip logic for all wire types
- Fixtures for multi-batch payloads
- Clear error when parse fails mid-payload
"""

from __future__ import annotations

import base64
import os
import sys
import unittest
import urllib.parse

# Allow importing ga_to_bitwarden from repo root
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ga_to_bitwarden import (  # noqa: E402
    ProtobufParseError,
    decode_migration_url,
    parse_migration_payload,
    parse_otp_parameters,
    read_varint,
    skip_field,
)
from tests.proto_helpers import (  # noqa: E402
    encode_fixed32_field,
    encode_fixed64_field,
    encode_key,
    encode_len_delimited,
    encode_migration_payload,
    encode_otp_parameters,
    encode_varint,
    encode_varint_field,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _write_fixture(name: str, data: bytes) -> str:
    path = os.path.join(FIXTURES, name)
    os.makedirs(FIXTURES, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def _migration_url(payload: bytes) -> str:
    b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"otpauth-migration://offline?data={urllib.parse.quote(b64)}"


class TestSkipField(unittest.TestCase):
    def test_skip_varint(self):
        data = encode_varint(300) + b"\x00"
        pos = skip_field(data, 0, 0)
        self.assertEqual(pos, len(encode_varint(300)))

    def test_skip_fixed64(self):
        data = b"\x00" * 8 + b"tail"
        self.assertEqual(skip_field(data, 0, 1), 8)

    def test_skip_length_delimited(self):
        payload = b"hello"
        data = encode_varint(len(payload)) + payload + b"X"
        self.assertEqual(skip_field(data, 0, 2), 1 + len(payload))

    def test_skip_fixed32(self):
        data = b"\x01\x02\x03\x04" + b"rest"
        self.assertEqual(skip_field(data, 0, 5), 4)

    def test_skip_group_raises(self):
        with self.assertRaises(ProtobufParseError) as ctx:
            skip_field(b"\x00", 0, 3)
        self.assertIn("group", str(ctx.exception).lower())

    def test_skip_unknown_wire_type_raises(self):
        with self.assertRaises(ProtobufParseError) as ctx:
            skip_field(b"\x00", 0, 6)
        self.assertIn("Unknown protobuf wire type", str(ctx.exception))

    def test_skip_truncated_fixed64_raises(self):
        with self.assertRaises(ProtobufParseError) as ctx:
            skip_field(b"\x00\x01", 0, 1)
        self.assertIn("Truncated 64-bit", str(ctx.exception))

    def test_skip_truncated_length_delimited_raises(self):
        data = encode_varint(10) + b"short"
        with self.assertRaises(ProtobufParseError) as ctx:
            skip_field(data, 0, 2)
        self.assertIn("Truncated length-delimited", str(ctx.exception))


class TestReadVarint(unittest.TestCase):
    def test_truncated_varint_clear_error(self):
        # Continuation bit set with no following byte
        with self.assertRaises(ProtobufParseError) as ctx:
            read_varint(b"\x80", 0)
        self.assertIn("Truncated varint", str(ctx.exception))


class TestMultiBatchFixtures(unittest.TestCase):
    """Build, persist, and parse multi-batch GA export payloads."""

    @classmethod
    def setUpClass(cls):
        secret_a = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
        secret_b = b"\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
        secret_c = b"\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e"
        batch_id = 424242

        otp_a = encode_otp_parameters(secret_a, "alice@example.com", "GitHub")
        otp_b = encode_otp_parameters(secret_b, "bob@example.com", "Google")
        otp_c = encode_otp_parameters(secret_c, "carol@example.com", "AWS")

        # Three QR batches of a single export (batch_size=3)
        cls.batch0 = encode_migration_payload(
            [otp_a], version=1, batch_size=3, batch_index=0, batch_id=batch_id
        )
        cls.batch1 = encode_migration_payload(
            [otp_b], version=1, batch_size=3, batch_index=1, batch_id=batch_id
        )
        cls.batch2 = encode_migration_payload(
            [otp_c], version=1, batch_size=3, batch_index=2, batch_id=batch_id
        )

        # Single payload with multiple otp_parameters + batch meta
        cls.multi_otp = encode_migration_payload(
            [otp_a, otp_b],
            version=1,
            batch_size=2,
            batch_index=0,
            batch_id=batch_id,
        )

        # Payload with unknown fixed32 / fixed64 fields interspersed so skip
        # logic must advance past them without desyncing later otp entries.
        unknown_fixed = (
            encode_fixed64_field(99, 0x1122334455667788)
            + encode_fixed32_field(100, 0xAABBCCDD)
        )
        otp_with_unknown = encode_otp_parameters(
            secret_a,
            "dave@example.com",
            "UnknownWire",
            extra=encode_fixed32_field(50, 0xDEADBEEF),
        )
        cls.with_unknown_wire = encode_migration_payload(
            [otp_with_unknown, otp_b],
            version=1,
            batch_size=1,
            batch_index=0,
            batch_id=1,
            trailing_unknown=unknown_fixed,
        )

        # Truncated mid-payload: claims a long length-delimited field then ends
        cls.truncated = (
            encode_len_delimited(1, otp_a)
            + encode_key(1, 2)
            + encode_varint(50)  # claims 50 bytes
            + b"\x01\x02"  # only 2 present
        )

        _write_fixture("batch_0.bin", cls.batch0)
        _write_fixture("batch_1.bin", cls.batch1)
        _write_fixture("batch_2.bin", cls.batch2)
        _write_fixture("multi_otp.bin", cls.multi_otp)
        _write_fixture("unknown_wire_types.bin", cls.with_unknown_wire)
        _write_fixture("truncated_mid_payload.bin", cls.truncated)

        # URL-wrapped multi-batch fixtures (as QR codes would encode them)
        urls = "\n".join(
            _migration_url(p) for p in (cls.batch0, cls.batch1, cls.batch2)
        )
        with open(os.path.join(FIXTURES, "multi_batch_urls.txt"), "w", encoding="utf-8") as f:
            f.write(urls + "\n")

    def test_each_batch_fixture_parses_one_account(self):
        for idx, raw in enumerate((self.batch0, self.batch1, self.batch2)):
            with self.subTest(batch_index=idx):
                path = os.path.join(FIXTURES, f"batch_{idx}.bin")
                with open(path, "rb") as f:
                    data = f.read()
                params = parse_migration_payload(data)
                self.assertEqual(len(params), 1)
                self.assertEqual(params[0]["_batch"]["batch_index"], idx)
                self.assertEqual(params[0]["_batch"]["batch_size"], 3)
                self.assertEqual(params[0]["_batch"]["batch_id"], 424242)

    def test_multi_otp_fixture(self):
        with open(os.path.join(FIXTURES, "multi_otp.bin"), "rb") as f:
            data = f.read()
        params = parse_migration_payload(data)
        self.assertEqual(len(params), 2)
        names = {p["name"] for p in params}
        self.assertEqual(names, {"alice@example.com", "bob@example.com"})
        self.assertEqual(params[0]["_batch"]["batch_size"], 2)

    def test_unknown_wire_types_do_not_desync(self):
        """fixed32/fixed64 unknown fields must be skipped so later accounts parse."""
        with open(os.path.join(FIXTURES, "unknown_wire_types.bin"), "rb") as f:
            data = f.read()
        params = parse_migration_payload(data)
        self.assertEqual(len(params), 2)
        self.assertEqual(params[0]["name"], "dave@example.com")
        self.assertEqual(params[0]["issuer"], "UnknownWire")
        self.assertEqual(params[1]["name"], "bob@example.com")
        self.assertIn("secret", params[1])

    def test_truncated_mid_payload_clear_error(self):
        with open(os.path.join(FIXTURES, "truncated_mid_payload.bin"), "rb") as f:
            data = f.read()
        with self.assertRaises(ProtobufParseError) as ctx:
            parse_migration_payload(data)
        msg = str(ctx.exception)
        self.assertIn("mid-payload", msg.lower())
        # Should mention truncation / length, not a bare IndexError
        self.assertTrue(
            "truncated" in msg.lower() or "remaining" in msg.lower(),
            msg,
        )

    def test_combine_all_batches_via_urls(self):
        path = os.path.join(FIXTURES, "multi_batch_urls.txt")
        with open(path, encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        self.assertEqual(len(urls), 3)

        combined = []
        for url in urls:
            raw = decode_migration_url(url)
            self.assertIsNotNone(raw)
            combined.extend(parse_migration_payload(raw))

        self.assertEqual(len(combined), 3)
        issuers = [p["issuer"] for p in combined]
        self.assertEqual(issuers, ["GitHub", "Google", "AWS"])
        # Same batch_id across all QR slices
        ids = {p["_batch"]["batch_id"] for p in combined}
        self.assertEqual(ids, {424242})

    def test_old_bug_unknown_wire_in_otp_would_loop_or_desync(self):
        """
        Regression: previously parse_otp_parameters ignored non-0/2 wire types
        with `pass`, leaving pos unchanged → infinite loop or mis-parse.
        """
        # Otp body with a fixed64 unknown field between name and issuer
        secret = b"\xaa" * 10
        body = (
            encode_len_delimited(1, secret)
            + encode_len_delimited(2, b"user")
            + encode_fixed64_field(40, 0)
            + encode_len_delimited(3, b"Issuer")
            + encode_varint_field(6, 2)
        )
        params = parse_otp_parameters(body)
        self.assertEqual(params["name"], "user")
        self.assertEqual(params["issuer"], "Issuer")
        self.assertEqual(params["secret"], secret)


class TestMigrationPayloadErrors(unittest.TestCase):
    def test_empty_payload(self):
        self.assertEqual(parse_migration_payload(b""), [])

    def test_garbage_tag_mid_stream_after_valid_account(self):
        otp = encode_otp_parameters(b"\x01" * 8, "x", "Y")
        # Valid account then illegal wire type 7 on field 9
        data = encode_len_delimited(1, otp) + encode_key(9, 7)
        with self.assertRaises(ProtobufParseError) as ctx:
            parse_migration_payload(data)
        self.assertIn("mid-payload", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
