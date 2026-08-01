"""Helpers to build synthetic Google Authenticator migration protobuf fixtures.

Uses only synthetic secrets (not real 2FA material).
"""

from __future__ import annotations

import base64
import urllib.parse


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint must be non-negative")
    parts = bytearray()
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts)


def encode_key(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def encode_bytes_field(field_number: int, data: bytes) -> bytes:
    return encode_key(field_number, 2) + encode_varint(len(data)) + data


def encode_string_field(field_number: int, text: str) -> bytes:
    return encode_bytes_field(field_number, text.encode("utf-8"))


def encode_varint_field(field_number: int, value: int) -> bytes:
    return encode_key(field_number, 0) + encode_varint(value)


def make_otp_parameters(
    secret: bytes,
    name: str,
    issuer: str = "",
    *,
    algorithm: int = 1,
    digits: int = 1,
    otp_type: int = 2,
) -> bytes:
    """Build OtpParameters protobuf bytes (field layout used by this project)."""
    body = b""
    body += encode_bytes_field(1, secret)
    body += encode_string_field(2, name)
    if issuer:
        body += encode_string_field(3, issuer)
    body += encode_varint_field(4, algorithm)
    body += encode_varint_field(5, digits)
    body += encode_varint_field(6, otp_type)
    return body


def make_migration_payload(otp_messages: list[bytes], *, version: int = 1) -> bytes:
    """Build MigrationPayload with repeated otp_parameters (field 1) and version (field 2)."""
    body = b""
    for otp in otp_messages:
        body += encode_bytes_field(1, otp)
    body += encode_varint_field(2, version)
    return body


def migration_url_from_payload(payload: bytes) -> str:
    """Wrap protobuf bytes in an otpauth-migration:// URL."""
    data_b64 = base64.b64encode(payload).decode("ascii")
    # URL-safe query value
    return "otpauth-migration://offline?data=" + urllib.parse.quote(data_b64, safe="")


def sample_accounts_payload() -> tuple[bytes, list[dict]]:
    """Return (payload_bytes, expected_account_dicts) for two synthetic accounts."""
    # Clearly synthetic fixture material (not real 2FA seeds).
    secret_a = b"EXAMPLE_NOT_A_SECRET"
    secret_b = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"

    otp_a = make_otp_parameters(secret_a, name="user@example.com", issuer="GitHub")
    otp_b = make_otp_parameters(secret_b, name="alice", issuer="Example Corp")
    payload = make_migration_payload([otp_a, otp_b])

    expected = [
        {"secret": secret_a, "name": "user@example.com", "issuer": "GitHub"},
        {"secret": secret_b, "name": "alice", "issuer": "Example Corp"},
    ]
    return payload, expected
