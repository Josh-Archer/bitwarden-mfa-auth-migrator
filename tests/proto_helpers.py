"""Minimal protobuf wire-format helpers for building migration fixtures."""

from __future__ import annotations


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        out.append(bits | (0x80 if value else 0))
        if not value:
            break
    return bytes(out)


def encode_key(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def encode_len_delimited(field_number: int, payload: bytes) -> bytes:
    return encode_key(field_number, 2) + encode_varint(len(payload)) + payload


def encode_varint_field(field_number: int, value: int) -> bytes:
    return encode_key(field_number, 0) + encode_varint(value)


def encode_fixed64_field(field_number: int, value: int = 0) -> bytes:
    return encode_key(field_number, 1) + value.to_bytes(8, "little")


def encode_fixed32_field(field_number: int, value: int = 0) -> bytes:
    return encode_key(field_number, 5) + value.to_bytes(4, "little")


def encode_otp_parameters(
    secret: bytes,
    name: str,
    issuer: str = "",
    algorithm: int = 1,
    digits: int = 1,
    otp_type: int = 2,
    counter: int | None = None,
    extra: bytes = b"",
) -> bytes:
    body = b""
    body += encode_len_delimited(1, secret)
    body += encode_len_delimited(2, name.encode("utf-8"))
    if issuer:
        body += encode_len_delimited(3, issuer.encode("utf-8"))
    body += encode_varint_field(4, algorithm)
    body += encode_varint_field(5, digits)
    body += encode_varint_field(6, otp_type)
    if counter is not None:
        body += encode_varint_field(7, counter)
    body += extra
    return body


def encode_migration_payload(
    otp_params_list: list[bytes],
    version: int = 1,
    batch_size: int | None = None,
    batch_index: int | None = None,
    batch_id: int | None = None,
    trailing_unknown: bytes = b"",
) -> bytes:
    """
    Build a MigrationPayload matching Google Authenticator export layout.

    Multi-batch exports set batch_size / batch_index / batch_id so each QR
    is one slice of a larger export.
    """
    body = b""
    for otp in otp_params_list:
        body += encode_len_delimited(1, otp)
    body += encode_varint_field(2, version)
    if batch_size is not None:
        body += encode_varint_field(3, batch_size)
    if batch_index is not None:
        body += encode_varint_field(4, batch_index)
    if batch_id is not None:
        body += encode_varint_field(5, batch_id)
    body += trailing_unknown
    return body
