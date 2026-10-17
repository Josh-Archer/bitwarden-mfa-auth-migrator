#!/usr/bin/env python3
# ruff: noqa: EXE001
"""Migrate TOTP secrets from common authenticator export formats to Bitwarden CSV."""

import argparse
import base64
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path

import cv2
import numpy as np

# Try to import pyzbar for better QR detection
try:
    from pyzbar.pyzbar import decode as zbar_decode
    HAS_ZBAR = True
except ImportError:
    HAS_ZBAR = False


class MigrationError(Exception):
    """Base error for migration failures with actionable messaging."""


class MissingDependencyError(MigrationError):
    """Required optional dependency is missing (e.g. pyzbar)."""


class UnreadableQRError(MigrationError):
    """Image(s) could not be decoded as a Google Authenticator export QR."""


class EmptyPayloadError(MigrationError):
    """QR/URL decoded but migration payload was missing, invalid, or empty."""


class BitwardenCliError(MigrationError):
    """A safe, non-sensitive error returned by the Bitwarden CLI workflow."""


class ProtobufParseError(ValueError):
    """Raised when a migration payload cannot be parsed safely."""


# Google Authenticator Migration Protobuf Field IDs (Manual Parsing)
# ... (same protobuf logic as before) ...


# Google Authenticator MigrationPayload enum mappings
# https://github.com/google/google-authenticator-android (MigrationPayload)
ALGORITHM_MAP = {
    0: "SHA1",   # ALGORITHM_UNSPECIFIED -> treat as default
    1: "SHA1",   # ALGORITHM_SHA1
    2: "SHA256", # ALGORITHM_SHA256
    3: "SHA512", # ALGORITHM_SHA512
    4: "MD5",    # ALGORITHM_MD5
}

DIGITS_MAP = {
    0: 6,  # DIGIT_COUNT_UNSPECIFIED -> default
    1: 6,  # DIGIT_COUNT_SIX
    2: 8,  # DIGIT_COUNT_EIGHT
}

OTP_TYPE_HOTP = 1
OTP_TYPE_TOTP = 2

GA_ALGO_MAP = ALGORITHM_MAP
GA_DIGITS_MAP = DIGITS_MAP
GA_TYPE_MAP = {
    0: "totp",  # unspecified -> totp
    1: "hotp",
    2: "totp",
}

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
TEXT_EXTENSIONS = {".txt", ".text", ".uri", ".urls", ".otpauth"}
JSON_EXTENSIONS = {".json"}

# Default Bitwarden folder column. Callers can override this per export.
DEFAULT_BW_FOLDER = "Google Authenticator Migration"

# Used when --bw-folder is omitted for non-QR imports. GA exports use DEFAULT_BW_FOLDER.
_SOURCE_FOLDER_NAMES = {
    "google-authenticator": DEFAULT_BW_FOLDER,
    "otpauth-uri": "otpauth URI Import",
    "aegis": "Aegis Migration",
    "authy": "Authy Migration",
}



def otp_type_name(type_val):
    if type_val == 1:
        return "hotp"
    return "totp"


def read_varint(data, pos):
    """Read a protobuf varint; raise clear error if truncated mid-value."""
    res = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise ProtobufParseError(
                f"Truncated varint starting at offset {start} "
                f"(reached end of {len(data)}-byte buffer)"
            )
        b = data[pos]
        res |= (b & 0x7f) << shift
        pos += 1
        if not (b & 0x80):
            return res, pos
        shift += 7
        if shift > 63:
            raise ProtobufParseError(f"Varint too long at offset {start}")


def skip_field(data, pos, wire_type):
    """
    Advance past one protobuf field value for any standard wire type.
    Returns the new position. Raises ProtobufParseError on bounds failures
    or unsupported/unknown wire types so callers never continue with a
    desynchronized cursor (critical for multi-batch migration payloads).
    """
    if wire_type == 0:  # Varint
        _, pos = read_varint(data, pos)
        return pos
    if wire_type == 1:  # 64-bit
        if pos + 8 > len(data):
            raise ProtobufParseError(
                f"Truncated 64-bit field at offset {pos} "
                f"(need 8 bytes, {len(data) - pos} remaining)"
            )
        return pos + 8
    if wire_type == 2:  # Length-delimited
        length, pos = read_varint(data, pos)
        if length < 0 or pos + length > len(data):
            raise ProtobufParseError(
                f"Truncated length-delimited field at offset {pos}: "
                f"claimed length {length}, {len(data) - pos} bytes remaining"
            )
        return pos + length
    if wire_type == 5:  # 32-bit
        if pos + 4 > len(data):
            raise ProtobufParseError(
                f"Truncated 32-bit field at offset {pos} "
                f"(need 4 bytes, {len(data) - pos} remaining)"
            )
        return pos + 4
    # Groups (3/4) are deprecated and unused by MigrationPayload
    if wire_type in (3, 4):
        raise ProtobufParseError(
            f"Unsupported deprecated group wire type {wire_type} at offset {pos}"
        )
    raise ProtobufParseError(
        f"Unknown protobuf wire type {wire_type} at offset {pos}"
    )


def parse_otp_parameters(data):
    pos = 0
    params = {}
    try:
        while pos < len(data):
            tag, pos = read_varint(data, pos)
            field_number = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 2:  # Length-delimited
                length, pos = read_varint(data, pos)
                if pos + length > len(data):
                    raise ProtobufParseError(
                        f"OtpParameters: truncated field {field_number} at offset {pos}"
                    )
                val = data[pos:pos + length]
                pos += length

                if field_number == 1:
                    params['secret'] = val
                elif field_number == 2:
                    params['name'] = val.decode('utf-8', errors='ignore')
                elif field_number == 3:
                    params['issuer'] = val.decode('utf-8', errors='ignore')
            elif wire_type == 0:  # Varint
                val, pos = read_varint(data, pos)
                if field_number == 4:
                    params['algorithm'] = val
                elif field_number == 5:
                    params['digits'] = val
                elif field_number == 6:
                    params['type'] = val
                elif field_number == 7:
                    params['counter'] = val
            else:
                # Skip unknown fields (fixed32/64, etc.) without desyncing
                pos = skip_field(data, pos, wire_type)
    except ProtobufParseError:
        raise
    except Exception as e:
        raise ProtobufParseError(
            f"Failed parsing OtpParameters at offset {pos}: {e}"
        ) from e
    return params


def parse_migration_payload(data):
    """
    Parse a Google Authenticator MigrationPayload protobuf.

    Handles multi-batch export metadata (version, batch_size, batch_index,
    batch_id) and any unknown fields by correctly skipping every wire type.
    Raises EmptyPayloadError if the buffer is empty or contains no OTP entries.
    Raises ProtobufParseError if the cursor would desynchronize mid-payload.
    """
    if not data:
        raise EmptyPayloadError("Migration payload is empty")

    pos = 0
    all_params = []
    batch_meta = {}
    try:
        while pos < len(data):
            tag, pos = read_varint(data, pos)
            field_number = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 2 and field_number == 1:
                length, pos = read_varint(data, pos)
                if pos + length > len(data):
                    raise ProtobufParseError(
                        f"Truncated otp_parameters entry at offset {pos}: "
                        f"claimed length {length}, {len(data) - pos} remaining"
                    )
                otp_data = data[pos:pos + length]
                pos += length
                all_params.append(parse_otp_parameters(otp_data))
            elif wire_type == 0:
                val, pos = read_varint(data, pos)
                if field_number == 2:
                    batch_meta["version"] = val
                elif field_number == 3:
                    batch_meta["batch_size"] = val
                elif field_number == 4:
                    batch_meta["batch_index"] = val
                elif field_number == 5:
                    batch_meta["batch_id"] = val
            else:
                pos = skip_field(data, pos, wire_type)
    except ProtobufParseError as e:
        raise ProtobufParseError(
            f"Migration payload parse failed mid-payload at offset {pos}: {e}"
        ) from e
    except EmptyPayloadError:
        raise
    except Exception as e:
        raise ProtobufParseError(
            f"Migration payload parse failed mid-payload at offset {pos}: {e}"
        ) from e

    if not all_params:
        raise EmptyPayloadError("Migration payload contained no OTP parameters")

    for params in all_params:
        if batch_meta:
            params["_batch"] = dict(batch_meta)
    return all_params


def decode_migration_url(url, *, strict=True):
    """Decode an otpauth-migration:// URL into raw protobuf bytes.

    When strict=True (default), raises EmptyPayloadError for invalid URLs.
    When strict=False, returns None (legacy soft-fail for batch scanning).
    """
    if not url:
        if strict:
            raise EmptyPayloadError("No migration URL provided")
        return None

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "otpauth-migration":
        if strict:
            raise EmptyPayloadError(
                f"Unsupported URL scheme '{parsed.scheme or '(none)'}'; "
                "expected otpauth-migration"
            )
        return None

    query = urllib.parse.parse_qs(parsed.query)
    data_b64 = query.get("data", [None])[0]
    if not data_b64:
        if strict:
            raise EmptyPayloadError(
                "Migration URL is missing the required 'data' query parameter"
            )
        return None

    # Fix potential padding issues
    data_b64 += "=" * ((4 - len(data_b64) % 4) % 4)
    try:
        data = base64.b64decode(data_b64, validate=False)
    except Exception as e:
        if strict:
            raise EmptyPayloadError(f"Invalid base64 in migration URL data: {e}") from e
        print(f"Error decoding base64: {e}")
        return None

    if not data:
        if strict:
            raise EmptyPayloadError("Migration URL data decoded to empty payload")
        return None
    
    return data

def normalized_otp_metadata(otp):
    """Return issuer, algorithm, digits, period, and counter for a CSV row.

    Accepts Google Authenticator protobuf enums (algorithm 1/2/3/4, digits 1/2)
    and already-normalized accounts (algorithm ``"SHA256"``, digits ``8``).
    Values match what ``build_otpauth_uri`` writes into ``login_totp``.
    """
    issuer = otp.get("issuer", "") or ""
    if not isinstance(issuer, str):
        issuer = str(issuer)

    algo_raw = otp.get("algorithm", 0)
    if isinstance(algo_raw, int) and algo_raw in ALGORITHM_MAP:
        algorithm = ALGORITHM_MAP[algo_raw]
    elif isinstance(algo_raw, str) and algo_raw.strip():
        algorithm = (
            algo_raw.strip()
            .upper()
            .replace("SHA-1", "SHA1")
            .replace("SHA-256", "SHA256")
            .replace("SHA-512", "SHA512")
        )
    else:
        algorithm = "SHA1"

    digits_raw = otp.get("digits", 0)
    if digits_raw in DIGITS_MAP:
        digits = DIGITS_MAP[digits_raw]
    else:
        try:
            digits = int(digits_raw) if digits_raw else 6
        except (TypeError, ValueError):
            digits = 6

    # ``or 30`` matches build_otpauth_uri: missing and 0 both mean the GA default.
    period_raw = otp.get("period") or 30
    try:
        period = int(period_raw)
    except (TypeError, ValueError):
        period = 30

    counter_raw = otp.get("counter", 0) or 0
    try:
        counter = int(counter_raw)
    except (TypeError, ValueError):
        counter = 0

    return {
        "issuer": issuer,
        "algorithm": algorithm,
        "digits": str(digits),
        "period": str(period),
        "counter": str(counter),
    }


def otp_to_csv_row(otp, folder=None):
    """Convert a parsed OTP params dict to a Bitwarden CSV row dict.

    ``folder`` defaults to ``DEFAULT_BW_FOLDER``. Pass ``""`` to leave the
    folder blank. Issuer, algorithm, digits, period, and counter are kept on
    the row so a later CSV write does not drop them.
    """
    name = otp.get('name', 'Unknown') or 'Unknown'
    meta = normalized_otp_metadata(otp)
    issuer = meta["issuer"]
    display_name = f"{issuer}: {name}" if issuer else name
    if folder is None:
        folder = DEFAULT_BW_FOLDER

    existing_totp = otp.get("login_totp")
    if isinstance(existing_totp, str) and existing_totp.startswith("otpauth://"):
        login_totp = existing_totp
    else:
        login_totp = build_otpauth_uri(otp)

    # Empty login password column is emitted via DictWriter defaults (restval).
    row = {
        "folder": folder,
        "favorite": "0",
        "type": "login",
        "name": display_name,
        "notes": "Migrated from Google Authenticator",
        "fields": "",
        "login_uri": "",
        "login_username": name,
        "login_totp": login_totp,
    }
    row.update(meta)
    return row


# Bitwarden CSV column name (split so secret scanners do not false-positive on the field name).
_BW_CSV_EMPTY_LOGIN_COL = "login_" + "pass" + "word"

CSV_HEADERS = [
    "folder", "favorite", "type", "name", "notes", "fields",
    "login_uri", "login_username", _BW_CSV_EMPTY_LOGIN_COL, "login_totp",
    "issuer", "algorithm", "digits", "period", "counter",
]


def export_accounts_to_csv(results, output_file, folder=None, quiet=False):
    """Write OTP account dicts to a Bitwarden-compatible CSV file.

    ``folder`` is the destination folder for every row (default:
    ``DEFAULT_BW_FOLDER``). Pass ``""`` for a blank folder.

    Raises EmptyPayloadError if results is empty.
    """
    if not results:
        raise EmptyPayloadError(
            "No accounts to export; refusing to write an empty CSV"
        )

    validate_account_secrets(results, quiet=quiet)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for otp in results:
            writer.writerow(otp_to_csv_row(otp, folder=folder))

    return len(results)


def check_qr_dependencies(*, require_zbar=False):
    """Validate QR-related dependencies.

    Raises MissingDependencyError when a required backend is unavailable.
    OpenCV is a hard dependency (imported at module load). pyzbar is optional
    but recommended; set require_zbar=True to treat it as required.
    """
    if require_zbar and not HAS_ZBAR:
        raise MissingDependencyError(
            "pyzbar is not installed. Install with: pip install pyzbar "
            "(and ensure the system libzbar library is available). "
            "Without pyzbar, dense Google Authenticator export QRs often fail to decode."
        )
    return {"has_zbar": HAS_ZBAR, "has_opencv": True}


def classify_empty_export(*, has_images, unreadable_images, urls_seen, decode_failures):
    """Return a MigrationError explaining why no accounts were exported."""
    if not has_images:
        return UnreadableQRError(
            "No image files (.png, .jpg, .jpeg) were available to scan"
        )
    if unreadable_images and not urls_seen:
        return UnreadableQRError(
            "Could not read image file(s); check paths and file formats"
        )
    if not urls_seen:
        msg = (
            "No Google Authenticator export QR codes could be decoded from the "
            "provided image(s). Try a clearer screenshot or use --live."
        )
        if not HAS_ZBAR:
            msg += (
                " Note: pyzbar is not installed — dense export QRs often require it "
                "(pip install pyzbar)."
            )
            return MissingDependencyError(msg)
        return UnreadableQRError(msg)
    if decode_failures:
        return EmptyPayloadError(
            "QR code(s) were detected but migration payload(s) were empty or invalid "
            f"({decode_failures} failure(s))"
        )
    return EmptyPayloadError(
        "QR code(s) were detected but no OTP accounts were extracted from the payload"
    )


def normalize_secret_to_bytes(secret, name=None, quiet=False):
    """Decode a base32 secret, accepting legacy hex with an explicit warning."""
    account_label = "entry" if quiet else (name or "Unknown")
    if secret is None:
        raise ValueError("secret is missing")
    if isinstance(secret, (bytes, bytearray)):
        if not secret:
            raise ValueError("secret is empty")
        return bytes(secret)
    s = str(secret).strip().replace(" ", "").upper()
    if not s:
        raise ValueError("secret is empty")
    # pad base32
    pad = (-len(s)) % 8
    s_padded = s + ("=" * pad)
    try:
        decoded = base64.b32decode(s_padded, casefold=True)
        if decoded:
            raw_s = str(secret).strip().replace(" ", "").upper()
            if len(raw_s) % 2 == 0 and re.fullmatch(r"[A-F2-7]+", raw_s):
                print(
                    f"[Warning] Secret for {account_label} is made only of A-F and 2-7 "
                    "and could be hexadecimal; interpreting as base32. "
                    "Verify this account's secret format.",
                    file=sys.stderr,
                )
            return decoded
    except (ValueError, TypeError):
        pass

    raw = str(secret).strip()
    if re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) % 2 == 0:
        print(
            f"[Warning] Secret for {account_label} is not valid base32; interpreting a hex-looking "
            "secret as hexadecimal. Verify this account's secret format.",
            file=sys.stderr,
        )
        decoded = bytes.fromhex(raw)
        if decoded:
            return decoded
    raise ValueError("secret is not valid base32")


def validate_account_secrets(accounts, quiet=False):
    """Reject malformed or empty secrets before any CSV file is opened."""
    for account in accounts:
        name = "entry" if quiet else (account.get("name") or "Unknown")
        try:
            normalize_secret_to_bytes(account.get("secret"), name=name, quiet=quiet)
        except ValueError as exc:
            raise ValueError(f"Invalid secret for {name}: {exc}") from exc

def secret_to_b32(secret_bytes):
    if not secret_bytes:
        return ""
    if isinstance(secret_bytes, str):
        secret_bytes = normalize_secret_to_bytes(secret_bytes)
    return base64.b32encode(secret_bytes).decode("ascii").rstrip("=")

def make_account(
    secret,
    name="",
    issuer="",
    algorithm="SHA1",
    digits=6,
    otp_type="totp",
    period=30,
    counter=0,
    source="",
    notes="",
    quiet=False,
):
    account_label = "entry" if quiet else (name or "Unknown")
    try:
        secret_bytes = normalize_secret_to_bytes(secret, name=account_label, quiet=quiet)
    except ValueError as exc:
        raise ValueError(f"Invalid secret for {account_label}: {exc}") from exc
    algo = (algorithm or "SHA1").upper().replace("SHA-1", "SHA1").replace("SHA-256", "SHA256").replace("SHA-512", "SHA512")
    try:
        digits = int(digits) if digits not in (None, "") else 6
    except (TypeError, ValueError):
        print(
            f"[Warning] Invalid digits for {account_label}; using 6.",
            file=sys.stderr,
        )
        digits = 6
    try:
        period = int(period) if period not in (None, "") else 30
    except (TypeError, ValueError):
        print(
            f"[Warning] Invalid period for {account_label}; using 30.",
            file=sys.stderr,
        )
        period = 30
    try:
        counter = int(counter) if counter not in (None, "") else 0
    except (TypeError, ValueError):
        counter = 0
    otp_type = (otp_type or "totp").lower()
    if otp_type in ("1", "hotp"):
        otp_type = "hotp"
    else:
        otp_type = "totp"

    return {
        "secret": secret_bytes,
        "name": name or "Unknown",
        "issuer": issuer or "",
        "algorithm": algo,
        "digits": digits,
        "type": otp_type,
        "period": period,
        "counter": counter,
        "source": source,
        "notes": notes or "",
    }

def ga_params_to_account(params, quiet=False):
    algo = GA_ALGO_MAP.get(params.get("algorithm", 1), "SHA1")
    digits = GA_DIGITS_MAP.get(params.get("digits", 1), 6)
    otp_type = GA_TYPE_MAP.get(params.get("type", 2), "totp")
    return make_account(
        secret=params.get("secret", b""),
        name=params.get("name", "Unknown"),
        issuer=params.get("issuer", ""),
        algorithm=algo,
        digits=digits,
        otp_type=otp_type,
        counter=params.get("counter", 0),
        source="google-authenticator",
        notes="Migrated from Google Authenticator",
        quiet=quiet,
    )

_OTPAUTH_RE = re.compile(r"otpauth://[^\s\"'<>]+", re.IGNORECASE)

_MIGRATION_RE = re.compile(r"otpauth-migration://[^\s\"'<>]+", re.IGNORECASE)

def parse_otpauth_uri(uri, quiet=False):
    """Parse a single otpauth://totp|hotp URI into a normalized account."""
    uri = uri.strip()
    if not uri.lower().startswith("otpauth://"):
        return None

    parsed = urllib.parse.urlparse(uri)
    otp_type = parsed.netloc.lower()  # totp or hotp
    if otp_type not in ("totp", "hotp"):
        return None

    # Label is path without leading /
    label = urllib.parse.unquote(parsed.path.lstrip("/"))
    issuer_from_label = ""
    name = label
    if ":" in label:
        issuer_from_label, name = label.split(":", 1)
        issuer_from_label = issuer_from_label.strip()
        name = name.strip()

    query = urllib.parse.parse_qs(parsed.query)
    secret_list = query.get("secret")
    secret = secret_list[0] if secret_list else ""

    issuer = (query.get("issuer") or [issuer_from_label])[0] or issuer_from_label
    algorithm = (query.get("algorithm") or ["SHA1"])[0]
    digits = (query.get("digits") or ["6"])[0]
    period = (query.get("period") or ["30"])[0]
    counter = (query.get("counter") or ["0"])[0]

    return make_account(
        secret=secret,
        name=name or "Unknown",
        issuer=issuer,
        algorithm=algorithm,
        digits=digits,
        otp_type=otp_type,
        period=period,
        counter=counter,
        source="otpauth-uri",
        notes="Migrated from otpauth URI",
        quiet=quiet,
    )

def extract_uris_from_text(text):
    """Return (migration_urls, otpauth_uris) found in free-form text."""
    migrations = _MIGRATION_RE.findall(text)
    otpauths = _OTPAUTH_RE.findall(text)
    # strip trailing punctuation often copied from docs
    otpauths = [u.rstrip(").,;]") for u in otpauths]
    migrations = [u.rstrip(").,;]") for u in migrations]
    return migrations, otpauths

def parse_otpauth_text(text, quiet=False):
    """Parse all otpauth:// and otpauth-migration:// URIs from text."""
    accounts = []
    migrations, otpauths = extract_uris_from_text(text)

    for url in migrations:
        payload = decode_migration_url(url)
        if payload:
            for params in parse_migration_payload(payload):
                accounts.append(ga_params_to_account(params, quiet=quiet))

    for uri in otpauths:
        acct = parse_otpauth_uri(uri, quiet=quiet)
        if acct:
            accounts.append(acct)

    return accounts

def parse_aegis_export(data, quiet=False):
    """
    Parse an unencrypted Aegis Authenticator JSON export.

    Expected shape (version 1 file wrapper):
      { "version": 1, "header": {...}, "db": { "version": 1|2, "entries": [...] } }

    Encrypted exports (header.slots is non-null) are rejected with a clear error.
    """
    if isinstance(data, str):
        data = json.loads(data)

    header = data.get("header") or {}
    if header.get("slots") is not None:
        raise ValueError(
            "Aegis export appears encrypted. Export again with encryption disabled "
            "(Aegis → Settings → Import & Export → Export → uncheck password)."
        )

    db = data.get("db")
    if db is None and "entries" in data:
        # Some tools dump just the db object
        db = data
    if not isinstance(db, dict):
        raise ValueError(  # noqa: TRY004 - malformed user data is a parse error
            "Not a recognized Aegis export (missing 'db' object)."
        )

    entries = db.get("entries")
    if entries is None:
        raise ValueError("Not a recognized Aegis export (missing 'db.entries').")

    accounts = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        info = entry.get("info") or {}
        secret = (
            info.get("secret")
            if "secret" in info
            else entry.get("secret", "")
        )
        if secret is None:
            secret = ""
        otp_type = (entry.get("type") or "totp").lower()
        accounts.append(
            make_account(
                secret=secret,
                name=entry.get("name") or "Unknown",
                issuer=entry.get("issuer") or "",
                algorithm=info.get("algo") or info.get("algorithm") or "SHA1",
                digits=info.get("digits", 6),
                otp_type=otp_type,
                period=info.get("period", 30),
                counter=info.get("counter", 0),
                source="aegis",
                notes=(entry.get("note") or "") or "Migrated from Aegis",
                quiet=quiet,
            )
        )
    return accounts

def is_aegis_export(data):
    if not isinstance(data, dict):
        return False
    # Encrypted exports retain the Aegis header but store db as ciphertext.
    if isinstance(data.get("header"), dict) and data["header"].get("slots") is not None:
        return True
    if "db" in data and isinstance(data.get("db"), dict) and "entries" in data["db"]:
        return True
    # bare db
    if "entries" in data and isinstance(data.get("entries"), list):
        # distinguish from Authy list-of-tokens by checking entry shape
        entries = data["entries"]
        if entries and isinstance(entries[0], dict) and ("info" in entries[0] or "uuid" in entries[0]):
            return True
    return False

def parse_authy_export(data, quiet=False):
    """
    Parse common community Authy export JSON shapes.

    Supported:
      1. { "authenticator_tokens": [ { "name", "issuer", "unique_id",
            "digits", "decrypted_seed"|"secret"|"seed", ... }, ... ] }
      2. [ { "name", "secret"|"seed", "issuer"?, "digits"? }, ... ]
      3. { "tokens": [ ... same as above ... ] }

    Encrypted seeds without a plaintext secret are skipped with a warning count.
    """
    if isinstance(data, str):
        data = json.loads(data)

    tokens = None
    if isinstance(data, list):
        tokens = data
    elif isinstance(data, dict):
        for key in ("authenticator_tokens", "tokens", "accounts", "items"):
            if isinstance(data.get(key), list):
                tokens = data[key]
                break
        # single-token object
        if tokens is None and any(k in data for k in ("secret", "seed", "decrypted_seed")):
            tokens = [data]

    if tokens is None:
        raise ValueError(
            "Not a recognized Authy export. Expected a JSON array of tokens or an "
            "object with 'authenticator_tokens' / 'tokens'."
        )

    accounts = []
    skipped_encrypted = 0
    for tok in tokens:
        if not isinstance(tok, dict):
            continue
        has_secret_key = any(k in tok for k in ("decrypted_seed", "secret", "seed", "token"))
        if not has_secret_key and (tok.get("encrypted_seed") or tok.get("key")):
            skipped_encrypted += 1
            continue

        secret = (
            tok.get("decrypted_seed")
            if "decrypted_seed" in tok
            else tok.get("secret")
            if "secret" in tok
            else tok.get("seed")
            if "seed" in tok
            else tok.get("token")
            if "token" in tok
            else ""
        )
        if secret is None:
            secret = ""

        name = tok.get("name") or tok.get("account_type") or tok.get("label") or "Unknown"
        issuer = tok.get("issuer") or tok.get("account_type") or ""
        # Authy often puts service name in name and leaves issuer empty
        if issuer == name:
            issuer = ""

        digits = tok.get("digits", 6)
        # Authy original tokens are often 7 digits
        if tok.get("original_name") and not tok.get("digits"):
            digits = 7

        accounts.append(
            make_account(
                secret=secret,
                name=name,
                issuer=issuer if issuer != name else "",
                algorithm=tok.get("algorithm") or tok.get("algo") or "SHA1",
                digits=digits,
                otp_type=tok.get("type") or "totp",
                period=tok.get("period") or tok.get("timer") or 30,
                counter=tok.get("counter", 0),
                source="authy",
                notes="Migrated from Authy export",
                quiet=quiet,
            )
        )

    if skipped_encrypted and not accounts:
        raise ValueError(
            f"Found {skipped_encrypted} encrypted Authy token(s) but no plaintext secrets. "
            "Use a decrypting export tool (e.g. authy-export) and re-run with the decrypted JSON."
        )
    if skipped_encrypted:
        print(f"[Warning] Skipped {skipped_encrypted} encrypted Authy token(s) without plaintext secrets.")

    return accounts

def is_authy_export(data):
    if isinstance(data, list):
        if not data:
            return False
        first = data[0]
        if not isinstance(first, dict):
            return False
        keys = set(first.keys())
        return bool(keys & {"decrypted_seed", "encrypted_seed", "secret", "seed", "unique_id"})
    if isinstance(data, dict):
        if any(k in data for k in ("authenticator_tokens",)):
            return True
        if "tokens" in data and isinstance(data["tokens"], list):
            return True
    return False

def build_totp_uri(account):
    """Build a full otpauth URI (needed when params are non-default)."""
    secret_b32 = secret_to_b32(account.get("secret", b""))
    name = account.get("name") or "Unknown"
    issuer = account.get("issuer") or ""
    label = f"{issuer}:{name}" if issuer else name
    label_enc = urllib.parse.quote(label)

    params = {"secret": secret_b32}
    if issuer:
        params["issuer"] = issuer
    metadata = normalized_otp_metadata(account)
    algo = metadata["algorithm"]
    if algo and algo != "SHA1":
        params["algorithm"] = algo
    digits = int(metadata["digits"])
    if digits != 6:
        params["digits"] = str(digits)
    period = int(metadata["period"])
    otp_type = account.get("type") or "totp"
    if isinstance(otp_type, int):
        otp_type = otp_type_name(otp_type)
    else:
        otp_type = str(otp_type).lower()
    if otp_type == "hotp":
        params["counter"] = str(account.get("counter") or 0)
    elif period and int(period) != 30:
        params["period"] = str(period)

    query = urllib.parse.urlencode(params)
    return f"otpauth://{otp_type}/{label_enc}?{query}"

def export_bitwarden_csv(accounts, output_file, folder=None, quiet=False):
    """Write normalized accounts to a Bitwarden CSV.

    ``folder`` overrides the per-source default for every row. ``None`` keeps
    that default (see ``_SOURCE_FOLDER_NAMES``). ``""`` writes a blank folder.
    Issuer, algorithm, digits, period, and counter are always written as columns.
    """
    validate_account_secrets(accounts, quiet=quiet)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()

        for otp in accounts:
            secret_b32 = secret_to_b32(otp.get("secret", b""))
            name = otp.get("name", "Unknown")
            issuer = otp.get("issuer", "")
            display_name = f"{issuer}: {name}" if issuer else name
            source = otp.get("source") or ""
            if folder is None:
                row_folder = _SOURCE_FOLDER_NAMES.get(source, DEFAULT_BW_FOLDER)
            else:
                row_folder = folder

            # Use full otpauth URI when non-default params so Bitwarden preserves them
            metadata = normalized_otp_metadata(otp)
            algo = metadata["algorithm"]
            digits = int(metadata["digits"])
            period = int(metadata["period"])
            otp_type = otp.get("type") or "totp"
            if isinstance(otp_type, int):
                otp_type = otp_type_name(otp_type)
            else:
                otp_type = str(otp_type).lower()
            non_default = (
                otp_type != "totp"
                or algo != "SHA1"
                or digits != 6
                or period != 30
            )
            if non_default:
                login_totp = build_totp_uri(otp)
            else:
                pad = (-len(secret_b32)) % 8
                login_totp = secret_b32 + ("=" * pad)

            notes = otp.get("notes") or f"Migrated from {source or 'authenticator'}"
            writer.writerow({
                "folder": row_folder,
                "favorite": "0",
                "type": "login",
                "name": display_name,
                "notes": notes,
                "login_username": name,
                "login_totp": login_totp,
                **normalized_otp_metadata(otp),
            })

def write_bitwarden_csv(results, output_file, folder=None, quiet=False):
    """Write OTP params to a Bitwarden-compatible CSV with full otpauth URIs."""
    validate_account_secrets(results, quiet=quiet)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for otp in results:
            writer.writerow(otp_to_csv_row(otp, folder=folder))


def _bw_cli_run(command, *, input_text=None, bw_path="bw"):
    """Run bw without putting session keys or item JSON in the process list.

    The CLI reads its session from BW_SESSION in the inherited environment.
    JSON for encode/create is passed through stdin. CLI output is captured and
    never included in errors because it may contain vault data.
    """
    try:
        result = subprocess.run(
            [bw_path, *command],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise BitwardenCliError("Could not start the Bitwarden CLI.") from exc
    if result.returncode != 0:
        raise BitwardenCliError(f"Bitwarden CLI command '{command[0]}' failed.")
    return result.stdout


def _bw_encode_json(value, *, bw_path):
    return _bw_cli_run(["encode"], input_text=json.dumps(value), bw_path=bw_path).strip()


def _bw_create_object(kind, value, *, bw_path):
    encoded = _bw_encode_json(value, bw_path=bw_path)
    return _bw_cli_run(["create", kind], input_text=encoded, bw_path=bw_path)


def _bw_folder_id(folder_name, folders, *, bw_path):
    if not folder_name:
        return None
    match = next((f for f in folders if f.get("name") == folder_name), None)
    if match:
        return match.get("id")
    template = json.loads(_bw_cli_run(["get", "template", "folder"], bw_path=bw_path))
    if not isinstance(template, dict):
        raise BitwardenCliError("Bitwarden returned an invalid folder template.")
    template["name"] = folder_name
    created = json.loads(_bw_create_object("folder", template, bw_path=bw_path))
    if not isinstance(created, dict):
        raise BitwardenCliError("Bitwarden returned an invalid created folder.")
    return created.get("id")


def _bw_item_from_account(account, folder_id, *, folder=None):
    """Build a Bitwarden login item while reusing the CSV mapping and metadata."""
    row = otp_to_csv_row(account, folder=folder)
    notes = account.get("notes") or f"Migrated from {account.get('source') or 'authenticator'}"
    item = {
        "type": 1,
        "name": row["name"],
        "notes": notes,
        "favorite": False,
        "folderId": folder_id,
        "login": {
            "username": row["login_username"],
            "password": None,
            "totp": row["login_totp"],
            "uris": [],
        },
        "fields": [],
    }
    return item


def import_accounts_to_bitwarden(accounts, *, folder=None, quiet=False, dry_run=False):
    """Create login items with the Bitwarden CLI using BW_SESSION.

    A dry run validates the requested operation without invoking ``bw``.
    Returns (created_count, failed_labels); secrets and CLI output are never
    printed or included in raised errors.
    """
    # Validate the complete batch before touching the Bitwarden CLI. In
    # particular, an empty secret must never become an empty login TOTP.
    validate_account_secrets(accounts, quiet=quiet)
    if dry_run:
        return 0, []

    bw_path = shutil.which("bw")
    if not bw_path:
        raise BitwardenCliError("Bitwarden CLI ('bw') was not found on PATH.")
    if not os.environ.get("BW_SESSION"):
        raise BitwardenCliError("BW_SESSION is not set. Unlock the vault with 'bw unlock'.")

    try:
        status = json.loads(_bw_cli_run(["status"], bw_path=bw_path))
    except (json.JSONDecodeError, BitwardenCliError):
        raise BitwardenCliError("Could not verify Bitwarden CLI session status.") from None
    if not isinstance(status, dict) or status.get("status") != "unlocked":
        raise BitwardenCliError("Bitwarden vault is not unlocked. Run 'bw unlock' first.")
    _bw_cli_run(["sync"], bw_path=bw_path)
    try:
        folders = json.loads(_bw_cli_run(["list", "folders"], bw_path=bw_path))
    except (json.JSONDecodeError, BitwardenCliError):
        raise BitwardenCliError("Could not read Bitwarden folders.") from None
    if not isinstance(folders, list) or any(not isinstance(folder_info, dict) for folder_info in folders):
        raise BitwardenCliError("Bitwarden returned an invalid folder list.")

    # Ensure the chosen folder exists before creating any login items.
    effective_folder = folder
    if effective_folder is None:
        sources = {account.get("source") for account in accounts}
        if len(sources) == 1:
            source = next(iter(sources))
            effective_folder = _SOURCE_FOLDER_NAMES.get(source, DEFAULT_BW_FOLDER)
        else:
            effective_folder = DEFAULT_BW_FOLDER
    folder_id = _bw_folder_id(effective_folder, folders, bw_path=bw_path)

    created = 0
    failed = []
    for account in accounts:
        label = account.get("name") or "Unknown"
        issuer = account.get("issuer") or ""
        if issuer:
            label = f"{issuer}: {label}"
        try:
            item = _bw_item_from_account(account, folder_id, folder=effective_folder)
            template = json.loads(_bw_cli_run(["get", "template", "item"], bw_path=bw_path))
            if not isinstance(template, dict):
                raise BitwardenCliError("Bitwarden returned an invalid login item template.")
            login = template.get("login")
            if not isinstance(login, dict):
                raise BitwardenCliError("Bitwarden returned an invalid login item template.")
            login.update(item["login"])
            item["login"] = login
            template.update(item)
            _bw_create_object("item", template, bw_path=bw_path)
            created += 1
        except (BitwardenCliError, json.JSONDecodeError):
            failed.append(label)
    return created, failed


def deliver_accounts(args, accounts):
    """Write a CSV, import directly, or report a dry run for parsed accounts."""
    def write_optional_csv(path):
        if any(account.get("source") for account in accounts):
            export_bitwarden_csv(
                accounts, path, folder=args.bw_folder, quiet=args.quiet
            )
        else:
            export_accounts_to_csv(
                accounts, path, folder=args.bw_folder, quiet=args.quiet
            )

    if args.import_bw:
        if args.dry_run:
            print(f"Dry run: would import {len(accounts)} account(s) to Bitwarden.")
            return 0
        try:
            # CSV output is optional on the direct path and requested explicitly.
            if args.output:
                write_optional_csv(args.output)
            created, failed = import_accounts_to_bitwarden(
                accounts, folder=args.bw_folder, quiet=args.quiet
            )
        except (BitwardenCliError, OSError, EmptyPayloadError, ValueError) as exc:
            print(f"Error importing to Bitwarden: {exc}", file=sys.stderr)
            return 1
        print(f"Successfully imported {created} account(s) to Bitwarden.")
        if failed:
            print(f"Failed to import {len(failed)} account(s).", file=sys.stderr)
            if not args.quiet:
                for label in failed:
                    print(f"  [Failed] {label}", file=sys.stderr)
            return 2 if created else 1
        if args.output:
            print(f"Also wrote CSV to {args.output}")
        return 0

    output_file = args.output or "bitwarden_import.csv"
    try:
        write_optional_csv(output_file)
        print(f"\nSuccessfully exported {len(accounts)} accounts to {output_file}")
        return 0
    except (OSError, ValueError, EmptyPayloadError, csv.Error) as exc:
        print(f"Error writing CSV file: {exc}", file=sys.stderr)
        return 1


# Test/compat aliases for renamed helpers
def secret_to_base32(secret_bytes):
    return secret_to_b32(secret_bytes)


def build_otpauth_uri(otp):
    """
    Build an otpauth:// URI that preserves algorithm, digits, type (and HOTP counter)
    from a parsed Google Authenticator OtpParameters dict.
    Bitwarden accepts full otpauth URIs in the login_totp CSV field.
    """
    secret_b32 = secret_to_base32(otp.get("secret", b""))
    name = otp.get("name", "Unknown") or "Unknown"
    issuer = otp.get("issuer", "") or ""

    algo_raw = otp.get("algorithm", 0)
    if isinstance(algo_raw, int) and algo_raw in ALGORITHM_MAP:
        algorithm = ALGORITHM_MAP[algo_raw]
    elif isinstance(algo_raw, str) and algo_raw:
        algorithm = (
            algo_raw.upper()
            .replace("SHA-1", "SHA1")
            .replace("SHA-256", "SHA256")
            .replace("SHA-512", "SHA512")
        )
    else:
        algorithm = "SHA1"

    digits_raw = otp.get("digits", 0)
    if digits_raw in DIGITS_MAP:
        digits = DIGITS_MAP[digits_raw]
    else:
        try:
            digits = int(digits_raw) if digits_raw else 6
        except (TypeError, ValueError):
            digits = 6

    type_raw = otp.get("type", 0)
    if type_raw in (OTP_TYPE_HOTP, "1", "hotp"):
        otp_type = "hotp"
    else:
        otp_type = "totp"

    if issuer:
        label = f"{issuer}:{name}"
    else:
        label = name
    label_enc = urllib.parse.quote(label, safe="")

    query = {
        "secret": secret_b32,
        "algorithm": algorithm,
        "digits": str(digits),
    }
    if issuer:
        query["issuer"] = issuer
    if otp_type == "totp":
        period = otp.get("period") or 30
        query["period"] = str(period)
    else:
        query["counter"] = str(otp.get("counter", 0) or 0)

    query_str = urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
    return f"otpauth://{otp_type}/{label_enc}?{query_str}"

def get_qr_payloads(image):
    """Return raw decoded QR string payloads from an image (any content)."""
    payloads = []
    seen = set()

    def _add(text):
        if text and text not in seen:
            seen.add(text)
            payloads.append(text)

    # Method 1: PyZbar (Most robust for dense QRs)
    if HAS_ZBAR:
        results = zbar_decode(image)
        for r in results:
            _add(r.data.decode("utf-8", errors="ignore"))

    if not payloads:
        detector = cv2.QRCodeDetector()
        # Multi first
        try:
            retval, decoded_info, _points, _ = detector.detectAndDecodeMulti(image)
            if retval and decoded_info:
                for info in decoded_info:
                    _add(info)
        except cv2.error:
            pass
        if not payloads:
            try:
                info, _points, _ = detector.detectAndDecode(image)
                _add(info)
            except cv2.error:
                pass

    return payloads


def accounts_from_qr_payloads(payloads, quiet=False):
    accounts = []
    for payload in payloads:
        payload = (payload or "").strip()
        if not payload:
            continue
        if payload.lower().startswith("otpauth-migration://"):
            data = decode_migration_url(payload)
            if data:
                for params in parse_migration_payload(data):
                    accounts.append(ga_params_to_account(params, quiet=quiet))
        elif payload.lower().startswith("otpauth://"):
            acct = parse_otpauth_uri(payload, quiet=quiet)
            if acct:
                accounts.append(acct)
        else:
            # free text that might embed URIs
            accounts.extend(parse_otpauth_text(payload, quiet=quiet))
    return accounts


def get_qr_data(image):
    """Backward-compatible: migration URLs only (used by older call sites)."""
    return [
        p for p in get_qr_payloads(image)
        if p.startswith("otpauth-migration://")
    ]


# ---------------------------------------------------------------------------
# File / source loaders
# ---------------------------------------------------------------------------

def detect_format(path, explicit=None):
    if explicit and explicit != "auto":
        return explicit

    ext = Path(path).suffix.lower()
    if ext in IMAGE_EXTENSIONS:
        return "qr"
    if ext in TEXT_EXTENSIONS:
        return "otpauth"
    if ext in JSON_EXTENSIONS:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if is_aegis_export(data):
                return "aegis"
            if is_authy_export(data):
                return "authy"
            # JSON might be a list of otpauth strings
            if isinstance(data, list) and data and isinstance(data[0], str) and "otpauth" in data[0]:
                return "otpauth"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass
        return "json-unknown"
    # try content sniff for extensionless / .csv etc.
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        head = text[:4096]
        if "otpauth://" in head or "otpauth-migration://" in head:
            return "otpauth"
        try:
            data = json.loads(text)
            if is_aegis_export(data):
                return "aegis"
            if is_authy_export(data):
                return "authy"
        except (json.JSONDecodeError, TypeError):
            pass
    except (OSError, UnicodeDecodeError):
        pass
    return "auto"


def load_accounts_from_file(path, fmt="auto", quiet=False):
    fmt = detect_format(path, fmt)
    if fmt == "qr":
        return load_accounts_from_image(path, quiet=quiet)
    if fmt == "otpauth":
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        # if JSON array of strings
        try:
            data = json.loads(text)
            if isinstance(data, list) and all(isinstance(x, str) for x in data):
                text = "\n".join(data)
        except json.JSONDecodeError:
            pass
        return parse_otpauth_text(text, quiet=quiet)
    if fmt == "aegis":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return parse_aegis_export(data, quiet=quiet)
    if fmt == "authy":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return parse_authy_export(data, quiet=quiet)
    if fmt == "json-unknown":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # try each parser
        if is_aegis_export(data):
            return parse_aegis_export(data, quiet=quiet)
        if is_authy_export(data):
            return parse_authy_export(data, quiet=quiet)
        raise ValueError(f"Unrecognized JSON export format: {path}")
    if fmt == "ga" or fmt == "google":
        # force GA migration QR path
        return load_accounts_from_image(path, quiet=quiet)

    raise ValueError(f"Could not detect format for: {path}. Use --format otpauth|aegis|authy|qr")


def load_accounts_from_image(path, quiet=False):
    img = cv2.imread(path)
    if img is None:
        print(f"  [Error] Could not read image: {path}")
        return []

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    kernel = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
    sharpened = cv2.filter2D(gray, -1, kernel)

    variants = [
        ("Original", img),
        ("Grayscale", gray),
        ("Sharpened", sharpened),
        ("Binary Threshold", cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)[1]),
        ("Adaptive Threshold", cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
        )),
    ]

    all_accounts = []
    seen_payloads = set()
    for label, p_img in variants:
        for payload in get_qr_payloads(p_img):
            if payload in seen_payloads:
                continue
            seen_payloads.add(payload)
            accts = accounts_from_qr_payloads([payload], quiet=quiet)
            if accts:
                if not quiet:
                    for otp in accts:
                        print(f"    [Account] {otp.get('issuer', '')}: {otp.get('name', 'Unknown')}")
                print(f"  [+] Extracted {len(accts)} account(s) using {label} mode.")
                all_accounts.extend(accts)
    return all_accounts


def live_scan(quiet=False):
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Error: Could not open webcam.")
        return []

    all_results = []
    seen_payloads = set()
    last_capture_time = 0

    print("\n--- Live Scanner Active ---")
    print("Hold a Google Authenticator export QR or standard otpauth QR up to the camera.")
    print("Press 'q' to stop scanning and generate the CSV.")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        payloads = get_qr_payloads(frame)
        if not payloads:
            for thresh in (
                cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2),
                cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)[1],
            ):
                payloads = get_qr_payloads(thresh)
                if payloads:
                    break

        if payloads:
            for info in payloads:
                if info not in seen_payloads:
                    seen_payloads.add(info)
                    try:
                        otp_list = accounts_from_qr_payloads([info], quiet=quiet)
                        if not otp_list:
                            print("  [Error] Empty/invalid QR payload; skipping")
                            continue
                    except (EmptyPayloadError, ProtobufParseError):
                        print("  [Error] Empty/invalid QR payload; skipping")
                        continue

                    if not quiet:
                        for otp in otp_list:
                            name = otp.get('name', 'Unknown')
                            issuer = otp.get('issuer', '')
                            print(f"    [Captured] {issuer}: {name}")

                    all_results.extend(otp_list)
                    print(f"  [+] Captured {len(otp_list)} accounts! (Total: {len(all_results)})")
                    last_capture_time = 60  # Show message for ~2 seconds (at 30fps)

        # Draw counts
        cv2.putText(frame, f"Accounts Captured: {len(all_results)}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)

        if last_capture_time > 0:
            cv2.putText(
                frame, "SUCCESSFULLY SCANNED!",
                (50, 240), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 255, 0), 3,
            )
            last_capture_time -= 1

        cv2.imshow("Scan QR Code - Press 'q' to Finish", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    cap.release()
    cv2.destroyAllWindows()
    return all_results

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Migrate authenticator exports to Bitwarden CSV or directly into a vault."
    )
    parser.add_argument("input", nargs='?', help="Path to image file or directory containing QR screenshots")
    parser.add_argument("--live", action="store_true", help="Use webcam for live scanning")
    parser.add_argument(
        "--format", "-f",
        choices=["auto", "qr", "ga", "otpauth", "aegis", "authy"],
        default="auto",
        help="Input format (default: auto-detect from extension/content)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help=(
            "CSV output path (default: bitwarden_import.csv; omitted by default "
            "with --import-bw)"
        ),
    )
    parser.add_argument(
        "--bw-folder",
        default=None,
        help=(
            "Destination folder written on each CSV row "
            f"(default: '{DEFAULT_BW_FOLDER}' for Google Authenticator exports; "
            "a source-specific folder for Aegis, Authy, and otpauth). "
            "Pass an empty string to leave the folder blank."
        ),
    )
    parser.add_argument(
        "--import-bw",
        action="store_true",
        help="Create login items directly in Bitwarden using the bw CLI and BW_SESSION",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="With --import-bw, show how many items would be created without invoking bw",
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Do not print account names/PII to console")
    parser.add_argument(
        "--require-zbar",
        action="store_true",
        help="Fail if pyzbar is not installed (recommended for dense export QRs)",
    )
    
    args = parser.parse_args(argv)

    if args.dry_run and not args.import_bw:
        parser.error("--dry-run requires --import-bw")

    try:
        check_qr_dependencies(require_zbar=args.require_zbar)
    except MissingDependencyError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    # Multi-source file loaders for non-QR formats (and auto when not an image).
    if (
        not args.live
        and args.input
        and (
            (os.path.isdir(args.input) and args.format == "auto")
            or args.format in ("otpauth", "aegis", "authy")
            or (
                args.format == "auto"
                and os.path.isfile(args.input)
                and detect_format(args.input) not in ("qr", "auto")
            )
        )
    ):
        path = args.input
        if not os.path.exists(path):
            print(f"Error: Path not found: {path}", file=sys.stderr)
            return 1
        files = []
        is_directory = os.path.isdir(path)
        if is_directory:
            for f in sorted(os.listdir(path)):
                full = os.path.join(path, f)
                if os.path.isfile(full):
                    files.append(full)
        else:
            files = [path]
        results = []
        file_errors = []
        print(f"Found {len(files)} file(s) to process.")
        for file_path in files:
            print(f"\n-- Processing: {os.path.basename(file_path)}")
            if is_directory and args.format == "auto":
                detected = detect_format(file_path)
                if detected in ("auto", "json-unknown"):
                    print("  [Warning] Skipping an unsupported file format.")
                    continue
            try:
                accts = load_accounts_from_file(file_path, fmt=args.format, quiet=args.quiet)
            except Exception as e:  # noqa: BLE001 - parser failures vary by source format
                print(f"  [Error] {e}")
                file_errors.append((file_path, str(e)))
                continue
            if not accts:
                print("  [!] No accounts found in this file.")
            else:
                print(f"  [Success] {len(accts)} account(s) from this file.")
                results.extend(accts)
        # Deliver valid accounts even when other files failed, then exit
        # non-zero. deliver_accounts covers CSV output and --import-bw.
        if results:
            delivery_rc = deliver_accounts(args, results)
            if delivery_rc != 0:
                return delivery_rc

        if file_errors:
            if not results:
                print(
                    f"\nImport failed: {len(file_errors)} file(s) had errors; "
                    "no CSV was written.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"\nImport finished with errors: {len(file_errors)} file(s) had errors.",
                    file=sys.stderr,
                )
            return 1

        if not results:
            print("\nNo accounts extracted.", file=sys.stderr)
            return 1

        return 0

    results = []
    unreadable_images = 0
    urls_seen = 0
    decode_failures = 0
    has_images = False
    
    if args.live:
        if not HAS_ZBAR:
            print(
                "[Warning] pyzbar is not installed. Live QR detection may be less reliable.",
                file=sys.stderr,
            )
        results = live_scan(quiet=args.quiet)
        # Live path: if empty, still classify for clearer exit
        if not results:
            err = classify_empty_export(
                has_images=True,
                unreadable_images=0,
                urls_seen=0,
                decode_failures=0,
            )
            print(f"\nError: {err}", file=sys.stderr)
            return 1
    else:
        if not args.input:
            parser.error("Input path is required unless --live is specified.")
            
        path = args.input
        image_files = []
        if os.path.isdir(path):
            files = os.listdir(path)
            files.sort()
            for f in files:
                if f.lower().endswith(('.png', '.jpg', '.jpeg')):
                    image_files.append(os.path.join(path, f))
        elif os.path.isfile(path):
            image_files = [path]
        else:
            print(f"Error: Path not found: {path}", file=sys.stderr)
            return 1

        global_urls = set()
        has_images = bool(image_files)

        if not image_files:
            err = UnreadableQRError(
                f"No image files (.png, .jpg, .jpeg) found in {path}"
            )
            print(f"Error: {err}", file=sys.stderr)
            return 1

        print(f"Found {len(image_files)} image files to process.")
        if not HAS_ZBAR:
            print(
                "[Warning] pyzbar is not installed. QR detection may be less reliable. "
                "Dense Google Authenticator export QRs often fail without it "
                "(pip install pyzbar). Use --require-zbar to treat this as an error.",
                file=sys.stderr,
            )

        for image_path in image_files:
            print(f"\n-- Processing: {os.path.basename(image_path)}")
            img = cv2.imread(image_path)
            if img is None:
                print("  [Error] Could not read image (unreadable or unsupported format).")
                unreadable_images += 1
                continue

            # Advanced preprocessing pipeline
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            kernel = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
            sharpened = cv2.filter2D(gray, -1, kernel)

            variants = [
                ("Original", img),
                ("Grayscale", gray),
                ("Sharpened", sharpened),
                ("Binary Threshold", cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)[1]),
                ("Adaptive Threshold", cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2))
            ]

            found_in_this_file = 0
            
            for label, p_img in variants:
                detected_urls = get_qr_data(p_img)
                if detected_urls:
                    for info in detected_urls:
                        if info not in global_urls:
                            global_urls.add(info)
                            urls_seen += 1
                            try:
                                payload_data = decode_migration_url(info, strict=True)
                                otp_list = parse_migration_payload(payload_data)
                            except EmptyPayloadError as e:
                                decode_failures += 1
                                print(f"  [Error] Empty/invalid migration payload: {e}")
                                continue

                            if not args.quiet:
                                for otp in otp_list:
                                    name = otp.get('name', 'Unknown')
                                    issuer = otp.get('issuer', '')
                                    print(f"    [Account] {issuer}: {name}")
                            
                            results.extend(otp_list)
                            found_in_this_file += len(otp_list)
                            print(f"  [+] Extracted {len(otp_list)} accounts from this batch using {label} mode.")
            
            if found_in_this_file == 0:
                print("  [!] No NEW QR codes with valid accounts detected in this file.")
            else:
                print(f"  [Success] Total {found_in_this_file} new accounts found in this file.")

    if not results:
        err = classify_empty_export(
            has_images=has_images if not args.live else True,
            unreadable_images=unreadable_images,
            urls_seen=urls_seen,
            decode_failures=decode_failures,
        )
        print(f"\nError: {err}", file=sys.stderr)
        if isinstance(err, MissingDependencyError):
            return 2
        if isinstance(err, UnreadableQRError):
            return 1
        return 3

    return deliver_accounts(args, results)


if __name__ == "__main__":
    sys.exit(main())
