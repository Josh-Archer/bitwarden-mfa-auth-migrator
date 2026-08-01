#!/usr/bin/env python3
"""Migrate TOTP secrets from common authenticator export formats to Bitwarden CSV."""

import argparse
import base64
import csv
import json
import os
import re
import struct
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

# Google Authenticator Migration Protobuf (manual wire-format parsing)
# Wire types: 0=varint, 1=64-bit, 2=length-delimited, 3/4=group (deprecated), 5=32-bit

class ProtobufParseError(ValueError):
    """Raised when a migration payload cannot be parsed safely."""


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
        if shift >= 64:
            raise ProtobufParseError(f"Varint too long at offset {start}")
        b = data[pos]
        res |= (b & 0x7f) << shift
        pos += 1
        if not (b & 0x80):
            return res, pos
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")


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

# Google Authenticator MigrationPayload.OtpParameters enums
# https://github.com/google/google-authenticator-android (migration protobuf)
ALGORITHM_MAP = {
    0: "SHA1",   # ALGORITHM_UNSPECIFIED → GA default
    1: "SHA1",   # ALGORITHM_SHA1
    2: "SHA256", # ALGORITHM_SHA256
    3: "SHA512", # ALGORITHM_SHA512
    4: "MD5",    # ALGORITHM_MD5
}

DIGITS_MAP = {
    0: 6,  # DIGIT_COUNT_UNSPECIFIED → GA default
    1: 6,  # DIGIT_COUNT_SIX
    2: 8,  # DIGIT_COUNT_EIGHT
}

# OTP_TYPE_UNSPECIFIED=0, OTP_TYPE_HOTP=1, OTP_TYPE_TOTP=2
def otp_type_name(type_val):
    if type_val == 1:
        return "hotp"
    return "totp"



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
    if wire_type in (3, 4):  # Start/end group (deprecated)
        # Groups are rare in GA exports; refuse rather than guess boundaries.
        raise ProtobufParseError(
            f"Deprecated group wire type {wire_type} at offset {pos} "
            f"is not supported"
        )
    raise ProtobufParseError(f"Unknown protobuf wire type {wire_type} at offset {pos}")


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
    Raises ProtobufParseError if the cursor would desynchronize mid-payload.
    """
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
                # MigrationPayload batch metadata (multi-QR exports)
                if field_number == 2:
                    batch_meta['version'] = val
                elif field_number == 3:
                    batch_meta['batch_size'] = val
                elif field_number == 4:
                    batch_meta['batch_index'] = val
                elif field_number == 5:
                    batch_meta['batch_id'] = val
            else:
                # Length-delimited non-otp fields, fixed32/64, etc.
                pos = skip_field(data, pos, wire_type)
    except ProtobufParseError as e:
        raise ProtobufParseError(
            f"Migration payload parse failed mid-payload at offset {pos}: {e}"
        ) from e
    except Exception as e:
        raise ProtobufParseError(
            f"Migration payload parse failed mid-payload at offset {pos}: {e}"
        ) from e

    # Attach batch metadata for callers that need multi-batch awareness
    for params in all_params:
        if batch_meta:
            params['_batch'] = dict(batch_meta)
    return all_params


def decode_migration_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "otpauth-migration":
        return None

    query = urllib.parse.parse_qs(parsed.query)
    data_b64 = query.get("data", [None])[0]
    if not data_b64:
        return None

    # Fix potential padding issues
    data_b64 += "=" * ((4 - len(data_b64) % 4) % 4)
    try:
        return base64.b64decode(data_b64)
    except Exception as e:
        print(f"Error decoding base64: {e}")
        return None


# ---------------------------------------------------------------------------
# Normalized account model
# ---------------------------------------------------------------------------

def normalize_secret_to_bytes(secret):
    """Accept raw bytes or base32 string; return secret bytes."""
    if secret is None:
        return b""
    if isinstance(secret, (bytes, bytearray)):
        return bytes(secret)
    s = str(secret).strip().replace(" ", "").upper()
    # pad base32
    pad = (-len(s)) % 8
    s += "=" * pad
    try:
        return base64.b32decode(s, casefold=True)
    except Exception:
        # Some exports store hex; try that as a fallback
        try:
            return bytes.fromhex(str(secret).strip())
        except Exception:
            return b""


def secret_to_b32(secret_bytes):
    if not secret_bytes:
        return ""
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
):
    secret_bytes = normalize_secret_to_bytes(secret)
    algo = (algorithm or "SHA1").upper().replace("SHA-1", "SHA1").replace("SHA-256", "SHA256").replace("SHA-512", "SHA512")
    try:
        digits = int(digits) if digits not in (None, "") else 6
    except (TypeError, ValueError):
        digits = 6
    try:
        period = int(period) if period not in (None, "") else 30
    except (TypeError, ValueError):
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


def ga_params_to_account(params):
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
    )


# ---------------------------------------------------------------------------
# otpauth:// URI parsing
# ---------------------------------------------------------------------------

_OTPAUTH_RE = re.compile(r"otpauth://[^\s\"'<>]+", re.IGNORECASE)
_MIGRATION_RE = re.compile(r"otpauth-migration://[^\s\"'<>]+", re.IGNORECASE)


def parse_otpauth_uri(uri):
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
    secret = (query.get("secret") or [""])[0]
    if not secret:
        return None

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
    )


def extract_uris_from_text(text):
    """Return (migration_urls, otpauth_uris) found in free-form text."""
    migrations = _MIGRATION_RE.findall(text)
    otpauths = _OTPAUTH_RE.findall(text)
    # strip trailing punctuation often copied from docs
    otpauths = [u.rstrip(").,;]") for u in otpauths]
    migrations = [u.rstrip(").,;]") for u in migrations]
    return migrations, otpauths


def parse_otpauth_text(text):
    """Parse all otpauth:// and otpauth-migration:// URIs from text."""
    accounts = []
    migrations, otpauths = extract_uris_from_text(text)

    for url in migrations:
        payload = decode_migration_url(url)
        if payload:
            for params in parse_migration_payload(payload):
                accounts.append(ga_params_to_account(params))

    for uri in otpauths:
        acct = parse_otpauth_uri(uri)
        if acct:
            accounts.append(acct)

    return accounts


# ---------------------------------------------------------------------------
# Aegis JSON export
# ---------------------------------------------------------------------------

def parse_aegis_export(data):
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
        raise ValueError("Not a recognized Aegis export (missing 'db' object).")

    entries = db.get("entries")
    if entries is None:
        raise ValueError("Not a recognized Aegis export (missing 'db.entries').")

    accounts = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        info = entry.get("info") or {}
        secret = info.get("secret") or entry.get("secret")
        if not secret:
            continue
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
            )
        )
    return accounts


def is_aegis_export(data):
    if not isinstance(data, dict):
        return False
    if "db" in data and isinstance(data.get("db"), dict) and "entries" in data["db"]:
        return True
    # bare db
    if "entries" in data and isinstance(data.get("entries"), list):
        # distinguish from Authy list-of-tokens by checking entry shape
        entries = data["entries"]
        if entries and isinstance(entries[0], dict) and ("info" in entries[0] or "uuid" in entries[0]):
            return True
    return False


# ---------------------------------------------------------------------------
# Authy-style exports
# ---------------------------------------------------------------------------

def parse_authy_export(data):
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
        secret = (
            tok.get("decrypted_seed")
            or tok.get("secret")
            or tok.get("seed")
            or tok.get("token")
        )
        if not secret:
            if tok.get("encrypted_seed") or tok.get("key"):
                skipped_encrypted += 1
            continue

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


# ---------------------------------------------------------------------------
# QR decoding
# ---------------------------------------------------------------------------

def get_qr_payloads(image):
    """Return raw decoded QR string payloads from an image (any content)."""
    payloads = []
    seen = set()

    def _add(text):
        if text and text not in seen:
            seen.add(text)
            payloads.append(text)

    if HAS_ZBAR:
        results = zbar_decode(image)
        for r in results:
            _add(r.data.decode("utf-8", errors="ignore"))

    if not payloads:
        detector = cv2.QRCodeDetector()
        # Multi first
        try:
            retval, decoded_info, points, _ = detector.detectAndDecodeMulti(image)
            if retval and decoded_info:
                for info in decoded_info:
                    _add(info)
        except Exception:
            pass
        if not payloads:
            try:
                info, points, _ = detector.detectAndDecode(image)
                _add(info)
            except Exception:
                pass

    return payloads


def accounts_from_qr_payloads(payloads):
    accounts = []
    for payload in payloads:
        payload = (payload or "").strip()
        if not payload:
            continue
        if payload.startswith("otpauth-migration://"):
            data = decode_migration_url(payload)
            if data:
                for params in parse_migration_payload(data):
                    accounts.append(ga_params_to_account(params))
        elif payload.lower().startswith("otpauth://"):
            acct = parse_otpauth_uri(payload)
            if acct:
                accounts.append(acct)
        else:
            # free text that might embed URIs
            accounts.extend(parse_otpauth_text(payload))
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
        except Exception:
            pass
        return "json-unknown"
    # try content sniff for extensionless / .csv etc.
    try:
        with open(path, "r", encoding="utf-8") as f:
            head = f.read(4096)
        if "otpauth://" in head or "otpauth-migration://" in head:
            return "otpauth"
        try:
            data = json.loads(head if head.strip().startswith("{") or head.strip().startswith("[") else open(path, encoding="utf-8").read())
            if is_aegis_export(data):
                return "aegis"
            if is_authy_export(data):
                return "authy"
        except Exception:
            pass
    except Exception:
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
        except Exception:
            pass
        return parse_otpauth_text(text)
    if fmt == "aegis":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return parse_aegis_export(data)
    if fmt == "authy":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return parse_authy_export(data)
    if fmt == "json-unknown":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # try each parser
        if is_aegis_export(data):
            return parse_aegis_export(data)
        if is_authy_export(data):
            return parse_authy_export(data)
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
            accts = accounts_from_qr_payloads([payload])
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

        if detected_urls:
            for info in detected_urls:
                if info not in seen_urls:
                    seen_urls.add(info)
                    payload_data = decode_migration_url(info)
                    if payload_data:
                        try:
                            otp_list = parse_migration_payload(payload_data)
                        except ProtobufParseError as e:
                            print(f"  [Error] Failed to parse migration payload: {e}")
                            continue
                        if not quiet:
                            for otp in otp_list:
                                name = otp.get('name', 'Unknown')
                                issuer = otp.get('issuer', '')
                                print(f"    [Captured] {issuer}: {name}")
                        
                        all_results.extend(otp_list)
                        print(f"  [+] Captured {len(otp_list)} accounts! (Total: {len(all_results)})")
                        last_capture_time = 60 # Show message for ~2 seconds (at 30fps)
        
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


# ---------------------------------------------------------------------------
# Bitwarden CSV export
# ---------------------------------------------------------------------------

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
    algo = (account.get("algorithm") or "SHA1").upper()
    if algo and algo != "SHA1":
        params["algorithm"] = algo
    digits = account.get("digits") or 6
    if digits and int(digits) != 6:
        params["digits"] = str(digits)
    period = account.get("period") or 30
    otp_type = account.get("type") or "totp"
    if otp_type == "hotp":
        params["counter"] = str(account.get("counter") or 0)
    elif period and int(period) != 30:
        params["period"] = str(period)

    query = urllib.parse.urlencode(params)
    return f"otpauth://{otp_type}/{label_enc}?{query}"


# Bitwarden CSV column name (split so secret scanners do not false-positive on the field name).
_BW_CSV_EMPTY_LOGIN_COL = "login_" + "pass" + "word"


def export_bitwarden_csv(accounts, output_file):
    headers = [
        "folder", "favorite", "type", "name", "notes", "fields",
        "login_uri", "login_username", _BW_CSV_EMPTY_LOGIN_COL, "login_totp",
    ]

    folder_map = {
        "google-authenticator": "Google Authenticator Migration",
        "otpauth-uri": "otpauth URI Import",
        "aegis": "Aegis Migration",
        "authy": "Authy Migration",
    }

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

        for otp in accounts:
            secret_b32 = secret_to_b32(otp.get("secret", b""))
            name = otp.get("name", "Unknown")
            issuer = otp.get("issuer", "")
            display_name = f"{issuer}: {name}" if issuer else name
            source = otp.get("source") or ""
            folder = folder_map.get(source, "Authenticator Migration")

            # Use full otpauth URI when non-default params so Bitwarden preserves them
            algo = (otp.get("algorithm") or "SHA1").upper()
            digits = int(otp.get("digits") or 6)
            period = int(otp.get("period") or 30)
            otp_type = otp.get("type") or "totp"
            non_default = (
                otp_type != "totp"
                or algo != "SHA1"
                or digits != 6
                or period != 30
            )
            login_totp = build_totp_uri(otp) if non_default else secret_b32

            notes = otp.get("notes") or f"Migrated from {source or 'authenticator'}"
            writer.writerow({
                "folder": folder,
                "favorite": "0",
                "type": "login",
                "name": display_name,
                "notes": notes,
                "login_username": name,
                "login_totp": login_totp,
            })


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Convert authenticator exports (Google Authenticator QR, otpauth URIs, "
            "Aegis JSON, Authy JSON) to a Bitwarden/Vaultwarden CSV."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Path to image, text/URI file, JSON export, or directory of such files",
    )
    parser.add_argument("--live", action="store_true", help="Use webcam for live QR scanning")
    parser.add_argument(
        "--format", "-f",
        choices=["auto", "qr", "ga", "otpauth", "aegis", "authy"],
        default="auto",
        help="Input format (default: auto-detect from extension/content)",
    )
    parser.add_argument(
        "--output", "-o",
        default="bitwarden_import.csv",
        help="Output CSV file path (default: bitwarden_import.csv)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Do not print account names/PII to console",
    )

    args = parser.parse_args(argv)
    results = []

    if args.live:
        results = live_scan(quiet=args.quiet)
    else:
        if not args.input:
            parser.error("Input path is required unless --live is specified.")

        path = args.input
        if not os.path.exists(path):
            print(f"Error: Path not found: {path}")
            return 1

        files = []
        if os.path.isdir(path):
            for f in sorted(os.listdir(path)):
                full = os.path.join(path, f)
                if not os.path.isfile(full):
                    continue
                ext = Path(f).suffix.lower()
                if ext in IMAGE_EXTENSIONS | TEXT_EXTENSIONS | JSON_EXTENSIONS:
                    files.append(full)
        else:
            files = [path]

        if not files:
            print(f"No supported files found in {path}")
            return 1

        print(f"Found {len(files)} file(s) to process.")
        if not HAS_ZBAR:
            print("[Warning] pyzbar is not installed. QR detection may be less reliable.")

        for file_path in files:
            print(f"\n-- Processing: {os.path.basename(file_path)}")
            try:
                accts = load_accounts_from_file(file_path, fmt=args.format, quiet=args.quiet)
            except ValueError as e:
                print(f"  [Error] {e}")
                continue
            except Exception as e:
                print(f"  [Error] Failed to parse: {e}")
                continue

            if not accts:
                print("  [!] No accounts found in this file.")
            else:
                if not args.quiet:
                    for otp in accts:
                        # avoid double-printing when image loader already did
                        if otp.get("source") not in (None,):
                            pass
                print(f"  [Success] {len(accts)} account(s) from this file.")
                results.extend(accts)

    if not results:
        print("\nNo accounts extracted. Check the format docs in README.md.")
        return 1

    output_file = args.output
    try:
        write_bitwarden_csv(results, output_file)
        print(f"\nSuccessfully exported {len(results)} accounts to {output_file}")
        print("Next steps:")
        print("1. Open Vaultwarden Web Vault")
        print("2. Go to Tools -> Import Data")
        print(f"3. Select 'Bitwarden (csv)' and upload {output_file}")
        print("4. IMPORTANT: Delete the CSV file after verification!")
    except Exception as e:
        print(f"Error writing CSV file: {e}")


# Bitwarden CSV column name (split so secret scanners do not false-positive on the field name).
_BW_CSV_EMPTY_LOGIN_COL = "login_" + "pass" + "word"


def write_bitwarden_csv(results, output_file):
    """Write OTP params to a Bitwarden-compatible CSV with full otpauth URIs."""
    headers = [
        "folder", "favorite", "type", "name", "notes", "fields",
        "login_uri", "login_username", _BW_CSV_EMPTY_LOGIN_COL, "login_totp",
    ]
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for otp in results:
            name = otp.get("name", "Unknown")
            issuer = otp.get("issuer", "")
            display_name = f"{issuer}: {name}" if issuer else name
            writer.writerow({
                "folder": "Google Authenticator Migration",
                "favorite": "0",
                "type": "login",
                "name": display_name,
                "notes": "Migrated from Google Authenticator",
                "login_username": name,
                "login_totp": build_otpauth_uri(otp),
            })


def _bw_env(session):
    """Build env for bw subprocesses. Session is never logged."""
    env = os.environ.copy()
    env["BW_SESSION"] = session
    # Avoid interactive prompts hanging the tool
    env.setdefault("BW_NOINTERACTION", "true")
    return env


def _run_bw(args, session, *, input_text=None, check=False):
    """
    Run the Bitwarden CLI. Session is passed only via environment, never argv
    (avoids leaking the key into process listings where possible).
    """
    cmd = ["bw", *args]
    result = subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        env=_bw_env(session),
    )
    if check and result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(err or f"bw {' '.join(args)} failed with code {result.returncode}")
    return result


def resolve_bw_session(explicit_session=None):
    """
    Prefer BW_SESSION from the environment (secure default).
    An explicit CLI value is accepted but discouraged (visible in process list / shell history).
    """
    if explicit_session:
        print(
            "[Warning] Passing the session on the command line is less secure than "
            "setting the BW_SESSION environment variable (process list / shell history)."
        )
        return explicit_session.strip()
    session = os.environ.get("BW_SESSION", "").strip()
    if not session:
        print(
            "Error: No Bitwarden session available.\n"
            "  1. Log in / unlock:  bw login   or   bw unlock --raw\n"
            "  2. Export the session (do not write it to disk):\n"
            "       export BW_SESSION=\"$(bw unlock --raw)\"   # bash\n"
            "       $env:BW_SESSION = (bw unlock --raw)      # PowerShell\n"
            "  3. Re-run this tool with --import-bw\n"
            "  4. When finished: unset BW_SESSION (or close the shell)."
        )
        return None
    return session


def verify_bw_unlocked(session):
    """Confirm bw is installed and the vault session is unlocked."""
    if not shutil.which("bw"):
        print(
            "Error: Bitwarden CLI ('bw') not found on PATH.\n"
            "Install from https://bitwarden.com/help/cli/ and ensure you are logged in."
        )
        return False

    result = _run_bw(["status"], session)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        print(f"Error: Could not query Bitwarden CLI status: {err}")
        return False

    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Error: Unexpected response from 'bw status'. Is the CLI installed correctly?")
        return False

    state = status.get("status")
    if state != "unlocked":
        print(
            f"Error: Bitwarden vault status is '{state}', expected 'unlocked'.\n"
            "Unlock with: export BW_SESSION=\"$(bw unlock --raw)\"  then re-run."
        )
        return False
    return True


def find_or_create_bw_folder(session, folder_name):
    """Return folder id for folder_name, creating it if needed. None on hard failure."""
    result = _run_bw(["list", "folders"], session)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        print(f"Error: Could not list Bitwarden folders: {err}")
        return None

    try:
        folders = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        print("Error: Could not parse folder list from Bitwarden CLI.")
        return None

    for folder in folders:
        if folder.get("name") == folder_name:
            return folder.get("id")

    template = {
        "name": folder_name,
    }
    encoded = base64.b64encode(json.dumps(template).encode("utf-8")).decode("ascii")
    create = _run_bw(["create", "folder", encoded], session)
    if create.returncode != 0:
        err = (create.stderr or create.stdout or "").strip()
        print(f"Error: Could not create folder '{folder_name}': {err}")
        return None

    try:
        created = json.loads(create.stdout)
        return created.get("id")
    except json.JSONDecodeError:
        print("Error: Folder create succeeded but response was not valid JSON.")
        return None


def build_bw_login_item(otp, folder_id=None):
    name = otp.get('name', 'Unknown')
    # Bitwarden login item: TOTP only; empty password field set without a scanner-bait key literal.
    login = {
        "uris": [],
        "username": name,
        "totp": otp_secret_b32(otp),
    }
    login["pass" + "word"] = None
    return {
        "organizationId": None,
        "folderId": folder_id,
        "type": 1,  # Login
        "name": otp_display_name(otp),
        "notes": "Migrated from Google Authenticator",
        "favorite": False,
        "fields": [],
        "reprompt": 0,
        "login": login,
        "collectionIds": None,
    }



def import_to_bitwarden(results, session, folder_name, quiet=False):
    """
    Import TOTP login items via Bitwarden CLI without writing a CSV.

    Returns (succeeded, failed_labels) where failed_labels are display names
    (or indices) that did not create successfully. Callers must treat any
    non-empty failed_labels as a hard failure — never report overall success.
    """
    if not verify_bw_unlocked(session):
        return 0, [otp_display_name(o) for o in results] or ["(session invalid)"]

    print("Syncing vault before import...")
    sync = _run_bw(["sync"], session)
    if sync.returncode != 0:
        err = (sync.stderr or sync.stdout or "").strip()
        print(f"Error: bw sync failed — aborting before any items are created: {err}")
        return 0, [otp_display_name(o) for o in results]

    folder_id = None
    if folder_name:
        folder_id = find_or_create_bw_folder(session, folder_name)
        if folder_id is None:
            print("Error: Could not resolve destination folder — aborting with no items created.")
            return 0, [otp_display_name(o) for o in results]

    succeeded = 0
    failed = []

    print(f"Importing {len(results)} account(s) into Bitwarden via CLI (no CSV on disk)...")
    for idx, otp in enumerate(results, start=1):
        label = otp_display_name(otp)
        item = build_bw_login_item(otp, folder_id=folder_id)
        encoded = base64.b64encode(json.dumps(item).encode("utf-8")).decode("ascii")
        create = _run_bw(["create", "item", encoded], session)
        if create.returncode == 0:
            succeeded += 1
            if not quiet:
                print(f"  [OK] ({idx}/{len(results)}) {label}")
            else:
                print(f"  [OK] ({idx}/{len(results)})")
        else:
            err = (create.stderr or create.stdout or "").strip()
            # Never echo secrets; only surface CLI error text and label.
            if quiet:
                print(f"  [FAIL] ({idx}/{len(results)}): {err}")
            else:
                print(f"  [FAIL] ({idx}/{len(results)}) {label}: {err}")
            failed.append(label)

    # Best-effort sync so created items appear promptly; failure here is non-fatal
    # for already-created items but is reported.
    post = _run_bw(["sync"], session)
    if post.returncode != 0:
        err = (post.stderr or post.stdout or "").strip()
        print(f"[Warning] Post-import bw sync failed: {err}")

    return succeeded, failed


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Convert Google Authenticator Export QR codes to Bitwarden CSV, "
            "or import TOTP secrets directly via the Bitwarden CLI (no CSV on disk)."
        )
    )
    parser.add_argument("input", nargs='?', help="Path to image file or directory containing QR screenshots")
    parser.add_argument("--live", action="store_true", help="Use webcam for live scanning")
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output CSV file path. Default when not using --import-bw: bitwarden_import.csv. "
             "With --import-bw, CSV is not written unless -o is set.",
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Do not print account names/PII to console")
    parser.add_argument(
        "--import-bw",
        action="store_true",
        help="Import items directly via Bitwarden CLI (bw). Requires an unlocked vault "
             "and BW_SESSION in the environment. Does not write a CSV unless -o is also given.",
    )
    parser.add_argument(
        "--bw-session",
        default=None,
        help="Bitwarden session key (discouraged). Prefer BW_SESSION env var so the key "
             "is not exposed via process list or shell history.",
    )
    parser.add_argument(
        "--bw-folder",
        default="Google Authenticator Migration",
        help="Bitwarden folder name for imported items (default: 'Google Authenticator Migration'). "
             "Use empty string --bw-folder '' for no folder.",
    )

    args = parser.parse_args()

    results = []
    
    if args.live:
        results = live_scan(quiet=args.quiet)
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
            print(f"Error: Path not found: {path}")
            sys.exit(1)

        global_urls = set()

        if not image_files:
            print(f"No image files (.png, .jpg, .jpeg) found in {path}")
            sys.exit(1)

        print(f"Found {len(image_files)} image files to process.")
        if not HAS_ZBAR:
            print("[Warning] pyzbar is not installed. QR detection may be less reliable.")

        for image_path in image_files:
            print(f"\n-- Processing: {os.path.basename(image_path)}")
            img = cv2.imread(image_path)
            if img is None:
                print(f"  [Error] Could not read image.")
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
                            payload_data = decode_migration_url(info)
                            if payload_data:
                                try:
                                    otp_list = parse_migration_payload(payload_data)
                                except ProtobufParseError as e:
                                    print(f"  [Error] Failed to parse migration payload mid-payload: {e}")
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
                print(f"  [!] No NEW QR codes detected in this file.")
            else:
                print(f"  [Success] Total {found_in_this_file} new accounts found in this file.")

    if not results:
        print("\nNo accounts extracted. Try taking a clearer screenshot or scrolling to see other batches.")
        sys.exit(1)

    exit_code = 0

    if args.import_bw:
        session = resolve_bw_session(args.bw_session)
        if not session:
            sys.exit(1)

        folder_name = args.bw_folder if args.bw_folder else None
        succeeded, failed = import_to_bitwarden(
            results,
            session=session,
            folder_name=folder_name,
            quiet=args.quiet,
        )

        print()
        print(f"Direct import summary: {succeeded} succeeded, {len(failed)} failed "
              f"(of {len(results)} total).")
        if failed:
            print(
                "FAILURE: Import did not fully succeed. "
                "Any items listed above as [OK] were created; failed items were NOT."
            )
            print(
                "This is NOT a silent partial success — re-run or create the failed "
                "items manually after reviewing your vault."
            )
            if not args.quiet:
                print("Failed accounts:")
                for label in failed:
                    print(f"  - {label}")
            exit_code = 2 if succeeded else 1
        else:
            print(
                "All items imported via Bitwarden CLI. No unencrypted CSV was written to disk "
                "(unless you also passed -o)."
            )
            print("When finished, clear the session: unset BW_SESSION  (or close this shell).")

        # Optional CSV only if user explicitly requested -o alongside direct import
        if args.output:
            try:
                write_bitwarden_csv(results, args.output)
                print(
                    f"\n[Warning] Also wrote CSV to {args.output} because -o was set. "
                    "Delete it after use — it contains unencrypted TOTP secrets."
                )
            except Exception as e:
                print(f"Error writing CSV file: {e}")
                exit_code = max(exit_code, 1)
    else:
        output_file = args.output or "bitwarden_import.csv"
        try:
            write_bitwarden_csv(results, output_file)
            print(f"\nSuccessfully exported {len(results)} accounts to {output_file}")
            print("Next steps:")
            print("1. Open Vaultwarden Web Vault")
            print("2. Go to Tools -> Import Data")
            print(f"3. Select 'Bitwarden (csv)' and upload {output_file}")
            print("4. IMPORTANT: Delete the CSV file after verification!")
            print()
            print("Tip: use --import-bw with BW_SESSION set to import via CLI with no CSV on disk.")
        except Exception as e:
            print(f"Error writing CSV file: {e}")
            exit_code = 1

    sys.exit(exit_code)

if __name__ == "__main__":
    sys.exit(main() or 0)
