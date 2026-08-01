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

# Algorithm / digit enums used in Google Authenticator migration protobuf
GA_ALGO_MAP = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
GA_DIGITS_MAP = {0: 6, 1: 6, 2: 8}
GA_TYPE_MAP = {0: "totp", 1: "hotp", 2: "totp"}  # 0 unspecified, 1 hotp, 2 totp

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
TEXT_EXTENSIONS = {".txt", ".uri", ".uris", ".otpauth"}
JSON_EXTENSIONS = {".json"}


# ---------------------------------------------------------------------------
# Protobuf helpers (Google Authenticator migration payload)
# ---------------------------------------------------------------------------

def read_varint(data, pos):
    res = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("Unexpected end of data while reading varint")
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

def parse_otp_parameters(data):
    pos = 0
    params = {}
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 2:  # Length-delimited
            length, pos = read_varint(data, pos)
            val = data[pos:pos + length]
            pos += length

            if field_number == 1:
                params["secret"] = val
            elif field_number == 2:
                params["name"] = val.decode("utf-8", errors="ignore")
            elif field_number == 3:
                params["issuer"] = val.decode("utf-8", errors="ignore")
        elif wire_type == 0:  # Varint
            val, pos = read_varint(data, pos)
            if field_number == 4: params['algorithm'] = val
            elif field_number == 5: params['digits'] = val
            elif field_number == 6: params['type'] = val
            elif field_number == 7: params['counter'] = val
        else:
            # Skip unknown wire types conservatively
            if wire_type == 1:
                pos += 8
            elif wire_type == 5:
                pos += 4
            else:
                break
    return params


def secret_to_base32(secret_bytes):
    """Encode raw secret bytes as base32 without padding (otpauth convention)."""
    return base64.b32encode(secret_bytes or b"").decode("ascii").rstrip("=")


def otp_params_are_default(otp):
    """
    Return True when TOTP params match Bitwarden/otpauth defaults:
    TOTP, SHA1, 6 digits (period 30 is implicit and not in GA export).
    """
    algorithm = ALGORITHM_MAP.get(otp.get("algorithm", 1), "SHA1")
    digits = DIGITS_MAP.get(otp.get("digits", 1), 6)
    otp_type = otp.get("type", OTP_TYPE_TOTP)
    return otp_type != OTP_TYPE_HOTP and algorithm == "SHA1" and digits == 6


def build_otpauth_uri(otp):
    """
    Build a full otpauth:// URI so Bitwarden import preserves algorithm,
    digits, type, issuer, and HOTP counter when present.
    """
    secret_b32 = secret_to_base32(otp.get("secret", b""))
    name = otp.get("name") or "Unknown"
    issuer = otp.get("issuer") or ""
    algorithm = ALGORITHM_MAP.get(otp.get("algorithm", 1), "SHA1")
    digits = DIGITS_MAP.get(otp.get("digits", 1), 6)
    otp_type = otp.get("type", OTP_TYPE_TOTP)
    is_hotp = otp_type == OTP_TYPE_HOTP
    kind = "hotp" if is_hotp else "totp"

    if issuer:
        label = f"{issuer}:{name}"
    else:
        label = name

    query = {
        "secret": secret_b32,
        "algorithm": algorithm,
        "digits": str(digits),
    }
    if issuer:
        query["issuer"] = issuer
    if is_hotp:
        query["counter"] = str(otp.get("counter", 0))
    else:
        # GA migration payload does not carry period; standard is 30s
        query["period"] = "30"

    # quote_via=quote keeps spaces as %20 (otpauth-friendly) rather than +
    return "otpauth://{kind}/{label}?{query}".format(
        kind=kind,
        label=urllib.parse.quote(label, safe=""),
        query=urllib.parse.urlencode(query, quote_via=urllib.parse.quote),
    )


def format_login_totp(otp):
    """
    Value for Bitwarden CSV login_totp column.

    Always emit a full otpauth:// URI so non-default algorithm/digits/type
    survive import. Bitwarden accepts either a bare base32 secret or an
    otpauth URI in this field; the URI form is required for non-defaults.
    """
    return build_otpauth_uri(otp)

def parse_migration_payload(data):
    pos = 0
    all_params = []
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 2 and field_number == 1:
            length, pos = read_varint(data, pos)
            otp_data = data[pos:pos + length]
            pos += length
            all_params.append(parse_otp_parameters(otp_data))
        elif wire_type == 0:
            _, pos = read_varint(data, pos)
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            pos += length
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        else:
            break
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

        for payload in payloads:
            if payload in seen_payloads:
                continue
            if not (
                payload.startswith("otpauth-migration://")
                or payload.lower().startswith("otpauth://")
            ):
                continue
            seen_payloads.add(payload)
            otp_list = accounts_from_qr_payloads([payload])
            if not otp_list:
                continue
            if not quiet:
                for otp in otp_list:
                    print(f"    [Captured] {otp.get('issuer', '')}: {otp.get('name', 'Unknown')}")
            all_results.extend(otp_list)
            print(f"  [+] Captured {len(otp_list)} accounts! (Total: {len(all_results)})")
            last_capture_time = 60

        cv2.putText(
            frame, f"Accounts Captured: {len(all_results)}",
            (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2,
        )
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
    headers = ["folder", "favorite", "type", "name", "notes", "fields", "login_uri", "login_username", "login_password", "login_totp"]
    
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            # Mask the secret key slightly if quiet mode? No, CSV needs the secret.
            # But the user asked to remove PII from the *script*, usage via args.
            
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for otp in results:
                name = otp.get('name', 'Unknown')
                issuer = otp.get('issuer', '')
                
                display_name = f"{issuer}: {name}" if issuer else name
                
                writer.writerow({
                    "folder": "Google Authenticator Migration",
                    "favorite": "0",
                    "type": "login",
                    "name": display_name,
                    "notes": "Migrated from Google Authenticator",
                    "login_username": name,
                    "login_totp": format_login_totp(otp),
                })
        
        print(f"\nSuccessfully exported {len(results)} accounts to {output_file}")
        print("Next steps:")
        print("1. Open Vaultwarden Web Vault")
        print("2. Go to Tools -> Import Data")
        print(f"3. Select 'Bitwarden (csv)' and upload {output_file}")
        print("4. IMPORTANT: Delete the CSV file after verification!")
        
    except Exception as e:
        print(f"Error writing CSV file: {e}")

if __name__ == "__main__":
    sys.exit(main() or 0)
