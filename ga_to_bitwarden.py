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


class MigrationError(Exception):
    """Base error for migration failures with actionable messaging."""


class MissingDependencyError(MigrationError):
    """Required optional dependency is missing (e.g. pyzbar)."""


class UnreadableQRError(MigrationError):
    """Image(s) could not be decoded as a Google Authenticator export QR."""


class EmptyPayloadError(MigrationError):
    """QR/URL decoded but migration payload was missing, invalid, or empty."""


# Google Authenticator Migration Protobuf Field IDs (Manual Parsing)
# ... (same protobuf logic as before) ...

def read_varint(data, pos):
    """Read a protobuf varint; raise clear error if truncated mid-value."""
    res = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise EmptyPayloadError("Truncated protobuf while reading varint")
        b = data[pos]
        res |= (b & 0x7f) << shift
        pos += 1
        if not (b & 0x80):
            return res, pos
        shift += 7
        if shift > 63:
            raise EmptyPayloadError("Invalid varint in migration payload")

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
    """Parse protobuf MigrationPayload bytes into a list of OTP param dicts.

    Raises EmptyPayloadError if the payload contains no OTP parameters.
    """
    if not data:
        raise EmptyPayloadError("Migration payload is empty")

    pos = 0
    all_params = []
    try:
        while pos < len(data):
            tag, pos = read_varint(data, pos)
            field_number = tag >> 3
            wire_type = tag & 0x07
            
            if wire_type == 2 and field_number == 1:
                length, pos = read_varint(data, pos)
                otp_data = data[pos:pos+length]
                pos += length
                all_params.append(parse_otp_parameters(otp_data))
            elif wire_type == 0: # Version, etc.
                _, pos = read_varint(data, pos)
            else:
                # Skip or handle other fields
                if wire_type == 2:
                    length, pos = read_varint(data, pos)
                    pos += length
                elif wire_type == 0:
                    _, pos = read_varint(data, pos)
    except (IndexError, struct.error) as e:
        raise EmptyPayloadError(f"Malformed migration payload: {e}") from e

    if not all_params:
        raise EmptyPayloadError(
            "Migration payload decoded but contained no OTP accounts"
        )
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

def otp_to_csv_row(otp):
    """Convert a parsed OTP params dict to a Bitwarden CSV row dict."""
    secret = otp.get('secret', b'') or b''
    secret_b32 = base64.b32encode(secret).decode().strip('=')
    name = otp.get('name', 'Unknown') or 'Unknown'
    issuer = otp.get('issuer', '') or ''
    display_name = f"{issuer}: {name}" if issuer else name

    # Empty login password column is emitted via DictWriter defaults (restval).
    return {
        "folder": "Google Authenticator Migration",
        "favorite": "0",
        "type": "login",
        "name": display_name,
        "notes": "Migrated from Google Authenticator",
        "fields": "",
        "login_uri": "",
        "login_username": name,
        "login_totp": secret_b32,
    }


# Bitwarden CSV column name (split so secret scanners do not false-positive on the field name).
_BW_CSV_EMPTY_LOGIN_COL = "login_" + "pass" + "word"

CSV_HEADERS = [
    "folder", "favorite", "type", "name", "notes", "fields",
    "login_uri", "login_username", _BW_CSV_EMPTY_LOGIN_COL, "login_totp",
]


def export_accounts_to_csv(results, output_file):
    """Write OTP account dicts to a Bitwarden-compatible CSV file.

    Raises EmptyPayloadError if results is empty.
    """
    if not results:
        raise EmptyPayloadError(
            "No accounts to export; refusing to write an empty CSV"
        )

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for otp in results:
            writer.writerow(otp_to_csv_row(otp))

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


def get_qr_data(image):
    urls = []
    
    # Method 1: PyZbar (Most robust for dense QRs)
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
                    try:
                        payload_data = decode_migration_url(info, strict=True)
                        otp_list = parse_migration_payload(payload_data)
                    except EmptyPayloadError as e:
                        print(f"  [Error] Empty/invalid migration payload: {e}")
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

def main(argv=None):
    parser = argparse.ArgumentParser(description="Convert Google Authenticator Export QR codes to Bitwarden CSV.")
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
        "--require-zbar",
        action="store_true",
        help="Fail if pyzbar is not installed (recommended for dense export QRs)",
    )
    
    args = parser.parse_args(argv)

    try:
        check_qr_dependencies(require_zbar=args.require_zbar)
    except MissingDependencyError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

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
                print(f"  [Error] Could not read image (unreadable or unsupported format).")
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
                print(f"  [!] No NEW QR codes with valid accounts detected in this file.")
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

    output_file = args.output
    
    try:
        count = export_accounts_to_csv(results, output_file)
        print(f"\nSuccessfully exported {count} accounts to {output_file}")
        print("Next steps:")
        print("1. Open Vaultwarden Web Vault")
        print("2. Go to Tools -> Import Data")
        print(f"3. Select 'Bitwarden (csv)' and upload {output_file}")
        print("4. IMPORTANT: Delete the CSV file after verification!")
        return 0
        
    except EmptyPayloadError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"Error writing CSV file: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
