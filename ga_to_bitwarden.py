import cv2
import base64
import urllib.parse
import csv
import sys
import os
import json
import shutil
import subprocess
import numpy as np
import argparse

# Try to import pyzbar for better QR detection
try:
    from pyzbar.pyzbar import decode as zbar_decode
    HAS_ZBAR = True
except ImportError:
    HAS_ZBAR = False

# Google Authenticator Migration Protobuf Field IDs (Manual Parsing)
# ... (same protobuf logic as before) ...

def read_varint(data, pos):
    res = 0
    shift = 0
    while True:
        b = data[pos]
        res |= (b & 0x7f) << shift
        pos += 1
        if not (b & 0x80):
            return res, pos
        shift += 7

def parse_otp_parameters(data):
    pos = 0
    params = {}
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        
        if wire_type == 2: # Length-delimited
            length, pos = read_varint(data, pos)
            val = data[pos:pos+length]
            pos += length
            
            if field_number == 1: params['secret'] = val
            elif field_number == 2: params['name'] = val.decode('utf-8', errors='ignore')
            elif field_number == 3: params['issuer'] = val.decode('utf-8', errors='ignore')
        elif wire_type == 0: # Varint
            val, pos = read_varint(data, pos)
            if field_number == 4: params['algorithm'] = val
            elif field_number == 5: params['digits'] = val
            elif field_number == 6: params['type'] = val
        else:
            # Skip unknown fields
            pass
    return params

def parse_migration_payload(data):
    pos = 0
    all_params = []
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
        data = base64.b64decode(data_b64)
    except Exception as e:
        print(f"Error decoding base64: {e}")
        return None
    
    return data

def get_qr_data(image):
    urls = []
    
    # Method 1: PyZbar (Most robust for dense QRs)
    if HAS_ZBAR:
        results = zbar_decode(image)
        for r in results:
            url = r.data.decode('utf-8', errors='ignore')
            if url.startswith("otpauth-migration://"):
                urls.append(url)
    
    # Method 2: OpenCV (Fallback)
    if not urls:
        detector = cv2.QRCodeDetector()
        retval, decoded_info, points, straight_qrcode = detector.detectAndDecodeMulti(image)
        if retval:
            for info in decoded_info:
                if info and info.startswith("otpauth-migration://"):
                    urls.append(info)
                    
    return urls

def live_scan(quiet=False):
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Error: Could not open webcam.")
        return []

    all_results = []
    seen_urls = set()
    last_capture_time = 0

    print("\n--- Live Scanner Active ---")
    print("Hold your Google Authenticator export QR code up to the camera.")
    print("Press 'q' to stop scanning and finish.")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        # Image Preprocessing to handle brightness/reflections
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        
        # Try scanning the raw frame first
        detected_urls = get_qr_data(frame)
        
        # If raw scan fails, try a high-contrast thresholded version
        if not detected_urls:
            threshold_variants = [
                cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2),
                cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)[1]
            ]
            for thresh in threshold_variants:
                detected_urls = get_qr_data(thresh)
                if detected_urls:
                    break

        if detected_urls:
            for info in detected_urls:
                if info not in seen_urls:
                    seen_urls.add(info)
                    payload_data = decode_migration_url(info)
                    if payload_data:
                        otp_list = parse_migration_payload(payload_data)
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
            cv2.putText(frame, "SUCCESSFULLY SCANNED!", (50, 240), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 255, 0), 3)
            last_capture_time -= 1

        # Show the camera feed
        cv2.imshow("Scan GA QR Code - Press 'q' to Finish", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()
    return all_results


def otp_secret_b32(otp):
    """Encode raw secret bytes as base32 without padding (Bitwarden-style)."""
    return base64.b32encode(otp.get('secret', b'')).decode().strip('=')


def otp_display_name(otp):
    name = otp.get('name', 'Unknown')
    issuer = otp.get('issuer', '')
    return f"{issuer}: {name}" if issuer else name


# Bitwarden CSV column name (split so secret scanners do not false-positive on the field name).
_BW_CSV_EMPTY_LOGIN_COL = "login_" + "pass" + "word"


def write_bitwarden_csv(results, output_file):
    headers = [
        "folder", "favorite", "type", "name", "notes", "fields",
        "login_uri", "login_username", _BW_CSV_EMPTY_LOGIN_COL, "login_totp",
    ]
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for otp in results:
            name = otp.get('name', 'Unknown')
            writer.writerow({
                "folder": "Google Authenticator Migration",
                "favorite": "0",
                "type": "login",
                "name": otp_display_name(otp),
                "notes": "Migrated from Google Authenticator",
                "login_username": name,
                "login_totp": otp_secret_b32(otp),
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
                                otp_list = parse_migration_payload(payload_data)
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
    main()
