import cv2
import base64
import urllib.parse
import csv
import sys
import os
import struct
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
    print("Press 'q' to stop scanning and generate the CSV.")

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

def main():
    parser = argparse.ArgumentParser(description="Convert Google Authenticator Export QR codes to Bitwarden CSV.")
    parser.add_argument("input", nargs='?', help="Path to image file or directory containing QR screenshots")
    parser.add_argument("--live", action="store_true", help="Use webcam for live scanning")
    parser.add_argument("--output", "-o", default="bitwarden_import.csv", help="Output CSV file path (default: bitwarden_import.csv)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Do not print account names/PII to console")
    
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
            return

        global_urls = set()

        if not image_files:
            print(f"No image files (.png, .jpg, .jpeg) found in {path}")
            return

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
        return

    output_file = args.output
    headers = ["folder", "favorite", "type", "name", "notes", "fields", "login_uri", "login_username", "login_password", "login_totp"]
    
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            # Mask the secret key slightly if quiet mode? No, CSV needs the secret.
            # But the user asked to remove PII from the *script*, usage via args.
            
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for otp in results:
                secret_b32 = base64.b32encode(otp.get('secret', b'')).decode().strip('=')
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
                    "login_totp": secret_b32
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
    main()
