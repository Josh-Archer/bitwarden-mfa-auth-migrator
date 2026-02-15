# Bitwarden MFA Auth Migrator

A Python tool to migrate Google Authenticator TOTP codes to a Bitwarden/Vaultwarden compatible CSV format.

## Features

- **Decode Export QR Codes**: Reads screenshots of Google Authenticator export QR codes.
- **Webcam Support**: Live scanning of QR codes directly from your phone screen.
- **Robust Parsing**: Uses `pyzbar` and advanced image enhancement to read dense/blurry QR codes.
- **Secure**: Runs locally. Can suppress PII output with `--quiet`.

## Prerequisites

- Python 3.x
- Dependencies:
  ```bash
  pip install -r requirements.txt
  ```

## Usage

### 1. File Mode (Screenshots)
Take screenshots of your Google Authenticator export QR codes and save them to a folder.

```bash
# Scan a single image
python ga_to_bitwarden.py my_qr_code.png

# Scan a directory of images
python ga_to_bitwarden.py C:\path\to\screenshots\
```

### 2. Live Webcam Mode
Hold your phone up to your computer's webcam.

```bash
python ga_to_bitwarden.py --live
```

### 3. Options

- `--output`, `-o`: Specify output CSV filename (default: `bitwarden_import.csv`).
- `--quiet`, `-q`: Suppress printing account names to the console (useful for privacy).

```bash
python ga_to_bitwarden.py C:\screenshots\ --output my_codes.csv --quiet
```

## Importing to Bitwarden / Vaultwarden

1. Log in to your Web Vault.
2. Go to **Tools** -> **Import Data**.
3. Select **Bitwarden (csv)** as the file format.
4. Upload the generated CSV file.

## ⚠️ Security Warning

The generated CSV file contains your **unencrypted 2FA secrets**. 
**Delete the CSV file immediately** after successfully importing it into your vault!
