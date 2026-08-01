# Bitwarden MFA Auth Migrator

A Python tool to migrate Google Authenticator TOTP codes to Bitwarden/Vaultwarden — either as a compatible CSV, or **directly via the Bitwarden CLI with no unencrypted CSV on disk**.

## Features

- **Decode Export QR Codes**: Reads screenshots of Google Authenticator export QR codes.
- **Webcam Support**: Live scanning of QR codes directly from your phone screen.
- **Robust Parsing**: Uses `pyzbar` and advanced image enhancement to read dense/blurry QR codes.
- **Direct CLI import**: Push login+TOTP items straight into an unlocked vault with `--import-bw` (no residual secret file by default).
- **Secure**: Runs locally. Can suppress PII output with `--quiet`. Session keys are read from the environment, not written to disk.

## Prerequisites

- Python 3.x
- Dependencies:
  ```bash
  pip install -r requirements.txt
  ```
- For **direct import** (`--import-bw`): [Bitwarden CLI](https://bitwarden.com/help/cli/) (`bw`) installed, logged in, and unlocked. Works with Bitwarden cloud or a self-hosted/Vaultwarden server configured via `bw config server`.

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

### 3. Direct Bitwarden CLI import (no CSV on disk)

Import TOTP secrets straight into your vault using the official `bw` CLI. By default **no CSV is written**, so unencrypted secrets never land on disk as a residual file.

```bash
# Unlock once; keep the session only in the environment (preferred — not argv / history).
# bash:
export BW_SESSION="$(bw unlock --raw)"
# PowerShell:
#   $env:BW_SESSION = (bw unlock --raw)

python ga_to_bitwarden.py C:\path\to\screenshots\ --import-bw
# or live:
python ga_to_bitwarden.py --live --import-bw --quiet

# When finished, clear the session from the shell:
unset BW_SESSION          # bash
# Remove-Item Env:BW_SESSION   # PowerShell
```

**Secure session handling**

| Approach | Recommendation |
|---|---|
| `BW_SESSION` environment variable | **Preferred.** Not passed on argv; clear when done. |
| `--bw-session <key>` | Supported but **discouraged** (visible in process list / shell history). |

The tool never writes `BW_SESSION` or TOTP secrets to log files. Account labels are only printed if you omit `--quiet`.

**Failure handling**

- If the vault is locked, `bw` is missing, or `bw sync` fails **before** creates, the tool aborts with a non-zero exit and **creates no items**.
- If some item creates fail mid-run, the summary reports exact success/failure counts and lists failed accounts (unless `--quiet`). Exit code is non-zero (`2` for partial, `1` for total failure). Already-created items remain in the vault — there is **no silent partial success**.

Optional flags for direct import:

- `--bw-folder "My Folder"` — destination folder (default: `Google Authenticator Migration`). Use `--bw-folder ""` for no folder.
- `-o path.csv` — also write a CSV **only if you explicitly request it** (not recommended; delete immediately).

### 4. Options

- `--output`, `-o`: Specify output CSV filename. Default without `--import-bw`: `bitwarden_import.csv`. With `--import-bw`, omitted unless you set `-o`.
- `--quiet`, `-q`: Suppress printing account names to the console (useful for privacy).
- `--import-bw`: Direct vault import via Bitwarden CLI (see above).
- `--bw-session`: Session key override (prefer `BW_SESSION` env instead).
- `--bw-folder`: Folder name for imported items.

```bash
python ga_to_bitwarden.py C:\screenshots\ --output my_codes.csv --quiet
python ga_to_bitwarden.py C:\screenshots\ --import-bw --quiet
```

## Importing to Bitwarden / Vaultwarden

### Preferred: direct CLI (no residual secret file)

See [Direct Bitwarden CLI import](#3-direct-bitwarden-cli-import-no-csv-on-disk) above. Secrets stay in memory and the vault; nothing is left on disk for you to remember to delete.

### Alternative: CSV import

1. Log in to your Web Vault.
2. Go to **Tools** -> **Import Data**.
3. Select **Bitwarden (csv)** as the file format.
4. Upload the generated CSV file.
5. **Delete the CSV immediately** after a successful import.

## ⚠️ Security Warning

- **CSV mode**: The generated CSV contains your **unencrypted 2FA secrets**. Delete it immediately after a successful import. Prefer `--import-bw` when possible so no residual secret file is created.
- **Direct import**: Keep `BW_SESSION` only in your current shell environment; never commit it, never write it to a file, and clear it when done. Anyone with a live session key can access your vault via the CLI.
- Screenshots of Google Authenticator export QR codes also contain secrets — delete those after migration as well.
