# Bitwarden MFA Auth Migrator

A Python tool to migrate TOTP/HOTP secrets from common authenticator apps into a Bitwarden/Vaultwarden-compatible CSV.

## Features

- **Google Authenticator export QR**: Screenshots or live webcam scan of migration QR codes.
- **Standard `otpauth://` URIs**: Text files (or QR codes) containing one or more otpauth URIs.
- **Aegis Authenticator**: Unencrypted Aegis JSON exports.
- **Authy (community exports)**: Decrypted Authy JSON produced by common export tools.
- **Robust QR parsing**: Uses `pyzbar` and image enhancement for dense/blurry codes.
- **Secure**: Runs locally. Suppress console PII with `--quiet`.

## Prerequisites

- Python 3.x
- Dependencies:

  ```bash
  pip install -r requirements.txt
  ```
- For **direct import** (`--import-bw`): [Bitwarden CLI](https://bitwarden.com/help/cli/) (`bw`) installed, logged in, and unlocked. Works with Bitwarden cloud or a self-hosted/Vaultwarden server configured via `bw config server`.

  On some systems `pyzbar` also needs the system ZBar library (e.g. `zbar` / `libzbar0`).

## Supported source formats

### 1. Google Authenticator (migration QR)

1. In Google Authenticator: **Transfer accounts → Export accounts**.
2. Screenshot each QR (or use `--live` webcam mode).

```bash
python ga_to_bitwarden.py path\to\screenshots\
python ga_to_bitwarden.py --live
```

### 2. Standard `otpauth://` URIs

Many apps (FreeOTP, andOTP export-as-URI, Authy after conversion, password managers, etc.) can produce [Key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) lines:

```
otpauth://totp/Example:user@example.com?secret=EXAMPLENOTREALAA&issuer=Example
```

Save one URI per line in a `.txt` file (comments starting with non-URI text are fine):

```bash
python ga_to_bitwarden.py my_uris.txt
python ga_to_bitwarden.py my_uris.txt --format otpauth
```

QR images that encode a single `otpauth://…` payload are also accepted (same image pipeline as GA).

### 3. Aegis Authenticator (JSON)

1. Aegis → **Settings → Import & Export → Export**.
2. Choose **JSON** and leave **encryption disabled** (this tool does not decrypt Aegis vaults).
3. Import the file:

```bash
python ga_to_bitwarden.py aegis-export.json
python ga_to_bitwarden.py aegis-export.json --format aegis
```

Encrypted exports (`header.slots` present) are rejected with a clear error—re-export without a password.

### 4. Authy (decrypted community JSON)

Authy has no official plaintext export. After using a **local** decrypting export tool (for example community `authy-export` utilities), feed the resulting JSON here.

Accepted shapes:

```json
{
  "authenticator_tokens": [
    {
      "name": "alice@example.com",
      "issuer": "Example",
      "decrypted_seed": "EXAMPLENOTREALAA",
      "digits": 6
    }
  ]
}
```

or a bare array of `{ "name", "secret"|"seed"|"decrypted_seed", "issuer"?, "digits"? }` objects:

```bash
python ga_to_bitwarden.py authy-decrypted.json
python ga_to_bitwarden.py authy-decrypted.json --format authy
```

Tokens that only contain `encrypted_seed` (no plaintext secret) are skipped; if none are usable, the tool errors.

> Prefer converting Authy output to `otpauth://` lines if your export tool supports that—the otpauth path is the most portable.

## Usage (CLI)

```bash
python ga_to_bitwarden.py <input> [--format auto|qr|ga|otpauth|aegis|authy] [-o out.csv] [-q]
python ga_to_bitwarden.py --live [-o out.csv] [-q]
```

| Option | Description |
|--------|-------------|
| `input` | Image, `.txt` URI list, `.json` export, or a directory of such files |
| `--format`, `-f` | Force format (`auto` sniffs extension + content) |
| `--live` | Webcam QR scanning (GA migration + otpauth QRs) |
| `--output`, `-o` | Output CSV path (default: `bitwarden_import.csv`) |
| `--quiet`, `-q` | Do not print account names to the console |

Example:

```bash
python ga_to_bitwarden.py C:\exports\ --output my_codes.csv --quiet
```

## Importing to Bitwarden / Vaultwarden

### Preferred: direct CLI (no residual secret file)

See [Direct Bitwarden CLI import](#3-direct-bitwarden-cli-import-no-csv-on-disk) above. Secrets stay in memory and the vault; nothing is left on disk for you to remember to delete.

### Alternative: CSV import

1. Log in to your Web Vault.
2. Go to **Tools → Import Data**.
3. Select **Bitwarden (csv)** as the file format.
4. Upload the generated CSV file.
5. **Delete the CSV** after verifying codes work.

## Tests

Fixture data under `tests/fixtures/` uses only public demo secrets (not real credentials):

```bash
python -m unittest discover -s tests -v
```

## ⚠️ Security Warning

The generated CSV contains your **unencrypted 2FA secrets**.
**Delete the CSV immediately** after a successful import. Prefer `--quiet` on shared machines, and never commit real export files.
