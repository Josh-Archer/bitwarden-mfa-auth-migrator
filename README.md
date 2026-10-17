# Bitwarden MFA Auth Migrator

A Python tool to migrate TOTP/HOTP secrets from common authenticator apps into a Bitwarden/Vaultwarden-compatible CSV.

## Features

- **Decode Export QR Codes**: Reads screenshots of Google Authenticator export QR codes.
- **Webcam Support**: Live scanning of QR codes directly from your phone screen.
- **Robust Parsing**: Uses `pyzbar` and advanced image enhancement to read dense/blurry QR codes.
- **Secure**: Runs locally. Can suppress PII output with `--quiet`.
- **Full TOTP params**: Exports `otpauth://` URIs preserving algorithm (SHA1/SHA256/SHA512), digits (6/8), type (TOTP/HOTP), and HOTP counter—not secret-only defaults.

## Prerequisites

- Python 3.x
- Dependencies:

  ```bash
  pip install -r requirements.txt
  ```
- For best QR detection, install **pyzbar** (already listed in `requirements.txt`) and the system `libzbar` library. Without pyzbar, dense Google Authenticator export QRs often fail to decode.

## Development / Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

CI runs the same unit suite on pull requests (see `.github/workflows/ci.yml`).

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

The tool writes a Bitwarden-compatible CSV locally; it does not connect to a vault. By default the file is `bitwarden_import.csv`. `--output` and `--bw-folder` let you choose the CSV path and destination folder. Account labels are only printed if you omit `--quiet`.

## Usage (CLI)

```bash
python ga_to_bitwarden.py <input> [--format auto|qr|ga|otpauth|aegis|authy] [-o out.csv] [--bw-folder NAME] [-q]
python ga_to_bitwarden.py --live [-o out.csv] [--bw-folder NAME] [-q]
```

| Option | Description |
|--------|-------------|
| `input` | Image, plain `otpauth://` URI list, unencrypted Aegis JSON, decrypted Authy JSON, or a directory of supported files |
| `--format`, `-f` | Force format (`auto` sniffs extension + content) |
| `--live` | Webcam QR scanning (GA migration + otpauth QRs) |
| `--output`, `-o` | Output CSV path (default: `bitwarden_import.csv`) |
| `--bw-folder` | Folder column for every row. Defaults to a source-specific folder. Pass `""` for a blank folder. |
| `--quiet`, `-q` | Do not print account names to the console |

Example:

```bash
python ga_to_bitwarden.py C:\exports\ --output my_codes.csv --quiet
```

### Exit codes / errors

When no accounts are exported, the tool reports a **distinct** error instead of a silent empty file:

| Situation | Error type | Typical exit code |
|-----------|------------|-------------------|
| pyzbar missing and no QR decoded | `MissingDependencyError` | 2 |
| Images/QR unreadable | `UnreadableQRError` | 1 |
| QR found but payload empty/invalid | `EmptyPayloadError` | 3 |

The tool also refuses to write an empty CSV.

## Importing to Bitwarden / Vaultwarden

1. Log in to your Web Vault.
2. Go to **Tools → Import Data**.
3. Select **Bitwarden (csv)** as the file format.
4. Upload the generated CSV file.
5. **Delete the CSV** after verifying codes work.

## Tests

Fixture data under `tests/fixtures/` uses fake placeholder secrets only (not real credentials):

```bash
python -m unittest discover -s tests -v
```

### TOTP field format (`login_totp`)

Bitwarden’s CSV importer accepts either a bare base32 secret or a full
[`otpauth://`](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) URI
in the `login_totp` column.

The `login_totp` field contains a full `otpauth://` URI when non-default settings
need to be preserved (including every HOTP entry). TOTP entries with standard
defaults use the bare base32 secret. URI parameters include:

| Parameter   | Source / default |
|-------------|------------------|
| `secret`    | Exported secret (base32, unpadded) |
| `issuer`    | Account issuer when present |
| `algorithm` | SHA1 / SHA256 / SHA512 / MD5 (from export) |
| `digits`    | 6 or 8 (from export) |
| `period`    | TOTP period, default `30` (not applicable to HOTP) |
| `counter`   | HOTP only (from export when present) |

Writing the full URI ensures non-default algorithms and digit counts survive
import. A bare secret alone would force Bitwarden’s defaults (SHA1, 6 digits)
and break those accounts.

The same values are also kept as their own CSV columns — `issuer`, `algorithm`,
`digits`, `period`, and `counter` — so they are not dropped when a row is
written. Bitwarden’s importer reads TOTP settings from `login_totp` and ignores
the extra columns. The `folder` column is `Google Authenticator Migration`
unless you pass `--bw-folder`.

## ⚠️ Security Warning

The generated CSV contains your **unencrypted 2FA secrets**.
**Delete the CSV immediately** after a successful import. Prefer `--quiet` on shared machines, and never commit real export files.
