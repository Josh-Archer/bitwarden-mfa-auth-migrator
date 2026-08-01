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
- `--require-zbar`: Fail immediately if pyzbar is not installed (recommended for dense export QRs).

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

### Exit codes / errors

When no accounts are exported, the tool reports a **distinct** error instead of a silent empty file:

| Situation | Error type | Typical exit code |
|-----------|------------|-------------------|
| pyzbar missing and no QR decoded | `MissingDependencyError` | 2 |
| Images/QR unreadable | `UnreadableQRError` | 1 |
| QR found but payload empty/invalid | `EmptyPayloadError` | 3 |

The tool also refuses to write an empty CSV.

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

### TOTP field format (`login_totp`)

Bitwarden’s CSV importer accepts either a bare base32 secret or a full
[`otpauth://`](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) URI
in the `login_totp` column.

This tool **always writes a full `otpauth://` URI**, including:

| Parameter   | Source / default |
|-------------|------------------|
| `secret`    | Exported secret (base32, unpadded) |
| `issuer`    | Account issuer when present |
| `algorithm` | SHA1 / SHA256 / SHA512 / MD5 (from export) |
| `digits`    | 6 or 8 (from export) |
| `period`    | `30` (Google Authenticator standard; not in export payload) |
| `counter`   | HOTP only (from export when present) |

Writing the full URI ensures non-default algorithms and digit counts survive
import. A bare secret alone would force Bitwarden’s defaults (SHA1, 6 digits)
and break those accounts.

## ⚠️ Security Warning

The generated CSV contains your **unencrypted 2FA secrets**.
**Delete the CSV immediately** after a successful import. Prefer `--quiet` on shared machines, and never commit real export files.
