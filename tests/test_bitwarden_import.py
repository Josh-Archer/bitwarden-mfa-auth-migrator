"""Direct Bitwarden import tests use mocked CLI calls and synthetic secrets."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import ga_to_bitwarden as m

FAKE_SECRET = "EXAMPLENOTREALAA"
FAKE_SESSION = "fake-session-key-never-for-a-vault"


def fake_process(*, existing_folders=None, fail_item_number=None):
    """Return a subprocess.run mock that emulates bw without network access."""
    existing_folders = existing_folders or []
    created_items = []
    created_folders = []
    calls = []

    def run(argv, *, input=None, text=None, capture_output=None, check=None):
        calls.append((argv, input))
        command = argv[1:]
        if command == ["status"]:
            stdout = json.dumps({"status": "unlocked"})
        elif command == ["sync"]:
            stdout = ""
        elif command == ["list", "folders"]:
            stdout = json.dumps(existing_folders)
        elif command == ["get", "template", "folder"]:
            stdout = json.dumps({"object": "folder", "id": None, "name": ""})
        elif command == ["get", "template", "item"]:
            stdout = json.dumps({
                "object": "item", "type": 1, "name": "", "notes": "",
                "favorite": False, "folderId": None, "fields": [],
                "login": {"username": "", "password": None, "totp": None, "uris": []},
            })
        elif command == ["encode"]:
            encoded = base64.b64encode(input.encode("utf-8")).decode("ascii")
            stdout = encoded
        elif command == ["create", "folder"]:
            folder = json.loads(base64.b64decode(input).decode("utf-8"))
            folder.update(id="fake-folder-id")
            created_folders.append(folder)
            stdout = json.dumps(folder)
        elif command == ["create", "item"]:
            item = json.loads(base64.b64decode(input).decode("utf-8"))
            created_items.append(item)
            if fail_item_number == len(created_items):
                return mock.Mock(returncode=1, stdout="", stderr="SECRET LEAK SENTINEL")
            item.update(id=f"fake-item-{len(created_items)}")
            stdout = json.dumps(item)
        else:
            raise AssertionError(f"Unexpected mocked bw command: {command}")
        return mock.Mock(returncode=0, stdout=stdout, stderr="")

    return mock.Mock(side_effect=run), calls, created_items, created_folders


def sample_account(name="fixture-user", **kwargs):
    values = {
        "secret": FAKE_SECRET,
        "name": name,
        "issuer": "Example Service",
        "algorithm": "SHA256",
        "digits": 8,
        "period": 60,
        "source": "aegis",
        "notes": "Synthetic fixture only",
    }
    values.update(kwargs)
    return m.make_account(**values)


class TestDirectBitwardenImport(unittest.TestCase):
    def setUp(self):
        self.which = mock.patch("ga_to_bitwarden.shutil.which", return_value="/mock/bw")
        self.run_patch = mock.patch("ga_to_bitwarden.subprocess.run")
        self.which.start()
        self.addCleanup(self.which.stop)
        self.run_mock = self.run_patch.start()
        self.addCleanup(self.run_patch.stop)
        self.env = mock.patch.dict(os.environ, {"BW_SESSION": FAKE_SESSION})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_creates_folder_and_login_item_using_stdin(self):
        process, calls, items, folders = fake_process()
        self.run_mock.side_effect = process.side_effect

        created, failed = m.import_accounts_to_bitwarden([sample_account()])

        self.assertEqual((created, failed), (1, []))
        self.assertEqual([folder["name"] for folder in folders], ["Aegis Migration"])
        item = items[0]
        self.assertEqual(item["folderId"], "fake-folder-id")
        self.assertEqual(item["name"], "Example Service: fixture-user")
        self.assertEqual(item["login"]["username"], "fixture-user")
        self.assertIn("algorithm=SHA256", item["login"]["totp"])
        self.assertEqual(item["notes"], "Synthetic fixture only")
        for argv, _input in calls:
            self.assertNotIn(FAKE_SESSION, " ".join(argv))
            self.assertEqual(argv[0], "/mock/bw")

    def test_uses_existing_folder_and_honors_blank_folder(self):
        existing, _calls, _items, folders = fake_process(
            existing_folders=[{"id": "existing-id", "name": "Vault"}]
        )
        self.run_mock.side_effect = existing.side_effect
        created, failed = m.import_accounts_to_bitwarden([sample_account()], folder="Vault")
        self.assertEqual((created, failed), (1, []))
        self.assertEqual(folders, [])

        blank, _calls, items, folders = fake_process()
        self.run_mock.side_effect = blank.side_effect
        created, failed = m.import_accounts_to_bitwarden([sample_account()], folder="")
        self.assertEqual((created, failed), (1, []))
        self.assertEqual(folders, [])
        self.assertIsNone(items[0]["folderId"])

    def test_dry_run_never_invokes_cli_or_reads_session(self):
        self.env.stop()
        with mock.patch.dict(os.environ, {}, clear=True):
            result = m.import_accounts_to_bitwarden([sample_account()], dry_run=True)
        self.assertEqual(result, (0, []))
        self.run_mock.assert_not_called()

    def test_invalid_secret_is_rejected_before_any_cli_call(self):
        account = sample_account()
        account["secret"] = b""

        with self.assertRaisesRegex(ValueError, "secret is empty"):
            m.import_accounts_to_bitwarden([account])

        self.run_mock.assert_not_called()

    def test_unlocked_status_failure_has_no_item_creates(self):
        self.run_mock.side_effect = lambda *a, **kw: mock.Mock(
            returncode=0, stdout=json.dumps({"status": "locked"}), stderr=""
        )
        with self.assertRaisesRegex(m.BitwardenCliError, "not unlocked"):
            m.import_accounts_to_bitwarden([sample_account()])
        self.assertEqual(self.run_mock.call_count, 1)

    def test_partial_failure_is_counted_without_cli_output(self):
        process, _calls, _items, _folders = fake_process(fail_item_number=2)
        self.run_mock.side_effect = process.side_effect
        created, failed = m.import_accounts_to_bitwarden(
            [sample_account(), sample_account("second-user")]
        )
        self.assertEqual(created, 1)
        self.assertEqual(failed, ["Example Service: second-user"])

    def test_missing_session_fails_before_cli_call(self):
        self.env.stop()
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(m.BitwardenCliError, "BW_SESSION is not set"),
        ):
            m.import_accounts_to_bitwarden([sample_account()])
        self.run_mock.assert_not_called()

    def test_cli_error_text_is_never_forwarded(self):
        process, _calls, _items, _folders = fake_process(fail_item_number=1)
        self.run_mock.side_effect = process.side_effect
        stdout = io.StringIO()
        stderr = io.StringIO()
        args = mock.Mock(import_bw=True, dry_run=False, output=None, bw_folder=None, quiet=True)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = m.deliver_accounts(args, [sample_account()])
        self.assertEqual(result, 1)
        self.assertNotIn("SECRET LEAK SENTINEL", stdout.getvalue() + stderr.getvalue())
        self.assertNotIn(FAKE_SECRET, stdout.getvalue() + stderr.getvalue())

    def test_cli_dry_run_reads_fixture_and_makes_no_bw_calls(self):
        self.run_mock.assert_not_called()
        fixture = Path(__file__).parent / "fixtures" / "otpauth_uris.txt"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = m.main([str(fixture), "--import-bw", "--dry-run", "--quiet"])
        self.assertEqual(result, 0)
        self.assertIn("would import 3 account(s)", output.getvalue())
        self.run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
