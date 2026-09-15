import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import integrations
import onboarding
import data_retention
from account_automation import (
    ASSIST_FIELD_KEYS,
    ASSIST_FIELD_WALK_ORDER,
    AccountCreator,
    format_assist_payload,
    normalize_personal_data,
    parse_confirmation,
)
from employee_profiles import (
    EMPLOYEE_ID_FIELD,
    RECORD_ROLE_FIELD,
    EmployeeProfileStore,
    ProfileSyncService,
)
from bw_import_converter import BitwardenConverter, strip_rtf_to_text
from data_retention import DataRetentionManager
from integrations import (
    APP_PASSWORD_HASH_KEY,
    APP_PIN_HASH_KEY,
    APP_SESSION_CREATED_KEY,
    APP_SESSION_TOKEN_KEY,
    BW_SECRET_KEY,
    BitwardenService,
    CredentialStore,
    PinAuth,
    SessionManager,
)
import gui
from gui import Dashboard
from onboarding import BitwardenConfig, Onboarding, OnboardingConfig
from transaction_db import TransactionDatabase

TEST_DB_KEY = "ab" * 32  # fixed, valid hex — real randomness isn't needed for tests


class FakeAudit:
    def __init__(self):
        self.events = []

    def log_retention_action(self, *args):
        self.events.append(("retention", args))

    def log_deletion(self, *args, **kwargs):
        self.events.append(("deletion", args, kwargs))

    def log_security_event(self, *args):
        self.events.append(("security", args))

    def log_import_operation(self, *args):
        self.events.append(("import", args))


class FakeTransactionDatabase:
    def __init__(self, delete_result=True):
        self.delete_result = delete_result

    def delete_employee_transactions(self, _employee):
        return self.delete_result


class MemoryCredentialStore:
    def __init__(self):
        self.values = {}

    def get(self, key, default=None):
        return self.values.get(key, default)

    def update(self, new_values):
        self.values.update(new_values)


class FakeBitwarden:
    def resolve_collection(self, _name):
        return None

    def import_json(self, _payload, _collection):
        return None

    def create_item(self, payload):
        return {"id": "fake-temp-item", "name": payload.get("name", "")}

    def sync(self):
        return None

    def delete_item_permanently(self, _item_id):
        return None

    def trash_item(self, _item_id):
        return None


class FakeAccountCreator:
    def __init__(self):
        self.calls = []
        self.closed = False
        self.reset_count = 0

    def _record(self, service, _personal_data, account_name):
        self.calls.append((service, account_name))
        return {"service": service, "filled_fields": ["email"]}

    def create_outlook_account(self, personal_data, account_name):
        return self._record("Outlook", personal_data, account_name)

    def create_hyatt_account(self, personal_data, account_name):
        return self._record("Hyatt", personal_data, account_name)

    def create_marriott_account(self, personal_data, account_name):
        return self._record("Marriott", personal_data, account_name)

    def close_browser(self):
        self.closed = True

    def reset_browser_session(self):
        self.reset_count += 1


def make_retention_manager(delete_result=True):
    manager = DataRetentionManager.__new__(DataRetentionManager)
    manager.transaction_db = FakeTransactionDatabase(delete_result)
    manager.audit = FakeAudit()
    manager.retention_data = {"employees": {}, "last_check": None}
    manager.prompt_callback = None
    manager._running = False
    manager._scheduler_thread = None
    manager._save_retention_data = lambda: None
    return manager


class BitwardenSessionTests(unittest.TestCase):
    def test_empty_instance_session_removes_inherited_session(self):
        service = BitwardenService()
        with mock.patch.dict(os.environ, {"BW_SESSION": "stale"}):
            self.assertNotIn("BW_SESSION", service._env_with_session())

    def test_instance_session_is_propagated(self):
        service = BitwardenService()
        service.session_key = "current"
        self.assertEqual(service._env_with_session()["BW_SESSION"], "current")

    def test_missing_named_collection_does_not_fall_back_to_personal(self):
        service = BitwardenService()
        result = subprocess.CompletedProcess([], 0, stdout="[]", stderr="")
        with mock.patch.object(service, "_run_bw", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "Select 'Personal Vault' explicitly"):
                service.resolve_collection("Employee Onboarding")

    def test_duplicate_named_collections_are_rejected(self):
        service = BitwardenService()
        result = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                '[{"id":"one","name":"Shared","organizationId":"org-a"},'
                '{"id":"two","name":"Shared","organizationId":"org-b"}]'
            ),
            stderr="",
        )
        with mock.patch.object(service, "_run_bw", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "ambiguous across organizations"):
                service.resolve_collection("Shared")


class BitwardenCliTimeoutTests(unittest.TestCase):
    """Every `bw` CLI call used to be unbounded: a hung/flaky CLI process
    would block forever, and since _run_bw serializes every caller behind
    one lock, that hang froze every other part of the app waiting on the
    same lock too (background provisioning, other profile loads, retention
    checks) with no way to recover short of a force quit. These tests
    simulate the hang via subprocess.TimeoutExpired (instant, no real
    waiting) and assert it's always bounded and always handled, never left
    to propagate unhandled out of a background thread.
    """

    def test_run_bw_applies_a_default_timeout(self):
        service = BitwardenService()
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")
            service._run_bw(["status", "--raw"], capture_output=True, text=True)
        self.assertEqual(mock_run.call_args.kwargs["timeout"], integrations.BW_CLI_TIMEOUT_SECONDS)

    def test_run_bw_does_not_override_an_explicit_timeout(self):
        service = BitwardenService()
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")
            service._run_bw(["sync"], capture_output=True, text=True, timeout=999)
        self.assertEqual(mock_run.call_args.kwargs["timeout"], 999)

    def test_sync_and_import_use_the_slower_timeout(self):
        service = BitwardenService()
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")
            service.sync()
        self.assertEqual(mock_run.call_args.kwargs["timeout"], integrations.BW_CLI_SLOW_TIMEOUT_SECONDS)

    def test_get_status_raises_cleanly_on_timeout_instead_of_hanging(self):
        service = BitwardenService()
        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["bw", "status"], timeout=30),
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                service.get_status()

    def test_unlock_returns_false_on_timeout_instead_of_hanging(self):
        service = BitwardenService()
        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["bw", "unlock"], timeout=30),
        ):
            self.assertFalse(service.unlock("some-password"))
        self.assertIsNone(service.session_key)

    def test_login_returns_a_failure_dict_on_timeout_instead_of_hanging(self):
        service = BitwardenService()
        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["bw", "login"], timeout=30),
        ):
            result = service.login("ops@example.com", "some-password")
        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"].lower())

    def test_resolve_collection_converts_timeout_to_runtime_error(self):
        service = BitwardenService()
        with mock.patch.object(
            service,
            "_run_bw",
            side_effect=subprocess.TimeoutExpired(cmd=["bw", "list"], timeout=30),
        ):
            with self.assertRaisesRegex(RuntimeError, "Could not resolve Bitwarden collection"):
                service.resolve_collection("Employee Onboarding")

    def test_import_json_converts_timeout_to_runtime_error(self):
        service = BitwardenService()
        with mock.patch.object(
            service,
            "_run_bw",
            side_effect=subprocess.TimeoutExpired(cmd=["bw", "import"], timeout=90),
        ):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                service.import_json('{"items": []}')


class AppSessionTests(unittest.TestCase):
    def test_password_is_hashed_and_wrong_password_is_rejected(self):
        store = MemoryCredentialStore()
        manager = SessionManager(store)
        self.assertTrue(manager.set_password("correct horse"))
        self.assertNotEqual(store.get(APP_PASSWORD_HASH_KEY), "correct horse")
        self.assertTrue(manager.verify_password("correct horse"))
        self.assertFalse(manager.verify_password("wrong password"))

    def test_random_session_is_created_and_expires(self):
        store = MemoryCredentialStore()
        manager = SessionManager(store)
        self.assertTrue(manager.set_password("correct horse"))
        with mock.patch.object(integrations.time, "time", return_value=1000.0):
            self.assertTrue(manager.create_session("correct horse"))
            self.assertTrue(manager.is_authenticated())
        self.assertNotEqual(store.get(APP_SESSION_TOKEN_KEY), "correct horse")
        self.assertEqual(store.get(APP_SESSION_CREATED_KEY), "1000.0")

        with mock.patch.object(integrations.time, "time", return_value=4601.0):
            self.assertFalse(manager.is_authenticated())
        self.assertEqual(store.get(APP_SESSION_TOKEN_KEY), "")


class CredentialMigrationTests(unittest.TestCase):
    def test_legacy_file_migrates_into_secure_store_and_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "legacy_credentials.json"
            dest = Path(directory) / "secure" / "credentials.json"
            source.write_text('{"bw_email": "ops@example.com", "token": "secret"}', encoding="utf-8")
            with (
                mock.patch.object(integrations, "CREDENTIALS_FILE", source),
                mock.patch.object(integrations, "SECURE_CREDENTIALS_FILE", dest),
            ):
                store = CredentialStore()
            self.assertEqual(store.get("bw_email"), "ops@example.com")
            self.assertEqual(store.get("token"), "secret")
            self.assertFalse(source.exists())
            self.assertTrue(dest.exists())
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)

    def test_update_persists_without_keychain(self):
        with tempfile.TemporaryDirectory() as directory:
            secure = Path(directory) / "secure.json"
            store = CredentialStore(path=secure)
            store.update({"shared_passphrase": "passphrase12", "auto_import": "true"})
            reloaded = CredentialStore(path=secure)
            self.assertEqual(reloaded.get("shared_passphrase"), "passphrase12")
            self.assertEqual(reloaded.get("auto_import"), "true")


class PinAuthTests(unittest.TestCase):
    def test_accepts_letters_numbers_or_both(self):
        self.assertIsNone(PinAuth.validate_pin("Ab12"))
        self.assertIsNone(PinAuth.validate_pin("ops7"))
        self.assertIsNone(PinAuth.validate_pin("1234"))
        self.assertIsNone(PinAuth.validate_pin("AbCdEf12"))
        self.assertIn("4–8", PinAuth.validate_pin("ab") or "")
        self.assertIn("letters and numbers", PinAuth.validate_pin("ab!234") or "")

    def test_pin_encrypts_and_unlocks_master_password(self):
        store = MemoryCredentialStore()
        auth = PinAuth(store)
        err = auth.setup(email="ops@example.com", master_password="horse battery", pin="Ops7")
        self.assertIsNone(err)
        self.assertTrue(auth.has_pin())
        self.assertNotEqual(store.get(BW_SECRET_KEY), "horse battery")
        self.assertNotEqual(store.get(APP_PIN_HASH_KEY), "Ops7")
        self.assertTrue(auth.verify_pin("Ops7"))
        self.assertFalse(auth.verify_pin("wrong"))
        self.assertEqual(auth.unlock_master_password("Ops7"), "horse battery")
        self.assertIsNone(auth.unlock_master_password("wrong"))

    def test_new_pin_uses_stronger_kdf_and_persists(self):
        store = MemoryCredentialStore()
        auth = PinAuth(store)
        self.assertIsNone(
            auth.setup(email="ops@example.com", master_password="pw12345", pin="Ops7")
        )
        self.assertEqual(
            store.get(integrations.APP_PIN_ITERS_KEY),
            str(integrations.PIN_KDF_ITERATIONS),
        )
        # A fresh PinAuth over the same store (a "relaunch") still unlocks.
        self.assertEqual(PinAuth(store).unlock_master_password("Ops7"), "pw12345")

    def test_legacy_pin_without_iters_uses_default_cost(self):
        store = MemoryCredentialStore()
        salt = bytes(range(16))
        iters = integrations.PBKDF2_ITERATIONS
        token = PinAuth._fernet_for_pin("Ops7", salt, iters).encrypt(b"legacy-pw")
        store.update(
            {
                "bw_email": "ops@example.com",
                integrations.APP_PIN_SALT_KEY: salt.hex(),
                APP_PIN_HASH_KEY: PinAuth._hash_pin("Ops7", salt, iters),
                BW_SECRET_KEY: token.decode("ascii"),
            }
        )
        auth = PinAuth(store)
        self.assertTrue(auth.has_pin())
        self.assertTrue(auth.verify_pin("Ops7"))
        self.assertEqual(auth.unlock_master_password("Ops7"), "legacy-pw")

    def test_lockout_after_max_failed_attempts(self):
        store = MemoryCredentialStore()
        auth = PinAuth(store)
        auth.setup(email="ops@example.com", master_password="pw12345", pin="Ops7")
        outcome = {}
        for _ in range(integrations.PIN_MAX_ATTEMPTS):
            outcome = auth.attempt_unlock("Wrong9")
        self.assertEqual(outcome["status"], "locked")
        self.assertGreater(auth.lock_remaining(), 0)
        # Even the correct PIN is refused while the lockout is active.
        self.assertEqual(auth.attempt_unlock("Ops7")["status"], "locked")

    def test_correct_pin_resets_failure_count(self):
        store = MemoryCredentialStore()
        auth = PinAuth(store)
        auth.setup(email="ops@example.com", master_password="pw12345", pin="Ops7")
        self.assertEqual(auth.attempt_unlock("Wrong9")["status"], "bad_pin")
        self.assertEqual(auth.attempt_unlock("Wrong9")["status"], "bad_pin")
        ok = auth.attempt_unlock("Ops7")
        self.assertEqual(ok["status"], "ok")
        self.assertEqual(ok["password"], "pw12345")
        self.assertEqual(auth._fail_count(), 0)
        self.assertEqual(auth.lock_remaining(), 0)


class TransactionDatabaseTests(unittest.TestCase):
    def test_permissions_and_missing_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "transactions.db"
            database = TransactionDatabase(db_path, encryption_key=TEST_DB_KEY)
            self.assertEqual(stat.S_IMODE(db_path.stat().st_mode), 0o600)
            with self.assertLogs(level="WARNING"):
                self.assertFalse(database.delete_transaction(999))

    def test_db_file_is_encrypted_at_rest_not_plaintext_sqlite(self):
        """The whole point: plain sqlite3 must not be able to read it, not
        just "permission denied" — actually encrypted, not merely
        access-restricted.
        """
        import sqlite3

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "transactions.db"
            database = TransactionDatabase(db_path, encryption_key=TEST_DB_KEY)
            database.add_transaction("2026-07-19", 12.50, "Example", "Ada Lovelace", "1111")

            plain = sqlite3.connect(str(db_path))
            with self.assertRaises(sqlite3.DatabaseError):
                plain.execute("SELECT * FROM transactions").fetchall()
            plain.close()

    def test_round_trips_with_the_right_key_across_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "transactions.db"
            TransactionDatabase(db_path, encryption_key=TEST_DB_KEY).add_transaction(
                "2026-07-19", 12.50, "Example", "Ada Lovelace", "1111"
            )
            reopened = TransactionDatabase(db_path, encryption_key=TEST_DB_KEY)
            transactions = reopened.get_all_transactions()
            self.assertEqual(len(transactions), 1)
            self.assertEqual(transactions[0]["merchant"], "Example")

    def test_wrong_key_fails_cleanly_instead_of_returning_garbage(self):
        import transaction_db

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "transactions.db"
            TransactionDatabase(db_path, encryption_key=TEST_DB_KEY).add_transaction(
                "2026-07-19", 12.50, "Example", "Ada Lovelace", "1111"
            )
            with self.assertRaises(transaction_db.DB_ERRORS):
                TransactionDatabase(db_path, encryption_key="cd" * 32)

    def test_migrates_a_plaintext_db_in_place_preserving_data(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "transactions.db"

            legacy = sqlite3.connect(str(db_path))
            legacy.execute(
                """
                CREATE TABLE transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL, amount REAL NOT NULL, merchant TEXT NOT NULL,
                    employee_name TEXT NOT NULL, card_number TEXT NOT NULL,
                    created_at TEXT NOT NULL, employee_file_date TEXT, employee_id TEXT
                )
                """
            )
            legacy.execute(
                "CREATE TABLE employee_budgets (employee_id TEXT PRIMARY KEY, "
                "employee_name TEXT NOT NULL, opening_spend REAL NOT NULL DEFAULT 0, "
                "spend_limit REAL NOT NULL, updated_at TEXT NOT NULL)"
            )
            legacy.execute(
                "INSERT INTO transactions "
                "(date, amount, merchant, employee_name, card_number, created_at) "
                "VALUES ('2026-01-01', 42.5, 'Coffee Co', 'Ada Lovelace', '1234', "
                "'2026-01-01T00:00:00')"
            )
            legacy.execute(
                "INSERT INTO employee_budgets VALUES "
                "('employee-uuid', 'Ada Lovelace', 0, 500, '2026-01-01T00:00:00')"
            )
            legacy.commit()
            legacy.close()

            migrated = TransactionDatabase(db_path, encryption_key=TEST_DB_KEY)
            transactions = migrated.get_all_transactions()
            self.assertEqual(len(transactions), 1)
            self.assertEqual(transactions[0]["merchant"], "Coffee Co")
            budgets = migrated.get_employee_budgets()
            self.assertEqual(len(budgets), 1)
            self.assertEqual(budgets[0]["employee_name"], "Ada Lovelace")

            # File on disk is now genuinely encrypted, not just "migrated" in memory.
            plain = sqlite3.connect(str(db_path))
            with self.assertRaises(sqlite3.DatabaseError):
                plain.execute("SELECT * FROM transactions").fetchall()
            plain.close()

            # Re-opening again (second launch) must not re-run the migration
            # or lose data — it should just work against the now-encrypted file.
            reopened = TransactionDatabase(db_path, encryption_key=TEST_DB_KEY)
            self.assertEqual(len(reopened.get_all_transactions()), 1)

    def test_transactions_can_be_linked_to_immutable_employee_id(self):
        with tempfile.TemporaryDirectory() as directory:
            database = TransactionDatabase(Path(directory) / "transactions.db", encryption_key=TEST_DB_KEY)
            database.add_transaction(
                "2026-07-19",
                12.50,
                "Example",
                "Ada Lovelace",
                "1111",
            )
            self.assertEqual(database.link_employee("Ada Lovelace", "employee-uuid"), 1)
            transactions = database.get_transactions_by_employee_id("employee-uuid")
            self.assertEqual(len(transactions), 1)
            self.assertEqual(transactions[0]["employee_name"], "Ada Lovelace")

    def test_employee_budget_combines_opening_spend_and_transactions(self):
        with tempfile.TemporaryDirectory() as directory:
            database = TransactionDatabase(Path(directory) / "transactions.db", encryption_key=TEST_DB_KEY)
            self.assertTrue(
                database.set_employee_budget(
                    "employee-uuid",
                    "Ada Lovelace",
                    125.0,
                    1000.0,
                )
            )
            database.add_transaction(
                "2026-07-19",
                75.0,
                "Example",
                "Ada Lovelace",
                "1111",
                employee_id="employee-uuid",
            )
            budget = database.get_employee_budgets()[0]
            self.assertEqual(budget["total_spent"], 200.0)
            self.assertEqual(budget["spend_limit"], 1000.0)


class RetentionTests(unittest.TestCase):
    def test_all_overdue_milestones_are_returned_independently(self):
        manager = make_retention_manager()
        manager.retention_data["employees"]["Example Employee"] = {
            "registered_date": (datetime.now() - timedelta(days=25)).isoformat(),
            "status": "active",
            "day5_audit": False,
            "day10_audit": False,
            "day15_shredded": False,
            "day20_logs_shredded": False,
        }
        self.assertEqual(
            {action["day"] for action in manager.check_retention_schedule()},
            {5, 10, 15, 20},
        )

    def test_failed_transaction_deletion_does_not_mark_day15_complete(self):
        manager = make_retention_manager(delete_result=False)
        manager.retention_data["employees"]["Example Employee"] = {
            "day15_shredded": False,
            "status": "active",
        }
        with self.assertLogs(level="ERROR"):
            self.assertFalse(manager.execute_auto_shred("Example Employee"))
        employee = manager.retention_data["employees"]["Example Employee"]
        self.assertFalse(employee["day15_shredded"])
        self.assertEqual(employee["status"], "active")

    def test_shared_log_scrub_removes_subject_and_restricts_permissions(self):
        manager = make_retention_manager()
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "shared.log"
            log_path.write_text(
                "keep this line\nExample Employee sensitive line\n",
                encoding="utf-8",
            )
            self.assertTrue(manager._scrub_employee_lines(log_path, "Example Employee"))
            self.assertEqual(log_path.read_text(encoding="utf-8"), "keep this line\n")
            self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)

    def test_registration_tracks_username_and_email_aliases(self):
        manager = make_retention_manager()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(data_retention, "LOGS_DIR", Path(directory)):
                manager.register_employee(
                    "Example Employee",
                    "2026-07-18",
                    aliases=["exampleemployee1980", "example@outlook.com"],
                    profile={
                        "first_name": "Example",
                        "last_name": "Employee",
                        "username": "exampleemployee1980",
                        "email": "example@outlook.com",
                    },
                )
        self.assertEqual(
            manager.retention_data["employees"]["Example Employee"]["aliases"],
            ["exampleemployee1980", "example@outlook.com"],
        )
        profile = manager.get_employee_profile("Example Employee")
        self.assertEqual(profile["username"], "exampleemployee1980")
        self.assertEqual(
            profile["accounts"],
            {"email": "pending", "hyatt": "pending", "marriott": "pending"},
        )
        self.assertTrue(
            manager.update_account_status("Example Employee", "email", "created")
        )
        self.assertEqual(
            manager.get_employee_profile("Example Employee")["accounts"]["email"],
            "created",
        )

    def test_scheduler_starts_only_one_immediate_worker(self):
        manager = make_retention_manager()
        thread = mock.Mock()
        with mock.patch.object(data_retention.threading, "Thread", return_value=thread) as thread_cls:
            manager.start_scheduler(check_interval_hours=24)
        self.assertEqual(thread_cls.call_count, 1)
        thread.start.assert_called_once_with()


class OnboardingTests(unittest.TestCase):
    def test_resume_accounts_skips_completed_services_and_persists_progress(self):
        retention = make_retention_manager()
        retention.retention_data["employees"]["Example Employee"] = {
            "profile": {
                "first_name": "Example",
                "last_name": "Employee",
                "username": "exampleemployee1980",
                "email": "exampleemployee1980@outlook.com",
            },
            "accounts": {
                "email": "created",
                "hyatt": "pending",
                "marriott": "pending",
            },
        }
        account_creator = FakeAccountCreator()
        pipeline = Onboarding(
            FakeBitwarden(),
            retention_manager=retention,
            account_creator=account_creator,
        )
        pipeline.resume_accounts(
            "Example Employee",
            "shared passphrase",
            OnboardingConfig(bw=BitwardenConfig("Personal Vault")),
            account_confirmation_callback=lambda _service, _employee, _result: True,
        )
        self.assertEqual(
            account_creator.calls,
            [
                ("Hyatt", "exampleemployee1980"),
                ("Marriott", "exampleemployee1980"),
            ],
        )
        accounts = retention.get_employee_profile("Example Employee")["accounts"]
        self.assertEqual(accounts["email"], "created")
        self.assertEqual(accounts["hyatt"], "created")
        self.assertEqual(accounts["marriott"], "created")

    def test_accounts_run_in_global_dependency_stages(self):
        audit = FakeAudit()
        account_creator = FakeAccountCreator()
        confirmations = []
        employees = [
            {
                "full_name": "Alpha Person",
                "first_name": "Alpha",
                "last_name": "Person",
                "username": "alphaperson1980",
                "email": "alphaperson1980@outlook.com",
            },
            {
                "full_name": "Beta Person",
                "first_name": "Beta",
                "last_name": "Person",
                "username": "betaperson1981",
                "email": "betaperson1981@outlook.com",
            },
        ]

        def convert(_source, output, _password):
            output.write_text('{"items": []}', encoding="utf-8")
            return {"items_generated": 6, "employees": employees}

        def confirm(service, employee, _result):
            confirmations.append((service, employee["username"]))
            return True

        with tempfile.TemporaryDirectory() as directory:
            downloads = Path(directory)
            temp_dir = downloads / "secure-temp"
            (downloads / "HQ-123.txt").write_text("sample", encoding="utf-8")
            with (
                mock.patch.object(onboarding, "get_audit_logger", return_value=audit),
                mock.patch.object(onboarding, "TEMP_DIR", temp_dir),
                mock.patch.object(onboarding, "convert_file_to_bitwarden_json", side_effect=convert),
                mock.patch.object(
                    onboarding,
                    "secure_delete_file",
                    side_effect=lambda path, mode: Path(path).unlink(),
                ),
            ):
                pipeline = Onboarding(FakeBitwarden(), account_creator=account_creator)
                pipeline.run(
                    downloads,
                    "shared passphrase",
                    OnboardingConfig(bw=BitwardenConfig("Personal Vault")),
                    account_confirmation_callback=confirm,
                )

        expected = [
            ("Outlook", "alphaperson1980"),
            ("Outlook", "betaperson1981"),
            ("Hyatt", "alphaperson1980"),
            ("Hyatt", "betaperson1981"),
            ("Marriott", "alphaperson1980"),
            ("Marriott", "betaperson1981"),
        ]
        self.assertEqual(account_creator.calls, expected)
        self.assertEqual(confirmations, expected)
        self.assertEqual(account_creator.reset_count, len(expected))
        self.assertTrue(account_creator.closed)

    def test_resume_accounts_retries_then_marks_done(self):
        retention = make_retention_manager()
        retention.retention_data["employees"]["Example Employee"] = {
            "profile": {
                "first_name": "Example",
                "last_name": "Employee",
                "username": "exampleemployee1980",
                "email": "exampleemployee1980@outlook.com",
            },
            "accounts": {
                "email": "created",
                "hyatt": "pending",
                "marriott": "created",
            },
        }
        account_creator = FakeAccountCreator()
        decisions = iter(["retry", "done"])

        pipeline = Onboarding(
            FakeBitwarden(),
            retention_manager=retention,
            account_creator=account_creator,
        )
        pipeline.resume_accounts(
            "Example Employee",
            "shared passphrase",
            OnboardingConfig(
                bw=BitwardenConfig("Personal Vault"),
                provision_outlook=False,
                provision_marriott=False,
            ),
            account_confirmation_callback=lambda *_args: next(decisions),
        )
        self.assertEqual(
            account_creator.calls,
            [
                ("Hyatt", "exampleemployee1980"),
                ("Hyatt", "exampleemployee1980"),
            ],
        )
        # One reset after retry, one after Done.
        self.assertEqual(account_creator.reset_count, 2)
        accounts = retention.get_employee_profile("Example Employee")["accounts"]
        self.assertEqual(accounts["hyatt"], "created")
        self.assertTrue(account_creator.closed)

    def test_lockdown_disposes_exact_source_and_generated_json_paths(self):
        audit = FakeAudit()
        disposed = []

        def convert(source, output, _password):
            output.write_text('{"items": []}', encoding="utf-8")
            return {"items_generated": 3, "employees": []}

        def dispose(path, mode):
            disposed.append((Path(path), mode))
            Path(path).unlink()

        with tempfile.TemporaryDirectory() as directory:
            downloads = Path(directory)
            temp_dir = downloads / "secure-temp"
            source = downloads / "HQ-123.txt"
            source.write_text("sample", encoding="utf-8")
            with (
                mock.patch.object(onboarding, "get_audit_logger", return_value=audit),
                mock.patch.object(onboarding, "TEMP_DIR", temp_dir),
                mock.patch.object(onboarding, "convert_file_to_bitwarden_json", side_effect=convert),
                mock.patch.object(onboarding, "secure_delete_file", side_effect=dispose),
            ):
                pipeline = Onboarding(FakeBitwarden())
                pipeline.run(
                    downloads,
                    "shared passphrase",
                    OnboardingConfig(
                        bw=BitwardenConfig("Personal Vault"),
                        provision_outlook=False,
                        provision_hyatt=False,
                        provision_marriott=False,
                    ),
                )

            disposed_paths = {path for path, _mode in disposed}
            self.assertIn(source, disposed_paths)
            generated = disposed_paths - {source}
            self.assertEqual(len(generated), 1)
            self.assertEqual(next(iter(generated)).parent, temp_dir)

    def test_converter_output_is_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            output = root / "output.json"
            source.write_text("unused", encoding="utf-8")
            converter = BitwardenConverter(source, output, "password")
            converter._write_output_file([])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_converter_tags_all_records_with_one_employee_uuid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "HQ-123.txt"
            source.write_text(
                "firstname|lastname|dob|cc|cvv|expmonth|expyear\n"
                "Ada|Lovelace|12/10/1815|4111111111111111|123|04|2030\n",
                encoding="utf-8",
            )
            converter = BitwardenConverter(source, root / "output.json", "password")
            items, employees = converter._process_input_file()
            employee_id = employees[0]["employee_id"]
            roles = set()
            for item in items:
                fields = {field["name"]: field["value"] for field in item["fields"]}
                self.assertEqual(fields[EMPLOYEE_ID_FIELD], employee_id)
                roles.add(fields[RECORD_ROLE_FIELD])
            self.assertEqual(roles, {"email_login", "identity", "work_card"})
            identity = next(item for item in items if item["type"] == 4)
            self.assertEqual(identity["identity"]["firstName"], "Ada")
            self.assertEqual(identity["identity"]["lastName"], "Lovelace")
            self.assertIn(
                "Date of Birth",
                {field["name"] for field in identity["fields"]},
            )

    def test_rtf_hq_export_strips_controls_and_converts(self):
        rtf = (
            r"{\rtf1\ansi\ansicpg1252{\fonttbl\f0\fswiss Helvetica;}"
            r"\f0\fs24 \cf0 n_id|firstname|lastname|dob|cc|cvv|expmonth|expyear|email"
            r"\line 99|Ada|Lovelace|12/10/1815|4111111111111111|123|04|2030|ada@example.com}"
        )
        plain = strip_rtf_to_text(rtf)
        self.assertIn("n_id|firstname|lastname", plain)
        self.assertIn("Ada|Lovelace", plain)
        self.assertNotIn("\\rtf", plain)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "HQ-882920.rtf"
            source.write_text(rtf, encoding="utf-8")
            converter = BitwardenConverter(source, root / "output.json", "password")
            items, employees = converter._process_input_file()
            self.assertEqual(len(employees), 1)
            self.assertEqual(employees[0]["first_name"], "Ada")
            self.assertEqual(len(items), 3)

    def test_textedit_backslash_newline_rtf_keeps_hq_rows(self):
        # macOS TextEdit writes Return as "\<newline>", not \line / \par.
        rtf = (
            "{\\rtf1\\ansi\\ansicpg1252\\cocoartf2820\n"
            "{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\n"
            "\\f0\\fs24 \\cf0 n_id|firstname|lastname|dob|cc|cvv|expmonth|expyear|email\\\n"
            "99|Ada|Lovelace|12/10/1815|4111111111111111|123|04|2030|ada@example.com}\n"
        )
        plain = strip_rtf_to_text(rtf)
        self.assertIn("n_id|firstname|lastname", plain)
        self.assertIn("Ada|Lovelace", plain)
        self.assertNotIn("email99", plain)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "HQ-882920.rtf"
            source.write_text(rtf, encoding="utf-8")
            converter = BitwardenConverter(source, root / "output.json", "password")
            items, employees = converter._process_input_file()
            self.assertEqual(len(employees), 1)
            self.assertEqual(employees[0]["first_name"], "Ada")
            self.assertEqual(len(items), 3)
            card = next(item for item in items if item["type"] == 3)
            self.assertEqual(card["card"]["number"], "4111111111111111")
            self.assertEqual(card["card"]["code"], "123")

    def test_failed_import_disposes_generated_json_but_keeps_source(self):
        audit = FakeAudit()
        disposed = []

        def convert(_source, output, _password):
            output.write_text('{"items": []}', encoding="utf-8")
            return {"items_generated": 3, "employees": []}

        def dispose(path, mode):
            disposed.append(Path(path))
            Path(path).unlink()

        with tempfile.TemporaryDirectory() as directory:
            downloads = Path(directory)
            temp_dir = downloads / "secure-temp"
            source = downloads / "HQ-123.txt"
            source.write_text("sample", encoding="utf-8")
            bitwarden = FakeBitwarden()
            bitwarden.import_json = mock.Mock(side_effect=RuntimeError("import failed"))
            with (
                mock.patch.object(onboarding, "get_audit_logger", return_value=audit),
                mock.patch.object(onboarding, "TEMP_DIR", temp_dir),
                mock.patch.object(onboarding, "convert_file_to_bitwarden_json", side_effect=convert),
                mock.patch.object(onboarding, "secure_delete_file", side_effect=dispose),
            ):
                pipeline = Onboarding(bitwarden)
                with self.assertRaisesRegex(RuntimeError, "import failed"):
                    pipeline.run(
                        downloads,
                        "shared passphrase",
                        OnboardingConfig(
                            bw=BitwardenConfig("Personal Vault"),
                            provision_outlook=False,
                            provision_hyatt=False,
                            provision_marriott=False,
                        ),
                    )

            self.assertTrue(source.exists())
            self.assertEqual(len(disposed), 1)
            self.assertEqual(disposed[0].parent, temp_dir)


class HqTemplateTests(unittest.TestCase):
    def test_write_hq_file_round_trips_through_converter(self):
        from hq_template import HQ_TEMPLATE_HEADER, validate_manual_values, write_hq_file

        values = {
            "firstname": "Ada",
            "middlename": "",
            "lastname": "Lovelace",
            "dob": "1815-12-10",
            "ssn": "000-00-0000",
            "address": "1 Analytical Engine",
            "city": "London",
            "state": "ENG",
            "zip": "SW1A",
            "country": "UK",
            "phone": "555-0100",
            "email": "ada@example.com",
            "cc": "4111111111111111",
            "expmonth": "12",
            "expyear": "30",
            "cvv": "123",
            "brand": "Visa",
        }
        self.assertEqual(validate_manual_values(values), [])
        with tempfile.TemporaryDirectory() as directory:
            source = write_hq_file(values, Path(directory))
            self.assertTrue(source.name.startswith("HQ-"))
            text = source.read_text(encoding="utf-8")
            self.assertTrue(text.startswith(HQ_TEMPLATE_HEADER))
            output = Path(directory) / "out.json"
            result = BitwardenConverter(source, output, "shared-pass").run()
            self.assertEqual(result["items_generated"], 3)
            self.assertEqual(result["employees"][0]["username"], "adalovelace1815")

    def test_validate_manual_values_requires_core_fields(self):
        from hq_template import validate_manual_values

        errors = validate_manual_values({"firstname": "Ada"})
        self.assertTrue(any("Last name" in error for error in errors))
        self.assertTrue(any("Card number" in error for error in errors))


class SecureWatchDirTests(unittest.TestCase):
    """The intake watch folder moved from ~/Downloads to a hardened
    ~/Downloads/Secure Downloads subfolder. These tests exercise the
    hardening function and the detect-then-convert path against a dummy
    HQ file, without touching the real filesystem location or any real
    Bitwarden vault.
    """

    def test_creates_owner_only_dir_with_spotlight_sentinel(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "Downloads" / "Secure Downloads"
            with mock.patch("subprocess.run") as mock_run:
                result = gui._ensure_secure_watch_dir(target)
            self.assertEqual(result, target)
            self.assertTrue(target.is_dir())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertTrue((target / ".metadata_never_index").exists())
            if sys.platform == "darwin":
                self.assertEqual(mock_run.call_args.args[0][:2], ["tmutil", "addexclusion"])
            else:
                mock_run.assert_not_called()

    def test_replaces_a_symlink_instead_of_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            real_target = Path(directory) / "elsewhere"
            real_target.mkdir()
            link = Path(directory) / "Secure Downloads"
            link.symlink_to(real_target)
            with mock.patch("subprocess.run"):
                gui._ensure_secure_watch_dir(link)
            self.assertFalse(link.is_symlink())
            self.assertTrue(link.is_dir())
            self.assertEqual(stat.S_IMODE(link.stat().st_mode), 0o700)

    def test_idempotent_on_repeated_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "Secure Downloads"
            with mock.patch("subprocess.run"):
                gui._ensure_secure_watch_dir(target)
                gui._ensure_secure_watch_dir(target)  # must not raise
            self.assertTrue(target.is_dir())

    def test_dummy_hq_file_is_detected_and_converts_from_the_hardened_dir(self):
        """Mirrors HqTemplateTests' dummy-employee fixture, but sourced from
        a freshly hardened watch dir, matching Dashboard._queued_employee_files'
        glob (HQ-*.txt / HQ-*.rtf) and the real conversion step. No Bitwarden
        CLI call is made — BitwardenConverter only builds the JSON payload.
        """
        from hq_template import write_hq_file

        with tempfile.TemporaryDirectory() as directory:
            watch_dir = Path(directory) / "Downloads" / "Secure Downloads"
            with mock.patch("subprocess.run"):
                gui._ensure_secure_watch_dir(watch_dir)

            values = {
                "firstname": "Test",
                "middlename": "",
                "lastname": "Dummy",
                "dob": "1990-01-01",
                "ssn": "000-00-0000",
                "address": "123 Fake St",
                "city": "Nowhere",
                "state": "ZZ",
                "zip": "00000",
                "country": "US",
                "phone": "555-0100",
                "email": "test.dummy@example.com",
                "cc": "4111111111111111",
                "expmonth": "12",
                "expyear": "30",
                "cvv": "000",
                "brand": "Visa",
            }
            source = write_hq_file(values, watch_dir)
            self.assertTrue(source.name.startswith("HQ-"))
            self.assertEqual(source.parent, watch_dir)

            queued = sorted(
                f for f in watch_dir.glob("HQ-*") if f.is_file() and f.suffix in {".txt", ".rtf"}
            )
            self.assertEqual(queued, [source])

            output = watch_dir / "out.json"
            result = BitwardenConverter(source, output, "shared-pass").run()
            self.assertEqual(result["items_generated"], 3)
            self.assertEqual(result["employees"][0]["username"], "testdummy1990")


class QueuedFilesStatusTests(unittest.TestCase):
    """_refresh_queued_files() used to silently no-op: it early-returned
    behind `if not hasattr(self, "queue_list")`, and queue_list is never
    actually created anywhere in the current UI. The status bar
    (self.status) is the only visible feedback left, so it must update
    regardless of that dead widget.
    """

    def test_status_bar_reports_queued_files_without_queue_list_widget(self):
        dashboard = Dashboard.__new__(Dashboard)
        dashboard.status = mock.Mock()
        dashboard.workflow_step = mock.Mock()
        self.assertFalse(hasattr(dashboard, "queue_list"))
        with tempfile.TemporaryDirectory() as directory:
            watch_dir = Path(directory) / "Secure Downloads"
            watch_dir.mkdir()
            (watch_dir / "HQ-one.txt").write_text("x", encoding="utf-8")
            with mock.patch.object(gui, "DOWNLOADS", watch_dir):
                dashboard._refresh_queued_files()
        status_text = dashboard.status.set.call_args[0][0]
        self.assertIn("HQ-one.txt", status_text)
        self.assertIn("1", status_text)

    def test_status_bar_reports_no_files_queued(self):
        dashboard = Dashboard.__new__(Dashboard)
        dashboard.status = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            watch_dir = Path(directory) / "Secure Downloads"
            watch_dir.mkdir()
            with mock.patch.object(gui, "DOWNLOADS", watch_dir):
                dashboard._refresh_queued_files()
        dashboard.status.set.assert_called_with("No files queued")


class AssistWalkthroughOrderTests(unittest.TestCase):
    """The (Command-1) through (Command-6) hotkeys always paste the same
    field regardless of service (bound directly to ASSIST_FIELD_KEYS), but
    "Next field" should walk in the order the target site's form actually
    asks for fields — e.g. Outlook wants email+password before name.
    """

    def test_outlook_walks_email_and_password_before_name(self):
        dashboard = Dashboard.__new__(Dashboard)
        dashboard._assist_service = "Outlook"
        dashboard._assist_personal = {
            "first_name": "Ada",
            "last_name": "Lovelace",
            "email": "ada@example.com",
            "username": "",
            "password": "hunter2",
            "confirm_password": "hunter2",
            "postal": "12345",
        }
        self.assertEqual(
            dashboard._assist_current_fields(),
            ["email", "password", "confirm_password", "first_name", "last_name", "postal"],
        )

    def test_unlisted_service_falls_back_to_hotkey_order(self):
        dashboard = Dashboard.__new__(Dashboard)
        dashboard._assist_service = "Hyatt"
        dashboard._assist_personal = {
            "first_name": "Ada",
            "last_name": "Lovelace",
            "email": "ada@example.com",
            "password": "hunter2",
            "confirm_password": "hunter2",
            "postal": "12345",
        }
        self.assertEqual(list(dashboard._assist_current_fields()), list(ASSIST_FIELD_KEYS))

    def test_walk_order_only_overrides_navigation_not_the_hotkey_contract(self):
        self.assertEqual(ASSIST_FIELD_KEYS[0], "first_name")
        self.assertEqual(ASSIST_FIELD_WALK_ORDER["Outlook"][0], "email")


class AssistHelpersTests(unittest.TestCase):
    def test_normalize_personal_data_fills_aliases(self):
        data = normalize_personal_data(
            {
                "full_name": "Ada Lovelace",
                "email": "ada@example.com",
                "password": "secret",
                "zip_code": "02139",
            }
        )
        self.assertEqual(data["first_name"], "Ada")
        self.assertEqual(data["last_name"], "Lovelace")
        self.assertEqual(data["username"], "ada@example.com")
        self.assertEqual(data["confirm_password"], "secret")
        self.assertEqual(data["postal"], "02139")
        self.assertEqual(data["country"], "USA")

    def test_format_assist_payload_is_key_value_lines(self):
        payload = format_assist_payload(
            {
                "full_name": "Ada Lovelace",
                "first_name": "Ada",
                "last_name": "Lovelace",
                "email": "ada@example.com",
                "password": "secret",
                "postal": "02139",
            },
            "adalovelace1815",
            service="Marriott",
        )
        self.assertIn("service: Marriott", payload)
        self.assertIn("account_name: adalovelace1815", payload)
        self.assertIn("first_name: Ada", payload)
        self.assertIn("confirm_password: secret", payload)
        self.assertIn("postal: 02139", payload)
        self.assertTrue(all(":" in line for line in payload.splitlines()))

    def test_parse_confirmation_accepts_bool_and_strings(self):
        self.assertEqual(parse_confirmation(True), "done")
        self.assertEqual(parse_confirmation(False), "skip")
        self.assertEqual(parse_confirmation(None), "skip")
        self.assertEqual(parse_confirmation("done"), "done")
        self.assertEqual(parse_confirmation("retry"), "retry")
        self.assertEqual(parse_confirmation("skip"), "skip")
        self.assertEqual(parse_confirmation("yes"), "done")

    def test_prefer_system_browser_handoff_skips_selenium(self):
        creator = AccountCreator(prefer_system_browser=True)
        personal = {
            "full_name": "Ada Lovelace",
            "first_name": "Ada",
            "last_name": "Lovelace",
            "email": "ada@example.com",
            "password": "secret",
            "postal": "02139",
        }
        with mock.patch("account_automation.open_ops_browser", return_value={"ok": True, "detail": "ops"}) as open_ops:
            result = creator.create_marriott_account(personal, "adalovelace1815")
        open_ops.assert_called_once()
        self.assertEqual(result["status"], "manual_only")
        self.assertEqual(result["service"], "Marriott")
        self.assertEqual(result["filled_fields"], [])
        self.assertEqual(result["assist_fields"], list(ASSIST_FIELD_KEYS))
        self.assertIn("first_name: Ada", result["payload"])
        self.assertIn("postal: 02139", result["payload"])
        self.assertEqual(result["personal_data"]["confirm_password"], "secret")

    def test_arrange_windows_reports_non_mac_clearly(self):
        from account_automation import arrange_windows_for_assist

        with mock.patch("account_automation.sys.platform", "linux"):
            result = arrange_windows_for_assist()
        self.assertFalse(result["ok"])
        self.assertIn("macOS", result["detail"])

    def test_temp_autofill_payload_links_site_field_names(self):
        from account_automation import (
            TemporaryAutofillManager,
            build_temp_autofill_payload,
        )

        personal = {
            "first_name": "Cameron",
            "last_name": "Cohen",
            "email": "cameroncohen1994@outlook.com",
            "username": "cameroncohen1994",
            "password": "DemoPass1!",
            "postal": "20002",
        }
        outlook = build_temp_autofill_payload("Outlook", personal, "cameroncohen1994")
        self.assertTrue(outlook["payload"]["name"].startswith("PROVISION · TEMP · Outlook"))
        self.assertEqual(outlook["payload"]["login"]["username"], "cameroncohen1994")
        field_names = {f["name"] for f in outlook["payload"]["fields"]}
        self.assertIn("MemberName", field_names)
        self.assertIn("usernameInput", field_names)

        marriott = build_temp_autofill_payload("Marriott", personal, "cameroncohen1994")
        marriott_names = {f["name"] for f in marriott["payload"]["fields"]}
        self.assertIn("firstName", marriott_names)
        self.assertIn("postalCode", marriott_names)
        self.assertIn("confirmPassword", marriott_names)

        bw = mock.Mock()
        bw.create_item.return_value = {"id": "temp-1"}
        manager = TemporaryAutofillManager(bw)
        pushed = manager.push("Hyatt", personal, "cameroncohen1994")
        self.assertTrue(pushed["autofill_ready"])
        self.assertEqual(pushed["autofill_item_id"], "temp-1")
        self.assertIn("firstName", pushed["autofill_linked_fields"])
        bw.sync.assert_called()
        removed = manager.cleanup()
        self.assertEqual(removed, ["temp-1"])
        bw.delete_item_permanently.assert_called_once_with("temp-1")

    def test_chrome_ops_profile_writes_setup_desk_and_privacy_prefs(self):
        from chrome_ops_profile import ChromeOpsProfile, RECOMMENDED_EXTENSIONS

        with tempfile.TemporaryDirectory() as directory:
            profile = ChromeOpsProfile(
                Path(directory) / "ops",
                extensions_root=Path(directory) / "exts",
            )
            root = profile.ensure(install_extensions=False)
            self.assertTrue(root.exists())
            prefs = json.loads((profile.default_dir / "Preferences").read_text(encoding="utf-8"))
            self.assertEqual(prefs["profile"]["name"], "Provision Ops")
            self.assertFalse(prefs["credentials_enable_service"])
            self.assertFalse(prefs["autofill"]["profile_enabled"])
            self.assertEqual(prefs["webrtc"]["ip_handling_policy"], "disable_non_proxied_udp")
            html = profile.setup_page.read_text(encoding="utf-8")
            self.assertIn("Bitwarden", html)
            self.assertIn("uBlock Origin Lite", html)
            self.assertIn("Canvas Fingerprint Defender", html)
            self.assertIn("WebRTC Control", html)
            for ext in RECOMMENDED_EXTENSIONS:
                self.assertIn(ext["id"], html)
            cleared = profile.clear_site_data()
            self.assertTrue(cleared["ok"])

    def test_chrome_ops_crx_unpack_and_load_extension_arg(self):
        import zipfile

        from chrome_ops_profile import (
            ChromeOpsProfile,
            RECOMMENDED_EXTENSIONS,
            extract_crx_payload,
            unpack_crx,
        )

        # Minimal CRX3: Cr24 + version 3 + empty header + zip with manifest.
        manifest = b'{"name":"Test Ext","version":"1.0","manifest_version":3}'
        buf = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        try:
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("manifest.json", manifest)
            buf.close()
            zip_bytes = Path(buf.name).read_bytes()
        finally:
            Path(buf.name).unlink(missing_ok=True)

        header_size = 0
        crx = b"Cr24" + struct.pack("<II", 3, header_size) + zip_bytes
        self.assertEqual(extract_crx_payload(crx), zip_bytes)
        self.assertEqual(extract_crx_payload(zip_bytes), zip_bytes)

        with tempfile.TemporaryDirectory() as directory:
            crx_path = Path(directory) / "test.crx"
            crx_path.write_bytes(crx)
            dest = Path(directory) / "unpacked"
            unpack_crx(crx_path, dest)
            self.assertTrue((dest / "manifest.json").exists())

            # Seed one auto-install id so load_extension_arg picks it up.
            ext_id = next(ext["id"] for ext in RECOMMENDED_EXTENSIONS if ext.get("auto_install", True))
            profile = ChromeOpsProfile(
                Path(directory) / "ops",
                extensions_root=Path(directory) / "exts",
            )
            installed = Path(directory) / "exts" / ext_id
            installed.mkdir(parents=True)
            (installed / "manifest.json").write_text(
                '{"name":"x","version":"1","manifest_version":3}',
                encoding="utf-8",
            )
            arg = profile.load_extension_arg()
            self.assertIsNotNone(arg)
            self.assertTrue(arg.startswith("--load-extension="))
            self.assertIn(str(installed), arg)
            # launch_args() only needs a Chrome binary path to build the
            # argument list; don't depend on one actually being installed
            # on whatever machine runs this test.
            with mock.patch(
                "chrome_ops_profile.find_chrome_binary",
                return_value="/usr/bin/google-chrome-stable",
            ):
                args = profile.launch_args("https://example.com", install_extensions=False)
            self.assertTrue(any(a.startswith("--load-extension=") for a in args))
            self.assertTrue(
                any("DisableLoadExtensionCommandLineSwitch" in a for a in args)
            )


class AutofillHandoffTests(unittest.TestCase):
    """The Field Autofill extension gets an employee's field values via a
    chrome-extension://<id>/handoff.html?data=<base64 json> URL opened as
    an extra tab. These tests decode that URL the same way handoff.js does
    (base64 -> UTF-8 JSON) and check its shape, without needing a browser.
    """

    def _decode(self, url: str) -> dict:
        import base64 as b64
        import urllib.parse as up

        parsed = up.urlparse(url)
        query = up.parse_qs(parsed.query)
        encoded = query["data"][0]
        return json.loads(b64.b64decode(encoded).decode("utf-8"))

    def test_outlook_handoff_url_carries_expected_fields_and_site_names(self):
        from account_automation import AUTOFILL_EXTENSION_ID, build_autofill_handoff_url

        url = build_autofill_handoff_url(
            "Outlook",
            {
                "full_name": "Ada Lovelace",
                "first_name": "Ada",
                "last_name": "Lovelace",
                "email": "ada@example.com",
                "password": "hunter2",
                "confirm_password": "hunter2",
                "postal": "12345",
            },
        )
        self.assertIsNotNone(url)
        self.assertTrue(url.startswith(f"chrome-extension://{AUTOFILL_EXTENSION_ID}/handoff.html?data="))
        profile = self._decode(url)
        self.assertEqual(profile["service"], "Outlook")
        self.assertEqual(profile["employee_name"], "Ada Lovelace")
        self.assertEqual(profile["fields"]["email"], "ada@example.com")
        self.assertEqual(profile["fields"]["password"], "hunter2")
        # loginfmt/i0116/email are all Outlook's real field names for the
        # email data key, per SITE_AUTOFILL_SPECS.
        self.assertEqual(profile["site_field_names"]["loginfmt"], "email")
        self.assertEqual(profile["site_field_names"]["i0116"], "email")

    def test_unknown_service_returns_none(self):
        from account_automation import build_autofill_handoff_url

        self.assertIsNone(build_autofill_handoff_url("SomeOtherService", {"email": "a@b.com"}))

    def test_no_usable_field_data_returns_none(self):
        from account_automation import build_autofill_handoff_url

        self.assertIsNone(build_autofill_handoff_url("Outlook", {}))

    def test_extension_files_exist_and_id_matches_manifest_key(self):
        """Regression guard: if manifest.json's key ever changes, the
        hardcoded AUTOFILL_EXTENSION_ID must be recomputed to match, or
        every handoff URL points at the wrong (or a nonexistent) extension.
        """
        import base64 as b64
        import hashlib

        from chrome_ops_profile import AUTOFILL_EXTENSION_DIR, AUTOFILL_EXTENSION_ID

        self.assertTrue((AUTOFILL_EXTENSION_DIR / "manifest.json").exists())
        self.assertTrue((AUTOFILL_EXTENSION_DIR / "content.js").exists())
        self.assertTrue((AUTOFILL_EXTENSION_DIR / "handoff.html").exists())
        self.assertTrue((AUTOFILL_EXTENSION_DIR / "handoff.js").exists())

        manifest = json.loads((AUTOFILL_EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8"))
        pub_der = b64.b64decode(manifest["key"])
        digest = hashlib.sha256(pub_der).digest()
        computed_id = "".join(
            chr(ord("a") + (byte >> 4)) + chr(ord("a") + (byte & 0xF)) for byte in digest[:16]
        )
        self.assertEqual(computed_id, AUTOFILL_EXTENSION_ID)


class BitwardenItemApiTests(unittest.TestCase):
    def test_create_item_encodes_payload_without_writing_it_to_disk(self):
        service = BitwardenService()
        calls = []

        def run(args, **kwargs):
            calls.append((args, kwargs))
            if args == ["encode"]:
                return subprocess.CompletedProcess(args, 0, stdout="encoded-value\n", stderr="")
            return subprocess.CompletedProcess(
                args,
                0,
                stdout='{"id":"item-1","revisionDate":"revision-1"}',
                stderr="",
            )

        with mock.patch.object(service, "_run_bw", side_effect=run):
            created = service.create_item({"type": 1, "name": "Record"})

        self.assertEqual(created["id"], "item-1")
        self.assertEqual(json.loads(calls[0][1]["input"])["name"], "Record")
        self.assertEqual(calls[1][0], ["create", "item", "encoded-value"])

    def test_item_lifecycle_commands_are_session_aware(self):
        service = BitwardenService()
        service.session_key = "session"
        results = [
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            subprocess.CompletedProcess([], 0, stdout='{"id":"item-1"}', stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
        with mock.patch.object(service, "_run_bw", side_effect=results) as run:
            service.trash_item("item-1")
            service.restore_item("item-1")
            service.delete_item_permanently("item-1")
        self.assertEqual(run.call_args_list[0].args[0], ["delete", "item", "item-1"])
        self.assertEqual(run.call_args_list[1].args[0], ["restore", "item", "item-1"])
        self.assertEqual(
            run.call_args_list[2].args[0],
            ["delete", "item", "item-1", "--permanent"],
        )


class FakeProfileVault:
    def __init__(self, items=None):
        self.items = {item["id"]: dict(item) for item in (items or [])}
        self.synced = 0
        self.trashed = []
        self.restored = []
        self.deleted = []
        self.fail_trash = set()
        self.fail_delete = set()

    def sync(self):
        self.synced += 1

    def list_items(self):
        return list(self.items.values())

    def get_item(self, item_id):
        return dict(self.items[item_id])

    def create_item(self, payload):
        item = {
            **payload,
            "id": f"created-{len(self.items) + 1}",
            "revisionDate": "created-revision",
        }
        self.items[item["id"]] = item
        return dict(item)

    def edit_item(self, item_id, payload):
        item = {**payload, "id": item_id, "revisionDate": "new-revision"}
        self.items[item_id] = item
        return dict(item)

    def trash_item(self, item_id):
        if item_id in self.fail_trash:
            raise RuntimeError("trash failed")
        self.trashed.append(item_id)

    def restore_item(self, item_id):
        self.restored.append(item_id)
        return {"id": item_id}

    def delete_item_permanently(self, item_id):
        if item_id in self.fail_delete:
            raise RuntimeError("delete failed")
        self.deleted.append(item_id)


class EmployeeProfileTests(unittest.TestCase):
    def _store(self, directory):
        return EmployeeProfileStore(Path(directory) / "profiles.json")

    @staticmethod
    def _tagged_item(item_id, employee_id, role, name, revision="r1"):
        return {
            "id": item_id,
            "type": 4 if role == "identity" else 1,
            "name": name,
            "revisionDate": revision,
            "fields": [
                {"name": EMPLOYEE_ID_FIELD, "value": employee_id, "type": 1},
                {"name": RECORD_ROLE_FIELD, "value": role, "type": 1},
            ],
        }

    def test_store_migrates_legacy_metadata_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.migrate_retention(
                {
                    "employees": {
                        "Ada Lovelace": {
                            "profile": {
                                "first_name": "Ada",
                                "last_name": "Lovelace",
                                "email": "ada@example.com",
                            },
                            "accounts": {"email": "created"},
                        }
                    }
                }
            )
            profile = store.list_profiles()[0]
            self.assertEqual(profile["email"], "ada@example.com")
            self.assertEqual(profile["accounts"]["email"], "created")
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
            self.assertNotIn("password", store.path.read_text(encoding="utf-8").lower())

    def test_tagged_items_reconcile_to_immutable_employee_id(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            profile = store.upsert(display_name="Ada Lovelace")
            item = self._tagged_item(
                "identity-1",
                profile["employee_id"],
                "identity",
                "Ada Lovelace — Work Identity",
            )
            service = ProfileSyncService(FakeProfileVault([item]), store)
            service.sync_profiles()
            self.assertEqual(
                store.get(profile["employee_id"])["vault_refs"]["identity"]["item_id"],
                "identity-1",
            )

    def test_one_stale_vault_reference_does_not_blank_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            profile = store.upsert(display_name="Ada Lovelace")
            for role, item_id, item_type in (
                ("identity", "identity-1", 2),
                ("work_card", "missing-card", 3),
            ):
                store.bind_vault_ref(
                    profile["employee_id"],
                    role,
                    {"id": item_id, "type": item_type, "revisionDate": "r1"},
                )
            vault = FakeProfileVault()

            def get_item(item_id):
                if item_id == "missing-card":
                    raise RuntimeError("not found")
                return {
                    "id": item_id,
                    "type": 4,
                    "identity": {"firstName": "Ada"},
                }

            vault.get_item = get_item
            bundle = ProfileSyncService(vault, store).get_bundle(profile["employee_id"])
            self.assertEqual(bundle["identity"]["identity"]["firstName"], "Ada")
            self.assertEqual(bundle["work_card"]["_load_error"], "RuntimeError")

    def test_ambiguous_legacy_records_are_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            profile = store.upsert(display_name="Ada Lovelace")
            items = [
                {
                    "id": item_id,
                    "name": "Ada Lovelace — Work Identity",
                    "type": 4,
                    "fields": [],
                }
                for item_id in ("one", "two")
            ]
            ProfileSyncService(FakeProfileVault(items), store).sync_profiles()
            updated = store.get(profile["employee_id"])
            self.assertNotIn("identity", updated["vault_refs"])
            self.assertIn("Ambiguous", updated["sync_error"])

    def test_revision_conflict_prevents_identity_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            profile = store.upsert(display_name="Ada Lovelace")
            item = {
                **self._tagged_item(
                    "identity-1",
                    profile["employee_id"],
                    "identity",
                    "Ada Lovelace — Work Identity",
                    revision="server-revision",
                ),
                "identity": {"firstName": "Ada"},
                "unknown": {"preserve": True},
            }
            vault = FakeProfileVault([item])
            store.bind_vault_ref(profile["employee_id"], "identity", item)
            service = ProfileSyncService(vault, store)
            with self.assertRaisesRegex(RuntimeError, "reload"):
                service.edit_identity(
                    profile["employee_id"],
                    {"firstName": "Augusta"},
                    "stale-revision",
                )
            self.assertEqual(vault.items["identity-1"]["identity"]["firstName"], "Ada")

    def test_login_creation_binds_real_returned_item(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            profile = store.upsert(
                display_name="Ada Lovelace",
                email="ada@example.com",
            )
            service = ProfileSyncService(FakeProfileVault(), store)
            item = service.create_login(
                profile["employee_id"],
                "hyatt_login",
                "Hyatt",
                "ada@example.com",
                "memory-only-password",
                "https://hyatt.com/",
            )
            updated = store.get(profile["employee_id"])
            self.assertEqual(updated["vault_refs"]["hyatt_login"]["item_id"], item["id"])
            self.assertNotIn(
                "memory-only-password",
                store.path.read_text(encoding="utf-8"),
            )

    def test_partial_trash_remains_retryable_and_restore_clears_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            profile = store.upsert(display_name="Ada Lovelace")
            vault = FakeProfileVault()
            service = ProfileSyncService(vault, store)
            for role, item_id, item_type in (
                ("identity", "one", 4),
                ("work_card", "two", 3),
            ):
                store.bind_vault_ref(
                    profile["employee_id"],
                    role,
                    {"id": item_id, "type": item_type, "revisionDate": "r1"},
                )
            vault.fail_trash.add("two")
            result = service.trash_bundle(profile["employee_id"])
            self.assertEqual(result["failed"], ["two"])
            self.assertEqual(
                store.get(profile["employee_id"])["deletion"]["status"],
                "partial",
            )
            restored = service.restore_bundle(profile["employee_id"])
            self.assertEqual(restored["failed"], [])
            self.assertIsNone(store.get(profile["employee_id"])["deletion"])

    def test_purge_waits_for_deadline_and_all_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            profile = store.upsert(display_name="Ada Lovelace")
            store.bind_vault_ref(
                profile["employee_id"],
                "identity",
                {"id": "one", "type": 4, "revisionDate": "r1"},
            )
            vault = FakeProfileVault()
            service = ProfileSyncService(vault, store)
            service.trash_bundle(profile["employee_id"])
            deletion = store.data["profiles"][profile["employee_id"]]["deletion"]
            deletion["purge_after"] = (
                datetime.now(timezone.utc) + timedelta(hours=1)
            ).isoformat()
            store._save()
            self.assertEqual(service.purge_due(), [])
            vault.fail_delete.add("one")
            results = service.purge_due(datetime.now(timezone.utc) + timedelta(hours=2))
            self.assertEqual(results[0]["failed"], ["one"])
            self.assertEqual(
                store.get(profile["employee_id"])["deletion"]["status"],
                "purge_failed",
            )
            vault.fail_delete.clear()
            service.purge_due(datetime.now(timezone.utc) + timedelta(hours=2))
            self.assertEqual(
                store.get(profile["employee_id"])["deletion"]["status"],
                "purged",
            )

    def test_profile_viewer_clears_loaded_secrets_and_reveal_state(self):
        dashboard = Dashboard.__new__(Dashboard)
        dashboard.profile_bundle = {
            "email_login": {"login": {"password": "memory-only-secret"}}
        }
        dashboard._revealed_profile_values = {("email_login", "Password")}
        dashboard._clear_profile_secrets()
        self.assertEqual(dashboard.profile_bundle, {})
        self.assertEqual(dashboard._revealed_profile_values, set())

    def test_identity_viewer_includes_native_and_custom_fields(self):
        rows = Dashboard._identity_view_rows(
            {
                "name": "Ada Lovelace — Work Identity",
                "identity": {
                    "firstName": "Ada",
                    "lastName": "Lovelace",
                    "city": "London",
                },
                "fields": [
                    {"name": "Date of Birth", "value": "12/10/1815"},
                    {"name": EMPLOYEE_ID_FIELD, "value": "hidden"},
                    {"name": RECORD_ROLE_FIELD, "value": "identity"},
                ],
            }
        )
        values = {label: (value, sensitive) for label, value, sensitive in rows}
        self.assertEqual(values["First name"][0], "Ada")
        self.assertEqual(values["City"][0], "London")
        self.assertTrue(values["Date of Birth"][1])
        self.assertNotIn(EMPLOYEE_ID_FIELD, values)


if __name__ == "__main__":
    unittest.main()
