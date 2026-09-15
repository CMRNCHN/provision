"""GUI smoke tests: real Tk/customtkinter widget construction.

Unlike tests/test_security_behaviors.py (fakes only, no display), these tests
build real widgets and need a live display connection (Xvfb in CI is fine).
"""

import contextlib
import logging
import os
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import audit_logger
import data_retention
import employee_profiles
import gui
import integrations
import transaction_db
from integrations import CredentialStore


def _patch_audit_singleton(tmp_dir: Path, stack: contextlib.ExitStack) -> None:
    """Point the process-wide audit logger singleton at tmp_dir and force a
    fresh instance, so tests never write to (or reuse a handle opened
    against) the real ~/.provision_audit.log.
    """
    stack.enter_context(mock.patch.object(audit_logger, "AUDIT_LOG_FILE", tmp_dir / "audit.log"))
    stack.enter_context(mock.patch.object(data_retention, "AUDIT_LOG_FILE", tmp_dir / "audit.log"))
    stack.enter_context(mock.patch.object(audit_logger, "_audit_logger", None))


def _patch_all_app_data_paths(tmp_dir: Path) -> contextlib.ExitStack:
    """Redirect every module-level file-path constant AppGUI() touches at
    construction time to tmp_dir, so a smoke test never reads/writes the
    real user's ~/.provision* files.
    """
    stack = contextlib.ExitStack()
    stack.enter_context(
        mock.patch.object(integrations, "SECURE_CREDENTIALS_FILE", tmp_dir / "credentials.json")
    )
    stack.enter_context(
        mock.patch.object(integrations, "CREDENTIALS_FILE", tmp_dir / "legacy_credentials.json")
    )
    stack.enter_context(mock.patch.object(transaction_db, "DB_PATH", tmp_dir / "transactions.db"))
    stack.enter_context(
        mock.patch.object(employee_profiles, "PROFILE_DATA_FILE", tmp_dir / "profiles.json")
    )
    stack.enter_context(
        mock.patch.object(data_retention, "RETENTION_DATA_FILE", tmp_dir / "retention.json")
    )
    stack.enter_context(mock.patch.object(data_retention, "LOGS_DIR", tmp_dir / "logs"))
    stack.enter_context(
        mock.patch.object(gui, "DOWNLOADS", tmp_dir / "Downloads" / "Secure Downloads")
    )
    stack.enter_context(mock.patch("subprocess.run"))
    _patch_audit_singleton(tmp_dir, stack)
    return stack


def _reset_leaky_loggers() -> None:
    """AuditLogger and AppGUI._setup_file_logging both add FileHandlers
    without ever removing prior ones. Left alone, repeated construction
    across tests stacks open file descriptors pointed at tmpdirs that have
    already been cleaned up, producing flaky errors on *later*, unrelated
    tests.
    """
    for name in (None, "audit"):
        target = logging.getLogger(name)
        for handler in list(target.handlers):
            handler.close()
            target.removeHandler(handler)


class GuiModuleImportSmokeTest(unittest.TestCase):
    def test_module_import_does_not_require_a_display(self):
        # gui.py's only module-scope Tk/CTk calls are ctk.set_appearance_mode(...)
        # and ctk.set_default_color_theme(...) — global config setters, not
        # window creation — so `import gui` must succeed with no display at all.
        # (Already implicitly exercised by importing this module; asserted here
        # explicitly as a regression guard.)
        self.assertTrue(hasattr(gui, "AppGUI"))
        self.assertTrue(hasattr(gui, "BitwardenLoginDialog"))
        self.assertTrue(hasattr(gui, "Dashboard"))


class CanvasWidgetSmokeTest(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()

    def tearDown(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def test_completion_ring_constructs(self):
        widget = gui.CompletionRing(self.root, percent=50)
        self.assertTrue(widget.winfo_exists())

    def test_brand_glyph_constructs(self):
        widget = gui.BrandGlyph(self.root)
        self.assertTrue(widget.winfo_exists())

    def test_initials_mark_constructs(self):
        widget = gui.InitialsMark(self.root, "AB")
        self.assertTrue(widget.winfo_exists())


class BitwardenLoginDialogSmokeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self._tmp.name)
        self._patches = contextlib.ExitStack()
        _patch_audit_singleton(self.tmp_dir, self._patches)
        self.root = tk.Tk()
        self.root.withdraw()

    def tearDown(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        self._patches.close()
        _reset_leaky_loggers()
        self._tmp.cleanup()

    def test_pin_setup_ui_builds_with_no_saved_pin(self):
        credential_store = CredentialStore(path=self.tmp_dir / "credentials.json")
        bw_service = mock.MagicMock()
        dialog = gui.BitwardenLoginDialog(
            self.root, bw_service, credential_store, on_success=lambda: None
        )
        try:
            self.assertTrue(dialog.winfo_exists())
        finally:
            try:
                dialog.destroy()
            except tk.TclError:
                pass

    def test_pin_unlock_ui_builds_with_a_saved_pin(self):
        credential_store = CredentialStore(path=self.tmp_dir / "credentials.json")
        # A PIN setup writes has_pin()'s four required keys; go through the real
        # PinAuth.setup() path so this exercises the same has_pin()-gated branch
        # the dialog itself checks, rather than hand-faking the store contents.
        from integrations import PinAuth

        setup_error = PinAuth(credential_store).setup(
            email="ops@example.com", master_password="horse battery", pin="Ops7"
        )
        self.assertIsNone(setup_error)

        bw_service = mock.MagicMock()
        dialog = gui.BitwardenLoginDialog(
            self.root, bw_service, credential_store, on_success=lambda: None
        )
        try:
            self.assertTrue(dialog.winfo_exists())
        finally:
            try:
                dialog.destroy()
            except tk.TclError:
                pass


class DashboardSheetSmokeTest(unittest.TestCase):
    """Real widget-construction coverage for Dashboard's in-window "sheet"
    builders — the highest-value untested surface in gui.py after the
    login dialog and AppGUI itself. A typo in a CTkButton call or a bad
    font= tuple in any of these would currently ship undetected.

    Builds a real Dashboard against a minimal stand-in for AppGUI (just
    the handful of attributes Dashboard.__init__ actually reads), rather
    than a full AppGUI() — Dashboard's own _build() is what actually
    constructs self._sheet / self.profile_viewer / etc. that these methods
    depend on, so a real Dashboard is what's needed, not a bypassed one.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self._tmp.name)
        self._patches = contextlib.ExitStack()
        _patch_audit_singleton(self.tmp_dir, self._patches)
        self._patches.enter_context(
            mock.patch.object(gui, "DOWNLOADS", self.tmp_dir / "Downloads" / "Secure Downloads")
        )
        self._patches.enter_context(mock.patch("subprocess.run"))

        self.credential_store = CredentialStore(path=self.tmp_dir / "credentials.json")
        self.transaction_db = transaction_db.TransactionDatabase(
            self.tmp_dir / "transactions.db", encryption_key="ab" * 32
        )
        self.profile_store = employee_profiles.EmployeeProfileStore(self.tmp_dir / "profiles.json")
        self.profile_sync = employee_profiles.ProfileSyncService(
            mock.MagicMock(), self.profile_store
        )

        self.root = tk.Tk()
        self.root.withdraw()

        class FakeApp:
            pass

        self.app = FakeApp()
        self.app.root = self.root
        self.app.credential_store = self.credential_store
        self.app.bw_service = mock.MagicMock()
        self.app.onboarding_logic = mock.MagicMock()
        self.app.transaction_db = self.transaction_db
        self.app.profile_store = self.profile_store
        self.app.profile_sync = self.profile_sync

        self.dashboard = gui.Dashboard(self.root, self.app)

    def tearDown(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        self._patches.close()
        _reset_leaky_loggers()
        self._tmp.cleanup()

    def test_open_sheet_builds_and_packs_a_real_widget_tree(self):
        built_hosts = []

        def builder(host):
            built_hosts.append(host)
            tk.Label(host, text="hello").pack()

        result_host = self.dashboard._open_sheet("Test sheet", builder)
        self.assertTrue(self.dashboard._sheet.winfo_manager())
        self.assertEqual(built_hosts, [result_host])
        self.assertTrue(result_host.winfo_exists())

    def test_open_settings_modal_builds_a_real_sheet(self):
        self.dashboard._open_settings_modal()
        self.assertTrue(self.dashboard._sheet.winfo_manager())

    def test_open_manual_employee_dialog_builds_a_real_form(self):
        self.dashboard._open_manual_employee_dialog()
        self.assertTrue(self.dashboard._sheet.winfo_manager())

    def test_render_profile_viewer_populates_the_existing_widget(self):
        self.assertTrue(hasattr(self.dashboard, "profile_viewer"))
        self.dashboard._render_profile_viewer("A test message")
        children = self.dashboard.profile_viewer.winfo_children()
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].cget("text"), "A test message")

    def test_show_next_budget_sheet_builds_a_real_sheet_when_queued(self):
        self.dashboard._budget_queue.append({"display_name": "Ada Lovelace"})
        self.dashboard._show_next_budget_sheet()
        self.assertTrue(self.dashboard._sheet.winfo_manager())
        self.assertEqual(self.dashboard._budget_queue, [])

    def test_show_next_budget_sheet_is_a_safe_noop_when_empty(self):
        self.dashboard._show_next_budget_sheet()
        self.assertFalse(self.dashboard._sheet.winfo_manager())

    def test_open_employee_modal_loads_a_seeded_profile_into_the_viewer(self):
        profile = self.profile_store.upsert(display_name="Ada Lovelace", first_name="Ada")
        employee_id = profile["employee_id"]

        self.dashboard._open_employee_modal(employee_id)
        # get_bundle() runs on a background thread and schedules its UI
        # update via self.after(0, ...); pump the Tk event queue instead of
        # touching internals to let that callback actually run.
        for _ in range(20):
            self.root.update()
            if self.dashboard.profile_bundle or self.dashboard.selected_profile_id:
                break
        self.assertEqual(self.dashboard.selected_profile_id, employee_id)
        self.assertEqual(self.dashboard.profile_title.get(), "Ada Lovelace")


class AppGUIConstructionSmokeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self._tmp.name)
        self._patches = _patch_all_app_data_paths(self.tmp_dir)

    def tearDown(self):
        self._patches.close()
        _reset_leaky_loggers()
        self._tmp.cleanup()

    def test_app_gui_constructs_without_a_real_bitwarden_login(self):
        calls = []

        class StubDialog:
            def __init__(self, parent, bw_service, credential_store, on_success):
                calls.append((parent, bw_service, credential_store, on_success))

            def wait_window(self):
                return None

        with mock.patch.object(gui, "BitwardenLoginDialog", StubDialog):
            app = gui.AppGUI()

        # AppGUI.__init__ falls through to constructing BitwardenLoginDialog
        # whenever there's no already-unlocked Bitwarden session (always true
        # for a freshly constructed BitwardenService with session_key=None) —
        # this asserts it reached that point with the right collaborators.
        self.assertEqual(len(calls), 1)
        parent, bw_service, credential_store, on_success = calls[0]
        self.assertIs(parent, app.root)
        self.assertIs(bw_service, app.bw_service)
        self.assertIs(credential_store, app.credential_store)
        self.assertTrue(callable(on_success))

        log_files = list((self.tmp_dir / "logs").glob("onboarding_*.log"))
        self.assertEqual(len(log_files), 1)

        db_path = self.tmp_dir / "transactions.db"
        self.assertTrue(db_path.exists())
        self.assertEqual(os.stat(db_path).st_mode & 0o777, 0o600)

        # The stub's wait_window() returns without ever setting _auth_ok=True,
        # so AppGUI falls through to _abort_startup(), which destroys self.root.
        # Don't touch app.root beyond this point.


def load_tests(loader, standard_tests, pattern):
    """Force AppGUIConstructionSmokeTest to run last.

    Empirically reproducible: constructing a real ctk.CTkToplevel (as
    BitwardenLoginDialogSmokeTest does) on a *new* Tk root, after AppGUI's
    own root+apply_theme() cycle has run and been torn down earlier in the
    *same process*, segfaults the interpreter (exit 139) — even though the
    reverse order, and repeated plain tk.Tk()/tk.Canvas cycles on their own,
    are both fine. This isn't a bug in these tests; it's this environment's
    Tcl/Tk + customtkinter global state not tolerating a second CTkToplevel
    generation after AppGUI's cycle. Keeping AppGUIConstructionSmokeTest last
    means nothing constructs a *new* CTkToplevel afterward, sidestepping it.
    """
    ordered_classes = [
        GuiModuleImportSmokeTest,
        CanvasWidgetSmokeTest,
        BitwardenLoginDialogSmokeTest,
        DashboardSheetSmokeTest,
        AppGUIConstructionSmokeTest,
    ]
    suite = unittest.TestSuite()
    for cls in ordered_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


if __name__ == "__main__":
    unittest.main()
