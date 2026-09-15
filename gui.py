#!/usr/bin/env python3
"""
Provision — secure employee onboarding appliance GUI.

Startup: PIN unlock (letters and/or numbers) decrypts Bitwarden master password.
Dashboard: intake → Bitwarden → partner accounts → lockdown.
Settings: disposal modes, provisioning toggles, collection config.
"""

from __future__ import annotations

import logging
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, TextIO, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

import customtkinter as ctk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD

    _DND_AVAILABLE = True
except Exception:
    DND_FILES = None  # type: ignore
    TkinterDnD = None  # type: ignore
    _DND_AVAILABLE = False

from account_automation import (
    ASSIST_FIELD_KEYS,
    ASSIST_FIELD_LABELS,
    ASSIST_FIELD_WALK_ORDER,
    assist_field_value,
    arrange_windows_for_assist,
    copy_to_clipboard,
    format_assist_payload,
    paste_field_value,
)
from audit_logger import get_audit_logger
from data_retention import DataRetentionManager
from employee_profiles import (
    EMPLOYEE_ID_FIELD,
    RECORD_ROLE_FIELD,
    EmployeeProfileStore,
    ProfileSyncService,
    RECORD_ROLES,
)
from hq_template import HQ_TEMPLATE_FIELDS, write_hq_file
from integrations import BitwardenService, CredentialStore, PinAuth, get_or_create_db_key
from onboarding import BitwardenConfig, Onboarding, OnboardingConfig
from secure_delete import (
    BW_SHRED_MODES,
    DEFAULT_BW_SHRED_MODE,
    DEFAULT_LOCAL_DELETE_MODE,
    LOCAL_DELETE_MODES,
)
from transaction_db import TransactionDatabase

# Intake watch folder: a locked-down subfolder of Downloads rather than
# Downloads itself, since it transiently holds unshredded employee PII
# (SSN, card numbers, DOB) between drop-off and pipeline disposal.
DOWNLOADS = Path.home() / "Downloads" / "Secure Downloads"


def _ensure_secure_watch_dir(path: Path = DOWNLOADS) -> Path:
    """Create/harden the HQ-file watch folder.

    Best-effort, idempotent, and safe to call repeatedly: owner-only
    permissions, refuses to reuse a symlink at that path (swap-attack
    protection), and — on macOS — excludes the folder from Spotlight
    indexing and Time Machine backups. None of this is required for the
    pipeline to function; it only reduces how long/widely sensitive intake
    files are exposed before disposal.
    """
    try:
        if path.is_symlink():
            logging.warning("Watch dir %s is a symlink; replacing it.", path)
            path.unlink()
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
    except OSError as exc:
        logging.warning("Could not create/harden watch dir %s: %s", path, exc)
        return path

    sentinel = path / ".metadata_never_index"
    if not sentinel.exists():
        try:
            sentinel.write_text("")
        except OSError:
            pass

    if sys.platform == "darwin":
        try:
            subprocess.run(
                ["tmutil", "addexclusion", str(path)],
                capture_output=True,
                check=False,
                timeout=5,
            )
        except Exception:
            pass

    return path

# shadcn-inspired neutral palette on the cool "slate" base: white cards,
# hairline borders, a single near-black primary, muted secondaries. Keys match
# the set the rest of this module references.
C = {
    "bg": "#f1f5f9",           # slate-100  app background
    "bg_wash": "#e2e8f0",      # slate-200  deeper wash behind panels
    "surface": "#f1f5f9",      # slate-100  secondary / muted panels
    "card": "#ffffff",         # white      cards & popovers
    "card_hi": "#e2e8f0",      # slate-200  hover
    "row_a": "#ffffff",        # white      table row (even)
    "row_b": "#f8fafc",        # slate-50   table row (odd)
    "border": "#e2e8f0",       # slate-200  hairline border
    "border_soft": "#f1f5f9",  # slate-100  softer divider
    "text": "#0f172a",         # slate-900  foreground
    "muted": "#64748b",        # slate-500  muted foreground
    "accent": "#0f172a",       # slate-900  primary
    "accent_hover": "#1e293b", # slate-800  primary hover
    "accent_dim": "#e2e8f0",   # slate-200  subtle selection tint
    "success": "#16a34a",      # green-600
    "warn": "#f59e0b",         # amber-500
    "danger": "#ef4444",       # red-500
    "danger_hover": "#fee2e2", # red-100    destructive hover
    "ink": "#0f172a",          # slate-900  dark text / marks
    "paper": "#ffffff",        # white      text on primary
    "status": "#64748b",       # slate-500
    "status_on_dark": "#cbd5e1",  # slate-300  text on the dark chrome bar
    "chrome": "#0f172a",       # slate-900  dark chrome (toolbar / footer)
}

# Radii — rounded but crisp (shadcn leans less pill-y than the sage build).
R_PANEL = 12
R_CTRL = 10
R_BTN = 8
R_CHIP = 8
R_MARK = 10

# Typography: SF on macOS (the target), Helvetica Neue fallback elsewhere;
# monospace only for vault/data.
if sys.platform == "darwin":
    UI = "SF Pro Text"
    UI_DISPLAY = "SF Pro Display"
    MONO = "SF Mono"
else:
    UI = "Helvetica Neue"
    UI_DISPLAY = "Helvetica Neue"
    MONO = "Menlo"

F_DISPLAY = (UI_DISPLAY, 20, "bold")
F_TITLE = (UI, 14, "bold")
F_BODY = (UI, 12)
F_CAPTION = (UI, 10)
F_DATA = (MONO, 10)
F_BRAND = (UI_DISPLAY, 16, "bold")

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("green")


def _ui_panel(parent: Any, **kwargs: Any) -> ctk.CTkFrame:
    opts: Dict[str, Any] = {
        "fg_color": C["card"],
        "corner_radius": R_PANEL,
        "border_width": 0,
    }
    opts.update(kwargs)
    return ctk.CTkFrame(parent, **opts)


def _ui_button(
    parent: Any,
    *,
    text: str,
    command: Callable[[], None],
    style: str = "ghost",
    **kwargs: Any,
) -> ctk.CTkButton:
    styles = {
        "primary": {
            "fg_color": C["accent"],
            "hover_color": C["accent_hover"],
            "text_color": C["paper"],
        },
        "ink": {
            "fg_color": C["chrome"],
            "hover_color": C["ink"],
            "text_color": C["paper"],
        },
        "ghost": {
            "fg_color": C["surface"],
            "hover_color": C["card_hi"],
            "text_color": C["ink"],
        },
        "quiet": {
            "fg_color": "transparent",
            "hover_color": C["accent_dim"],
            "text_color": C["muted"],
        },
        "danger": {
            "fg_color": "transparent",
            "hover_color": C["danger_hover"],
            "text_color": C["danger"],
        },
    }
    opts: Dict[str, Any] = {
        "text": text,
        "command": command,
        "corner_radius": R_BTN,
        "border_width": 0,
        "font": F_BODY,
        "cursor": "hand2",
        **styles.get(style, styles["ghost"]),
    }
    opts.update(kwargs)
    return ctk.CTkButton(parent, **opts)


def _filevault_status() -> tuple[Optional[bool], str]:
    if sys.platform != "darwin":
        return None, "Disk encryption status is only checked on macOS."
    try:
        proc = subprocess.run(
            ["fdesetup", "status"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        out = (proc.stdout or proc.stderr or "").strip()
        if "FileVault is On" in out:
            return True, out
        if "FileVault is Off" in out:
            return False, out
        return None, out or "Unable to determine FileVault status."
    except Exception as e:
        return None, f"Unable to check FileVault: {e}"


def apply_theme(root: tk.Tk) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=C["bg"])
    style.configure(".", background=C["card"], foreground=C["text"], fieldbackground=C["card"])
    style.configure("TFrame", background=C["card"])
    style.configure("Card.TFrame", background=C["surface"])
    style.configure("Surface.TFrame", background=C["surface"])
    style.configure("TLabel", background=C["card"], foreground=C["text"], font=F_BODY)
    style.configure("Muted.TLabel", background=C["card"], foreground=C["muted"], font=F_CAPTION)
    style.configure("Title.TLabel", background=C["card"], foreground=C["text"], font=F_DISPLAY)
    style.configure("Subtitle.TLabel", background=C["card"], foreground=C["muted"], font=F_BODY)
    style.configure("CardTitle.TLabel", background=C["surface"], foreground=C["text"], font=F_TITLE)
    style.configure("CardMuted.TLabel", background=C["surface"], foreground=C["muted"], font=F_DATA)
    style.configure("Icon.TLabel", background=C["surface"], foreground=C["accent"], font=F_BRAND)
    style.configure("Drop.TLabel", background=C["card"], foreground=C["text"], font=F_TITLE)
    style.configure("TButton", background=C["surface"], foreground=C["text"], padding=(14, 8), font=F_CAPTION)
    style.map("TButton", background=[("active", C["card_hi"])])
    style.configure(
        "Accent.TButton",
        background=C["accent"],
        foreground=C["paper"],
        padding=(16, 10),
        font=F_TITLE,
    )
    style.map("Accent.TButton", background=[("active", C["accent_hover"])])
    style.configure("TEntry", fieldbackground=C["card"], foreground=C["text"], insertcolor=C["text"])
    style.configure("TCheckbutton", background=C["card"], foreground=C["text"], font=F_BODY)
    style.configure("TLabelframe", background=C["card"], foreground=C["text"], bordercolor=C["border_soft"])
    style.configure("TLabelframe.Label", background=C["card"], foreground=C["muted"], font=F_CAPTION)
    style.configure("TNotebook", background=C["bg"], borderwidth=0)
    style.configure("TNotebook.Tab", background=C["surface"], foreground=C["muted"], padding=(16, 8))
    style.map("TNotebook.Tab", background=[("selected", C["card"])], foreground=[("selected", C["text"])])
    style.configure("TCombobox", fieldbackground=C["card"], foreground=C["text"], background=C["card"])
    style.configure(
        "Treeview",
        background=C["surface"],
        foreground=C["text"],
        fieldbackground=C["surface"],
        rowheight=36,
        borderwidth=0,
        font=F_DATA,
    )
    style.configure(
        "Treeview.Heading",
        background=C["surface"],
        foreground=C["muted"],
        borderwidth=0,
        padding=(10, 8),
        font=F_CAPTION,
    )
    style.map(
        "Treeview.Heading",
        background=[("active", C["card_hi"])],
        foreground=[("active", C["ink"])],
    )
    return style


class CompletionRing(tk.Canvas):
    """Compact progress ring — olive when complete, ink otherwise."""

    def __init__(self, master: Any, percent: int, size: int = 48, *, bg: Optional[str] = None):
        canvas_bg = bg or C["card"]
        super().__init__(
            master,
            width=size,
            height=size,
            bg=canvas_bg,
            highlightthickness=0,
            borderwidth=0,
        )
        inset = 4
        self.create_oval(
            inset,
            inset,
            size - inset,
            size - inset,
            outline=C["border"],
            width=2,
        )
        if percent:
            self.create_arc(
                inset,
                inset,
                size - inset,
                size - inset,
                start=90,
                extent=-(360 * min(percent, 100) / 100),
                style=tk.ARC,
                outline=C["accent"] if percent >= 80 else C["ink"],
                width=2,
            )
        self.create_text(
            size / 2,
            size / 2,
            text=str(percent),
            fill=C["ink"],
            font=("Menlo", 7, "bold"),
        )


class BrandGlyph(tk.Canvas):
    """Soft DL mark — rounded fill, no hard frame."""

    def __init__(self, master: Any, size: int = 30, *, bg: Optional[str] = None, ink: Optional[str] = None):
        canvas_bg = bg if bg is not None else C["card"]
        stroke = ink if ink is not None else C["accent"]
        super().__init__(
            master,
            width=size,
            height=size,
            bg=canvas_bg,
            highlightthickness=0,
            borderwidth=0,
        )
        pad = 1
        self.create_oval(
            pad,
            pad,
            size - pad,
            size - pad,
            fill=C["accent_dim"],
            outline="",
        )
        self.create_text(
            size / 2,
            size / 2 + 0.5,
            text="DL",
            fill=stroke,
            font=(UI, max(9, size // 3), "bold"),
        )


class InitialsMark(tk.Canvas):
    """Soft initials pill for the people list."""

    def __init__(
        self,
        master: Any,
        initials: str,
        *,
        size: int = 32,
        selected: bool = False,
        bg: Optional[str] = None,
    ):
        canvas_bg = bg or C["card"]
        super().__init__(
            master,
            width=size,
            height=size,
            bg=canvas_bg,
            highlightthickness=0,
            borderwidth=0,
        )
        pad = 1
        fill = C["accent"] if selected else C["accent_dim"]
        self.create_oval(
            pad,
            pad,
            size - pad,
            size - pad,
            fill=fill,
            outline="",
        )
        self.create_text(
            size / 2,
            size / 2 + 0.5,
            text=(initials or "—")[:2].upper(),
            fill=C["paper"] if selected else C["accent"],
            font=(UI, 10, "bold"),
        )


# Back-compat alias used by older call sites during restyle.
KeyTag = InitialsMark


def _auth_shell(dialog: ctk.CTkToplevel, *, height: int) -> ctk.CTkFrame:
    """Unlock panel: soft wash + floating rounded card."""
    dialog.resizable(False, False)
    dialog.configure(fg_color=C["bg"])
    dialog.update_idletasks()
    width = 440
    screen_w = max(dialog.winfo_screenwidth(), width)
    screen_h = max(dialog.winfo_screenheight(), height)
    x = max((screen_w - width) // 2, 40)
    y = max((screen_h - height) // 3, 40)
    dialog.geometry(f"{width}x{height}+{x}+{y}")
    shell = ctk.CTkFrame(dialog, fg_color=C["bg"], corner_radius=0)
    shell.pack(fill=tk.BOTH, expand=True)
    # Subtle depth band behind the card.
    wash = ctk.CTkFrame(shell, fg_color=C["bg_wash"], corner_radius=0)
    wash.place(relx=0, rely=0.55, relwidth=1, relheight=0.45)
    card = _ui_panel(shell)
    card.pack(fill=tk.BOTH, expand=True, padx=22, pady=22)
    return card


def _present_auth_dialog(dialog: ctk.CTkToplevel, parent: tk.Tk) -> None:
    """Force the unlock dialog on-screen (CTkToplevel stays hidden if parent is withdrawn)."""

    def show() -> None:
        try:
            if not dialog.winfo_exists():
                return
        except tk.TclError:
            return
        try:
            dialog.transient(parent)
        except tk.TclError:
            pass
        dialog.update_idletasks()
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
        try:
            dialog.attributes("-topmost", True)
        except tk.TclError:
            pass
        try:
            dialog.grab_set()
        except tk.TclError:
            pass

    show()
    dialog.after(50, show)
    dialog.after(220, show)
    dialog.after(400, lambda: dialog.attributes("-topmost", False) if dialog.winfo_exists() else None)


def _auth_brand(parent: ctk.CTkFrame, title: str, subtitle: str) -> None:
    header = ctk.CTkFrame(parent, fg_color="transparent", corner_radius=0)
    header.pack(fill=tk.X, padx=32, pady=(32, 20))
    mark = ctk.CTkFrame(
        header,
        width=56,
        height=56,
        corner_radius=R_MARK,
        fg_color=C["surface"],
    )
    mark.pack()
    mark.pack_propagate(False)
    BrandGlyph(mark, size=48, bg=C["surface"], ink=C["accent"]).pack(expand=True)
    ctk.CTkLabel(
        header,
        text="Provision",
        font=F_BRAND,
        text_color=C["ink"],
    ).pack(pady=(16, 4))
    ctk.CTkLabel(
        header,
        text=title,
        font=F_TITLE,
        text_color=C["text"],
    ).pack()
    ctk.CTkLabel(
        header,
        text=subtitle,
        font=F_BODY,
        text_color=C["muted"],
        wraplength=320,
        justify="center",
    ).pack(pady=(8, 0))


def _auth_field_label(parent: ctk.CTkFrame, text: str) -> None:
    ctk.CTkLabel(
        parent,
        text=text,
        font=F_CAPTION,
        text_color=C["muted"],
        anchor="w",
    ).pack(fill=tk.X, pady=(0, 6))


def _auth_entry(
    parent: ctk.CTkFrame,
    *,
    textvariable: tk.StringVar,
    show: str = "",
    placeholder: str = "",
) -> ctk.CTkEntry:
    entry = ctk.CTkEntry(
        parent,
        textvariable=textvariable,
        height=44,
        corner_radius=R_CTRL,
        border_width=0,
        fg_color=C["surface"],
        text_color=C["text"],
        placeholder_text=placeholder,
        placeholder_text_color=C["muted"],
        font=F_BODY,
        show=show,
    )
    entry.pack(fill=tk.X, pady=(0, 12))
    return entry


def _auth_primary_button(parent: ctk.CTkFrame, text: str, command: Callable[[], None]) -> ctk.CTkButton:
    button = _ui_button(
        parent,
        text=text,
        command=command,
        style="primary",
        height=46,
        font=F_TITLE,
    )
    button.pack(fill=tk.X, pady=(8, 0))
    return button


class BitwardenLoginDialog(ctk.CTkToplevel):
    """Gate the app: first-run Bitwarden + PIN setup, then PIN unlock thereafter."""

    def __init__(
        self,
        parent: tk.Tk,
        bw_service: BitwardenService,
        credential_store: CredentialStore,
        on_success: Callable[[], None],
    ):
        super().__init__(parent)
        self.bw_service = bw_service
        self.credential_store = credential_store
        self.pin_auth = PinAuth(credential_store)
        self.on_success = on_success
        self.audit = get_audit_logger()
        self.success = False
        self._form: Optional[ctk.CTkFrame] = None
        self._card: Optional[ctk.CTkFrame] = None

        self.title("Provision")
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self._build_ui()
        _present_auth_dialog(self, parent)

    def _on_cancel(self):
        self.bw_service.clear_session()
        self.audit.log_authentication(False, method="pin_cancelled")
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
        try:
            self.master.destroy()
        except tk.TclError:
            pass

    def _clear_form(self) -> None:
        if self._form is not None:
            self._form.destroy()
            self._form = None

    def _build_ui(self):
        height = 520 if self.pin_auth.has_pin() else 640
        self._card = _auth_shell(self, height=height)
        if self.pin_auth.has_pin():
            self._build_pin_unlock()
        else:
            self._build_pin_setup()

    def _rebuild(self) -> None:
        if self._card is not None:
            self._card.destroy()
            self._card = None
        self._build_ui()
        _present_auth_dialog(self, self.master)

    def _finish_success(self, method: str) -> None:
        self.audit.log_authentication(True, method=method)
        self.success = True
        self.destroy()
        self.on_success()

    def _bw_login_or_unlock(self, email: str, password: str, status_var: tk.StringVar) -> Dict[str, Any]:
        try:
            status = self.bw_service.get_status()
        except Exception:
            status = "unauthenticated"

        if status in {"unlocked", "locked"}:
            ok = self.bw_service.unlock(password)
            return {"success": ok, "error": None if ok else "Incorrect master password."}

        result = self.bw_service.login(email, password)
        if result.get("two_factor_required"):
            code = simpledialog.askstring("Two-Factor", "Enter your 2FA code:", parent=self)
            if not code:
                self.bw_service.clear_session()
                self.audit.log_authentication(False, method="bitwarden_2fa_cancelled")
                status_var.set("")
                return {"success": False, "error": "Two-factor cancelled."}
            result = self.bw_service.login(email, password, code)
        return result

    def _build_pin_setup(self) -> None:
        assert self._card is not None
        _auth_brand(
            self._card,
            "Create your PIN",
            "4–8 letters and/or numbers. Bitwarden unlocks once; the PIN opens Provision next time.",
        )
        form = ctk.CTkFrame(self._card, fg_color="transparent", corner_radius=0)
        form.pack(fill=tk.BOTH, expand=True, padx=28, pady=(0, 28))
        self._form = form

        _auth_field_label(form, "Bitwarden Email")
        email_var = tk.StringVar(value=self.credential_store.get("bw_email", ""))
        _auth_entry(form, textvariable=email_var, placeholder="you@company.com")

        _auth_field_label(form, "Master Password")
        password_var = tk.StringVar()
        _auth_entry(form, textvariable=password_var, show="•")

        _auth_field_label(form, "PIN (4–8 letters or numbers)")
        pin_var = tk.StringVar()
        pin_entry = _auth_entry(form, textvariable=pin_var, show="•", placeholder="e.g. Ops7")

        _auth_field_label(form, "Confirm PIN")
        pin2_var = tk.StringVar()
        pin2_entry = _auth_entry(form, textvariable=pin2_var, show="•")

        status_var = tk.StringVar(value="")
        ctk.CTkLabel(
            form,
            textvariable=status_var,
            font=F_BODY,
            text_color=C["muted"],
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 4))

        def do_setup():
            email = email_var.get().strip()
            password = password_var.get()
            pin = pin_var.get()
            pin2 = pin2_var.get()
            if pin != pin2:
                messagebox.showerror("PIN mismatch", "PIN and confirmation do not match.", parent=self)
                return
            err = self.pin_auth.validate_pin(pin)
            if err:
                messagebox.showerror("Invalid PIN", err, parent=self)
                return
            if not email or not password:
                messagebox.showerror("Required", "Enter Bitwarden email and master password.", parent=self)
                return

            status_var.set("Signing in to Bitwarden…")
            self.update_idletasks()
            result = self._bw_login_or_unlock(email, password, status_var)
            if not result.get("success"):
                self.audit.log_authentication(False, method="bitwarden_pin_setup")
                status_var.set("")
                messagebox.showerror(
                    "Bitwarden Login Failed",
                    result.get("error") or "Could not sign in.",
                    parent=self,
                )
                return

            setup_err = self.pin_auth.setup(email=email, master_password=password, pin=pin)
            if setup_err:
                status_var.set("")
                messagebox.showerror("PIN setup failed", setup_err, parent=self)
                return
            self._finish_success("bitwarden_pin_setup")

        _auth_primary_button(form, "Save PIN & Unlock", do_setup)
        pin2_entry.bind("<Return>", lambda _event: do_setup())
        pin_entry.focus()
        ctk.CTkLabel(
            form,
            text="Your master password is encrypted with the PIN and stored only on this Mac.",
            font=F_BODY,
            text_color=C["muted"],
            wraplength=300,
            justify="center",
        ).pack(pady=(16, 0))

    def _build_pin_unlock(self) -> None:
        assert self._card is not None
        email = self.credential_store.get("bw_email", "") or "your vault"
        _auth_brand(
            self._card,
            "Enter your PIN",
            f"Unlocks Bitwarden for {email}.",
        )
        form = ctk.CTkFrame(self._card, fg_color="transparent", corner_radius=0)
        form.pack(fill=tk.BOTH, expand=True, padx=28, pady=(0, 28))
        self._form = form

        _auth_field_label(form, "PIN")
        pin_var = tk.StringVar()
        pin_entry = _auth_entry(form, textvariable=pin_var, show="•", placeholder="4–8 letters or numbers")

        status_var = tk.StringVar(value="")
        ctk.CTkLabel(
            form,
            textvariable=status_var,
            font=F_BODY,
            text_color=C["muted"],
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 4))

        def refresh_lock():
            remaining = self.pin_auth.lock_remaining()
            if remaining > 0:
                status_var.set(f"Too many attempts — locked for {remaining}s")
                self.after(1000, refresh_lock)
            elif status_var.get().startswith("Too many attempts"):
                status_var.set("")

        def do_unlock():
            pin = pin_var.get()
            err = self.pin_auth.validate_pin(pin)
            if err:
                messagebox.showerror("Invalid PIN", err, parent=self)
                return
            outcome = self.pin_auth.attempt_unlock(pin)
            if outcome["status"] == "locked":
                self.audit.log_authentication(False, method="pin_locked")
                refresh_lock()
                messagebox.showerror(
                    "Too many attempts",
                    f"PIN entry is locked. Try again in {outcome['remaining']} seconds.",
                    parent=self,
                )
                return
            if outcome["status"] == "bad_pin":
                self.audit.log_authentication(False, method="pin")
                left = outcome["attempts_left"]
                message = "That PIN did not unlock this workspace."
                if left <= 2:
                    message += (
                        f"\n\n{left} attempt(s) left before a timed lockout."
                    )
                messagebox.showerror("Incorrect PIN", message, parent=self)
                return
            master = outcome["password"]
            email_addr = str(self.credential_store.get("bw_email", "") or "").strip()
            if not email_addr:
                messagebox.showerror("Missing email", "No Bitwarden email on file. Reset PIN setup.", parent=self)
                return
            status_var.set("Unlocking Bitwarden…")
            self.update_idletasks()
            result = self._bw_login_or_unlock(email_addr, master, status_var)
            if result.get("success"):
                self._finish_success("pin")
            else:
                self.audit.log_authentication(False, method="pin_bitwarden")
                status_var.set("")
                messagebox.showerror(
                    "Bitwarden Unlock Failed",
                    result.get("error") or "Could not unlock the vault.",
                    parent=self,
                )

        def reset_pin():
            if not messagebox.askyesno(
                "Reset PIN?",
                "Clear the saved PIN and set up again with your Bitwarden master password?",
                parent=self,
            ):
                return
            self.pin_auth.clear()
            self.bw_service.clear_session()
            self._rebuild()

        _auth_primary_button(form, "Unlock", do_unlock)
        pin_entry.bind("<Return>", lambda _event: do_unlock())
        pin_entry.focus()
        refresh_lock()
        ctk.CTkButton(
            form,
            text="Forgot PIN — reset setup",
            command=reset_pin,
            height=32,
            corner_radius=R_CTRL,
            border_width=0,
            fg_color="transparent",
            hover_color=C["accent_dim"],
            text_color=C["muted"],
            font=F_BODY,
            cursor="hand2",
        ).pack(fill=tk.X, pady=(14, 0))


class QueueStreamWriter:
    def __init__(self, log_queue: queue.Queue[str], original_stream: TextIO):
        self.log_queue = log_queue
        self.original_stream = original_stream

    def write(self, s: str, /) -> int:
        stripped = s.strip()
        if stripped:
            self.log_queue.put(stripped)
        return len(s)

    def flush(self) -> None:
        self.original_stream.flush()


class QueueHandler(logging.Handler):
    def __init__(self, log_queue: queue.Queue[str]):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord):
        self.log_queue.put(self.format(record))


class AppGUI:
    def __init__(self):
        self.root: Any = TkinterDnD.Tk() if _DND_AVAILABLE else tk.Tk()
        # Keep root mapped but invisible during auth so CTk dialogs can appear on macOS.
        # withdraw() hides child unlock windows; off-screen geometry shows a blank window.
        self.root.title("Provision")
        self.root.geometry("1x1+0+0")
        self.root.minsize(1, 1)
        try:
            self.root.attributes("-alpha", 0.0)
        except tk.TclError:
            self.root.withdraw()
        self.session_log_path: Path | None = None
        apply_theme(self.root)

        self.credential_store = CredentialStore()
        self.bw_service = BitwardenService()
        self.transaction_db = TransactionDatabase(
            encryption_key=get_or_create_db_key(self.credential_store)
        )
        self.profile_store = EmployeeProfileStore()
        self.profile_sync = ProfileSyncService(self.bw_service, self.profile_store)
        self.audit = get_audit_logger()
        self.retention_manager = DataRetentionManager(
            self.transaction_db,
            prompt_callback=self._queue_retention_prompt,
            profile_sync=self.profile_sync,
        )
        self.profile_store.migrate_retention(self.retention_manager.retention_data)
        for profile in self.profile_store.list_profiles(include_purged=True):
            self.transaction_db.link_employee(
                profile.get("display_name", ""),
                profile["employee_id"],
            )
        self.onboarding_logic = Onboarding(
            self.bw_service,
            retention_manager=self.retention_manager,
            profile_store=self.profile_store,
            profile_sync=self.profile_sync,
        )
        self.onboarding_logic.account_creator.prefer_system_browser = True
        self._pending_retention_prompts: queue.Queue = queue.Queue()
        self._setup_file_logging()
        self._auth_ok = False
        self.root.protocol("WM_DELETE_WINDOW", self._shutdown)

        if self.bw_service.session_key and self._bw_ready():
            self._auth_ok = True
            self._post_auth()
        else:
            dialog = BitwardenLoginDialog(
                self.root, self.bw_service, self.credential_store, self._on_auth_success
            )
            dialog.wait_window()
            if not self._auth_ok:
                self._abort_startup()

    def _abort_startup(self):
        try:
            if self.root.winfo_exists():
                self.root.destroy()
        except tk.TclError:
            pass

    def _bw_ready(self) -> bool:
        try:
            return self.bw_service.get_status() in {"unlocked", "locked"} and bool(
                self.bw_service.session_key
            )
        except Exception:
            return False

    def _on_auth_success(self):
        self._auth_ok = True
        self._post_auth()

    def _post_auth(self):
        self.retention_manager.start_scheduler(check_interval_hours=24)
        self.build_main_screen()
        self.root.after(250, self._drain_retention_prompts)
        self.root.after(500, self._warn_if_filevault_off)
        if self.credential_store.get("sync_on_startup", "true") == "true":
            # Local refresh only on launch — full Bitwarden pull is the Sync button.
            self.root.after(750, lambda: self.dashboard._sync_profiles(pull=False))

    def _shutdown(self):
        self.retention_manager.stop_scheduler()
        self.bw_service.clear_session()
        self.audit.log_security_event("session_closed", "Application window closed")
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def _warn_if_filevault_off(self):
        enabled, detail = _filevault_status()
        if enabled is False:
            self.audit.log_security_event("filevault_off", detail)
            dash = getattr(self, "dashboard", None)
            if dash is not None:
                dash._confirm_in_window(
                    "FileVault recommended",
                    "FileVault is Off.\n\n"
                    "Local employee files and the transaction database are not "
                    "encrypted at rest without full-disk encryption.\n\n"
                    "Enable FileVault before production use.\n\n"
                    f"({detail})",
                    lambda: None,
                    yes_label="Got it",
                    no_label="Dismiss",
                )
            else:
                messagebox.showwarning(
                    "FileVault recommended",
                    "FileVault is Off. Enable it before production use.\n\n"
                    f"({detail})",
                    parent=self.root,
                )

    def _queue_retention_prompt(self, action: dict):
        self._pending_retention_prompts.put(action)

    def _drain_retention_prompts(self):
        dash = getattr(self, "dashboard", None)
        if dash is not None and dash._sheet.winfo_manager():
            # Wait until the current in-window sheet closes.
            try:
                if self.root.winfo_exists():
                    self.root.after(250, self._drain_retention_prompts)
            except tk.TclError:
                pass
            return
        try:
            action = self._pending_retention_prompts.get_nowait()
        except queue.Empty:
            action = None
        if action is not None:
            self._show_retention_prompt(action)
        try:
            if self.root.winfo_exists():
                self.root.after(250, self._drain_retention_prompts)
        except tk.TclError:
            pass

    def _show_retention_prompt(self, action: dict):
        employee = action["employee"]
        day = action["day"]
        message = action["message"]
        dash = getattr(self, "dashboard", None)
        if dash is None:
            if day == 5:
                answer = messagebox.askyesno(
                    "Retention (Day 5)", f"{message}\n\nYes = still active"
                )
                self.retention_manager.process_audit_response(
                    employee, 5, "yes" if answer else "no"
                )
            elif day == 10:
                answer = messagebox.askyesno(
                    "Retention (Day 10)", f"{message}\n\nYes = shred"
                )
                self.retention_manager.process_audit_response(
                    employee, 10, "yes" if answer else "no"
                )
            return

        if day == 5:
            title = "Retention · Day 5"
            yes_label = "Still active"
            no_label = "Not active"
        elif day == 10:
            title = "Retention · Day 10"
            yes_label = "Shred"
            no_label = "Keep"
        else:
            return

        def yes() -> None:
            self.retention_manager.process_audit_response(employee, day, "yes")

        def no() -> None:
            self.retention_manager.process_audit_response(employee, day, "no")

        dash._confirm_in_window(
            title,
            message,
            yes,
            yes_label=yes_label,
            no_label=no_label,
            on_no=no,
        )

    def build_main_screen(self):
        self.root.title("Provision")
        self.root.minsize(420, 480)
        self.root.geometry("480x560+120+60")
        for child in self.root.winfo_children():
            child.destroy()
        self.dashboard = Dashboard(self.root, self)
        try:
            self.root.attributes("-alpha", 1.0)
        except tk.TclError:
            pass
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(350, lambda: self.root.attributes("-topmost", False))
        self.root.focus_force()

    def run(self):
        self.root.mainloop()

    def _setup_file_logging(self):
        from data_retention import LOGS_DIR

        log_dir = LOGS_DIR
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(log_dir, 0o700)
        except OSError:
            pass
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = log_dir / f"onboarding_{timestamp}.log"
        self.session_log_path = log_file
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] - %(message)s"))
        logging.getLogger().addHandler(file_handler)
        logging.getLogger().setLevel(logging.INFO)


class Dashboard(ttk.Frame):
    """Single-window workspace: people list + ledger + action modals."""

    def __init__(self, parent: tk.Tk, app: AppGUI):
        super().__init__(parent)
        self.pack(fill=tk.BOTH, expand=True)
        self.app = app
        self.store = app.credential_store
        self.bw = app.bw_service
        self.onboarding = app.onboarding_logic
        self.transaction_db = app.transaction_db
        self.profile_store = app.profile_store
        self.profile_sync = app.profile_sync
        self.audit = get_audit_logger()

        self.shared_passphrase = tk.StringVar(
            value=self.store.get("shared_passphrase", "")
        )
        self.collection_name = tk.StringVar(
            value=self.store.get("collection_name", "Personal Vault")
        )
        self.auto_import = tk.BooleanVar(
            value=self.store.get("auto_import", "true") == "true"
        )
        self.sync_on_startup = tk.BooleanVar(
            value=self.store.get("sync_on_startup", "true") == "true"
        )
        self.provision_outlook = tk.BooleanVar(
            value=self.store.get("provision_outlook", "true") == "true"
        )
        self.provision_hyatt = tk.BooleanVar(
            value=self.store.get("provision_hyatt", "true") == "true"
        )
        self.provision_marriott = tk.BooleanVar(
            value=self.store.get("provision_marriott", "true") == "true"
        )
        self.local_delete_mode = tk.StringVar(
            value=self.store.get("local_delete_mode", DEFAULT_LOCAL_DELETE_MODE)
        )
        self.bw_shred_mode = tk.StringVar(
            value=self.store.get("bw_shred_mode", DEFAULT_BW_SHRED_MODE)
        )

        self.workflow_step = tk.StringVar(value="ready")
        self.status = tk.StringVar(value="Watching Downloads/Secure Downloads for HQ files…")
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.step_labels: Dict[str, tk.Label] = {}
        self._pipeline_running = False
        self.selected_employee: Optional[str] = None
        self.selected_profile_id: Optional[str] = None
        self.selected_record_role = "identity"
        self.profile_bundle: Dict[str, Dict[str, Any]] = {}
        self._revealed_profile_values: Set[Tuple[str, str]] = set()
        self._ledger_employee_map: Dict[str, str] = {}
        self._assist_panel: Optional[ctk.CTkFrame] = None
        self._assist_window: Optional[ctk.CTkToplevel] = None
        self._assist_event = threading.Event()
        self._assist_decision = "skip"
        self._assist_personal: Dict[str, str] = {}
        self._assist_service = ""
        self._assist_field_index = 0
        self._sheet_close_callback: Optional[Callable[[], None]] = None
        self._budget_queue: List[Dict[str, Any]] = []

        _ensure_secure_watch_dir()
        self._build()
        self._bind_assist_hotkeys()
        self._configure_logging()
        self.after(100, self._poll_log_queue)
        self._refresh_queued_files()
        threading.Thread(target=self._monitor_downloads, daemon=True).start()

    def _build(self):
        shell = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        shell.pack(fill=tk.BOTH, expand=True)

        # Soft masthead — floating brand, no ink rule
        header = ctk.CTkFrame(shell, fg_color=C["bg"], height=64, corner_radius=0)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        mast = ctk.CTkFrame(header, fg_color="transparent")
        mast.pack(fill=tk.BOTH, expand=True, padx=18, pady=(14, 6))

        brand = ctk.CTkFrame(mast, fg_color="transparent")
        brand.pack(side=tk.LEFT)
        mark = ctk.CTkFrame(brand, width=36, height=36, corner_radius=R_MARK, fg_color=C["card"])
        mark.pack(side=tk.LEFT)
        mark.pack_propagate(False)
        BrandGlyph(mark, size=34, bg=C["card"], ink=C["accent"]).pack(expand=True)
        title_col = ctk.CTkFrame(brand, fg_color="transparent")
        title_col.pack(side=tk.LEFT, padx=(10, 0))
        ctk.CTkLabel(
            title_col,
            text="Provision",
            font=F_BRAND,
            text_color=C["ink"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_col,
            text="ops desk",
            font=F_CAPTION,
            text_color=C["muted"],
        ).pack(anchor="w")

        actions = ctk.CTkFrame(mast, fg_color="transparent")
        actions.pack(side=tk.RIGHT)
        _ui_button(
            actions,
            text="Sync",
            command=self._sync_profiles,
            style="primary",
            width=72,
            height=34,
            font=F_CAPTION,
        ).pack(side=tk.LEFT, padx=(0, 8))
        _ui_button(
            actions,
            text="···",
            command=self._open_settings_modal,
            style="ghost",
            width=36,
            height=34,
            font=F_TITLE,
        ).pack(side=tk.LEFT)

        content = ctk.CTkFrame(shell, fg_color="transparent")
        content.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 10))
        self._content = content

        body = ctk.CTkFrame(content, fg_color="transparent")
        body.pack(fill=tk.BOTH, expand=True)
        self._workspace = body
        body.grid_columnconfigure(0, weight=0, minsize=200)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._sheet = ctk.CTkFrame(content, fg_color=C["bg"], corner_radius=0)

        # Left: names only
        people = _ui_panel(body, width=200)
        people.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        people.grid_propagate(False)
        head = ctk.CTkFrame(people, fg_color="transparent")
        head.pack(fill=tk.X, padx=14, pady=(14, 6))
        ctk.CTkLabel(
            head,
            text="Employee List",
            font=F_CAPTION,
            text_color=C["muted"],
        ).pack(side=tk.LEFT)
        self.employee_count = tk.StringVar(value="0")
        ctk.CTkLabel(
            head,
            textvariable=self.employee_count,
            font=F_DATA,
            text_color=C["accent"],
        ).pack(side=tk.RIGHT)

        self.employee_scroll = ctk.CTkScrollableFrame(
            people,
            fg_color="transparent",
            corner_radius=0,
        )
        self.employee_scroll.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))
        self.employee_grid = self.employee_scroll

        intake = ctk.CTkFrame(people, fg_color="transparent")
        intake.pack(fill=tk.X, padx=12, pady=(0, 14))
        _ui_button(
            intake,
            text="Manual",
            command=self._open_manual_employee_dialog,
            style="primary",
            height=34,
            font=F_CAPTION,
        ).pack(fill=tk.X, pady=(0, 6))
        row = ctk.CTkFrame(intake, fg_color="transparent")
        row.pack(fill=tk.X)
        _ui_button(
            row,
            text="File",
            command=self._browse_files,
            style="ghost",
            height=34,
            font=F_CAPTION,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        _ui_button(
            row,
            text="Run",
            command=lambda: self.run_pipeline(quiet=False),
            style="ink",
            height=34,
            font=F_CAPTION,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Right: full profile + employee actions
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(0, weight=3)
        right.grid_rowconfigure(1, weight=0)
        right.grid_columnconfigure(0, weight=1)

        profile_card = _ui_panel(right)
        profile_card.grid(row=0, column=0, sticky="nsew", pady=(0, 12))
        self._profile_card = profile_card

        # Blank until an employee is selected; then title becomes their name.
        self.profile_title = tk.StringVar(value="")
        self.profile_subtitle = tk.StringVar(value="")
        self._profile_top = ctk.CTkFrame(profile_card, fg_color="transparent")
        ctk.CTkLabel(
            self._profile_top,
            textvariable=self.profile_title,
            font=F_DISPLAY,
            text_color=C["ink"],
            anchor="w",
        ).pack(side=tk.LEFT)
        self.profile_edit_button = _ui_button(
            self._profile_top,
            text="Edit",
            command=self._edit_selected_identity,
            style="primary",
            width=64,
            height=34,
            font=F_CAPTION,
            state=tk.DISABLED,
        )
        self.profile_edit_button.pack(side=tk.RIGHT)
        self._profile_subtitle_label = ctk.CTkLabel(
            profile_card,
            textvariable=self.profile_subtitle,
            font=F_CAPTION,
            text_color=C["muted"],
            anchor="w",
        )

        self._role_rail = ctk.CTkFrame(profile_card, fg_color="transparent")
        self.record_buttons = {}
        labels = {
            "identity": "Identity",
            "email_login": "Email",
            "work_card": "Card",
            "hyatt_login": "Hyatt",
            "marriott_login": "Marriott",
        }
        for role in RECORD_ROLES:
            btn = ctk.CTkButton(
                self._role_rail,
                text=labels.get(role, role),
                command=lambda r=role: self._show_profile_record(r),
                width=78,
                height=32,
                corner_radius=R_CHIP,
                fg_color=C["surface"],
                hover_color=C["card_hi"],
                text_color=C["muted"],
                font=F_CAPTION,
            )
            btn.pack(side=tk.LEFT, padx=3, pady=2)
            self.record_buttons[role] = btn

        self.profile_viewer = ctk.CTkScrollableFrame(
            profile_card,
            fg_color="transparent",
            corner_radius=0,
        )
        self.profile_viewer.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 14))

        actions_card = _ui_panel(right)
        actions_card.grid(row=1, column=0, sticky="ew")
        ahead = ctk.CTkFrame(actions_card, fg_color="transparent")
        ahead.pack(fill=tk.X, padx=16, pady=(14, 6))
        ctk.CTkLabel(
            ahead,
            text="Actions",
            font=F_CAPTION,
            text_color=C["muted"],
        ).pack(side=tk.LEFT)
        self.actions_hint = tk.StringVar(value="")
        ctk.CTkLabel(
            ahead,
            textvariable=self.actions_hint,
            font=F_CAPTION,
            text_color=C["status"],
        ).pack(side=tk.RIGHT)
        self._set_profile_panel_populated(False)

        action_row = ctk.CTkFrame(actions_card, fg_color="transparent")
        action_row.pack(fill=tk.X, padx=12, pady=(0, 8))
        action_specs = (
            ("Log spend", self._action_log_spend),
            ("Create accounts", self._resume_profile_accounts),
            ("Check email", self._action_check_email),
            ("Budget", self._configure_selected_budget),
        )
        for label, command in action_specs:
            _ui_button(
                action_row,
                text=label,
                command=command,
                style="ghost",
                height=36,
                font=F_CAPTION,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

        danger = ctk.CTkFrame(actions_card, fg_color="transparent")
        danger.pack(fill=tk.X, padx=12, pady=(0, 10))
        self.profile_restore_button = _ui_button(
            danger,
            text="Restore",
            command=self._restore_selected_profile,
            style="ghost",
            height=34,
            font=F_CAPTION,
            state=tk.DISABLED,
        )
        self.profile_restore_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(3, 3))
        self.profile_delete_button = _ui_button(
            danger,
            text="Delete",
            command=self._delete_selected_profile,
            style="danger",
            height=34,
            font=F_CAPTION,
            state=tk.DISABLED,
        )
        self.profile_delete_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(3, 3))

        # Spend list still available for selected employee (compact).
        spend_wrap = ctk.CTkFrame(actions_card, fg_color=C["surface"], corner_radius=R_CTRL)
        spend_wrap.pack(fill=tk.X, padx=12, pady=(0, 14))
        self.budget_overview = ctk.CTkFrame(spend_wrap, fg_color="transparent")
        self.budget_overview.pack(fill=tk.X, padx=8, pady=(6, 0))
        self.ledger_filter = tk.StringVar(value="All")
        self._ledger_filter_ids: Dict[str, Optional[str]] = {"All": None}
        self.ledger_chips = ctk.CTkFrame(spend_wrap, fg_color="transparent")
        # Hidden chips host kept for existing refresh helpers.
        self.ledger_chips.pack_forget()
        cols = ("date", "merchant", "amount")
        self.trans_tree = ttk.Treeview(spend_wrap, columns=cols, show="headings", height=3)
        for c, t, w in (("date", "Date", 72), ("merchant", "Where", 120), ("amount", "$", 48)):
            self.trans_tree.heading(c, text=t)
            self.trans_tree.column(c, width=w, anchor="w" if c != "amount" else "e")
        self.trans_tree.pack(fill=tk.X, padx=8, pady=(0, 8))
        self.trans_tree.bind("<Delete>", lambda _e: self._delete_selected_transaction())

        self.profile_search = tk.StringVar(value="")
        self.employee_amount = tk.StringVar()
        self.employee_merchant = tk.StringVar()
        self.employee_combo_var = tk.StringVar(value="")
        self._profile_list_ids: List[str] = []
        self.nav_buttons: Dict[str, ctk.CTkButton] = {}
        self.preview_title = self.profile_title
        self.preview_meta = self.profile_subtitle

        footer = ctk.CTkFrame(shell, fg_color=C["chrome"], height=30, corner_radius=0)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)
        ctk.CTkLabel(
            footer,
            textvariable=self.status,
            font=F_CAPTION,
            text_color=C["status_on_dark"],
            anchor="w",
        ).pack(fill=tk.X, padx=18, pady=6)

        self._refresh_employee_list()
        self._refresh_transaction_list()
        try:
            self.app.root.geometry("900x680+60+30")
            self.app.root.minsize(760, 560)
        except tk.TclError:
            pass

    def _dismiss_sheet(self) -> None:
        for child in self._sheet.winfo_children():
            child.destroy()
        try:
            self._sheet.pack_forget()
        except tk.TclError:
            pass
        if not self._workspace.winfo_manager():
            self._workspace.pack(fill=tk.BOTH, expand=True)

    def _close_sheet(self) -> None:
        callback = self._sheet_close_callback
        self._sheet_close_callback = None
        self._dismiss_sheet()
        if callback:
            callback()

    def _open_sheet(
        self,
        title: str,
        builder: Callable[[ctk.CTkFrame], None],
        *,
        on_close: Optional[Callable[[], None]] = None,
        subtitle: str = "",
    ) -> ctk.CTkFrame:
        """Replace the workspace with an in-window sheet (no second window)."""
        if self._sheet.winfo_manager() or self._sheet_close_callback is not None:
            self._close_sheet()
        self._sheet_close_callback = on_close
        self._workspace.pack_forget()
        self._sheet.pack(fill=tk.BOTH, expand=True)

        card = _ui_panel(self._sheet)
        card.pack(fill=tk.BOTH, expand=True)

        bar = ctk.CTkFrame(card, fg_color="transparent")
        bar.pack(fill=tk.X, padx=20, pady=(18, 8))
        titles = ctk.CTkFrame(bar, fg_color="transparent")
        titles.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ctk.CTkLabel(
            titles,
            text=title,
            font=F_TITLE,
            text_color=C["ink"],
            anchor="w",
        ).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(
                titles,
                text=subtitle,
                font=F_CAPTION,
                text_color=C["muted"],
                anchor="w",
            ).pack(anchor="w", pady=(2, 0))
        _ui_button(
            bar,
            text="Close",
            command=self._close_sheet,
            style="ghost",
            width=72,
            height=32,
            font=F_CAPTION,
        ).pack(side=tk.RIGHT)

        host = ctk.CTkFrame(card, fg_color="transparent")
        host.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 16))
        builder(host)
        return host

    def _confirm_in_window(
        self,
        title: str,
        message: str,
        on_yes: Callable[[], None],
        *,
        yes_label: str = "Confirm",
        no_label: str = "Cancel",
        on_no: Optional[Callable[[], None]] = None,
    ) -> None:
        def build(host: ctk.CTkFrame) -> None:
            ctk.CTkLabel(
                host,
                text=message,
                font=F_BODY,
                text_color=C["text"],
                wraplength=520,
                justify="left",
                anchor="w",
            ).pack(fill=tk.X, padx=4, pady=(8, 16))
            row = ctk.CTkFrame(host, fg_color="transparent")
            row.pack(fill=tk.X)

            def yes() -> None:
                self._sheet_close_callback = None
                self._dismiss_sheet()
                on_yes()

            def no() -> None:
                self._sheet_close_callback = None
                self._dismiss_sheet()
                if on_no:
                    on_no()

            ctk.CTkButton(
                row,
                text=yes_label,
                command=yes,
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["accent"],
                hover_color=C["accent_hover"],
                text_color=C["paper"],
                font=F_TITLE,
            ).pack(side=tk.LEFT)
            ctk.CTkButton(
                row,
                text=no_label,
                command=no,
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["surface"],
                hover_color=C["card_hi"],
                text_color=C["ink"],
                font=F_BODY,
            ).pack(side=tk.LEFT, padx=8)

        self._open_sheet(title, build, on_close=on_no)

    def _show_view(self, view_name: str):
        if view_name == "profiles" and self.selected_profile_id:
            self._select_employee_profile(self.selected_profile_id)

    def _run_context_action(self):
        self._sync_profiles()

    def _action_log_spend(self) -> None:
        if not self.selected_profile_id:
            self.status.set("Select an employee to log spend")
            return
        self.employee_combo_var.set(self.selected_employee or "")
        self._add_transaction_dialog()

    def _action_check_email(self) -> None:
        """Open Outlook on the web for this employee. Inbox API pull is not wired yet."""
        profile = self.profile_store.get(self.selected_profile_id or "")
        if not profile:
            self.status.set("Select an employee to check email")
            return
        email = (profile.get("email") or "").strip()
        webbrowser.open("https://outlook.live.com/mail/0/")
        self.status.set(
            "Opened Outlook web"
            + (f" for {email}" if email else "")
            + " · inbox pull needs Microsoft Graph (not enabled)"
        )

    def _open_settings_modal(self):
        def build(host: ctk.CTkFrame) -> None:
            form = ctk.CTkScrollableFrame(host, fg_color="transparent")
            form.pack(fill=tk.BOTH, expand=True)

            def labeled_entry(label: str, var: tk.Variable, show: str = "") -> None:
                ctk.CTkLabel(
                    form,
                    text=label.upper(),
                    font=F_CAPTION,
                    text_color=C["muted"],
                    anchor="w",
                ).pack(fill=tk.X, pady=(8, 4))
                ctk.CTkEntry(
                    form,
                    textvariable=var,
                    height=34,
                    corner_radius=R_CTRL,
                    fg_color=C["surface"],
                    show=show,
                    font=F_BODY,
                ).pack(fill=tk.X)

            labeled_entry("Shared passphrase", self.shared_passphrase, show="•")
            labeled_entry("Vault collection", self.collection_name)

            for label, var in (
                ("Auto-import HQ files", self.auto_import),
                ("Sync on startup", self.sync_on_startup),
                ("Create Outlook", self.provision_outlook),
                ("Create Hyatt", self.provision_hyatt),
                ("Create Marriott", self.provision_marriott),
            ):
                row = ctk.CTkFrame(form, fg_color="transparent")
                row.pack(fill=tk.X, pady=4)
                ctk.CTkLabel(
                    row, text=label, font=F_BODY, text_color=C["text"]
                ).pack(side=tk.LEFT)
                ctk.CTkSwitch(
                    row,
                    text="",
                    variable=var,
                    width=42,
                    fg_color=C["border"],
                    progress_color=C["accent"],
                ).pack(side=tk.RIGHT)

            ctk.CTkLabel(
                form,
                text=(
                    "Assisted signup — opens the isolated Ops Chrome profile; "
                    "CAPTCHA/submit stay with you."
                ),
                font=F_CAPTION,
                text_color=C["muted"],
                wraplength=520,
                justify="left",
                anchor="w",
            ).pack(fill=tk.X, pady=(8, 2))

            ctk.CTkLabel(
                form,
                text="Chrome ops profile",
                font=F_CAPTION,
                text_color=C["muted"],
                anchor="w",
            ).pack(fill=tk.X, pady=(14, 4))
            ctk.CTkLabel(
                form,
                text=(
                    "Isolated browser for employee signups. Auto-installs Bitwarden, "
                    "uBlock Origin Lite, fingerprint defenders, and related privacy tools "
                    "(close Chrome first). Keep it signed out of personal Google."
                ),
                font=F_CAPTION,
                text_color=C["status"],
                wraplength=520,
                justify="left",
                anchor="w",
            ).pack(fill=tk.X, pady=(0, 8))
            chrome_row = ctk.CTkFrame(form, fg_color="transparent")
            chrome_row.pack(fill=tk.X, pady=(0, 4))
            chrome_row2 = ctk.CTkFrame(form, fg_color="transparent")
            chrome_row2.pack(fill=tk.X, pady=(0, 4))

            def open_ops_chrome() -> None:
                from chrome_ops_profile import ChromeOpsProfile

                result = ChromeOpsProfile().open_empty()
                self.status.set(result.get("detail") or ("Opened" if result.get("ok") else "Failed"))

            def open_ext_desk() -> None:
                from chrome_ops_profile import ChromeOpsProfile

                result = ChromeOpsProfile().open_setup_desk()
                self.status.set(result.get("detail") or ("Opened" if result.get("ok") else "Failed"))

            def install_ops_extensions() -> None:
                from chrome_ops_profile import ChromeOpsProfile

                self.status.set("Downloading ops extensions…")
                result = ChromeOpsProfile().install_extensions(force=True)
                self.status.set(result.get("detail") or ("Done" if result.get("ok") else "Failed"))

            def clear_ops_site_data() -> None:
                from chrome_ops_profile import ChromeOpsProfile

                result = ChromeOpsProfile().clear_site_data()
                removed = len(result.get("removed") or [])
                self.status.set(f"Cleared {removed} ops-profile cache item(s) — close Chrome first if open")

            _ui_button(
                chrome_row,
                text="Open Ops Chrome",
                command=open_ops_chrome,
                style="primary",
                height=34,
                font=F_CAPTION,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
            _ui_button(
                chrome_row,
                text="Extension desk",
                command=open_ext_desk,
                style="ghost",
                height=34,
                font=F_CAPTION,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
            _ui_button(
                chrome_row,
                text="Clear site data",
                command=clear_ops_site_data,
                style="ghost",
                height=34,
                font=F_CAPTION,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)
            _ui_button(
                chrome_row2,
                text="Install / refresh extensions",
                command=install_ops_extensions,
                style="primary",
                height=34,
                font=F_CAPTION,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

            ctk.CTkLabel(
                form,
                text="Local delete",
                font=F_CAPTION,
                text_color=C["muted"],
                anchor="w",
            ).pack(fill=tk.X, pady=(10, 4))
            ctk.CTkOptionMenu(
                form,
                variable=self.local_delete_mode,
                values=list(LOCAL_DELETE_MODES),
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["surface"],
                button_color=C["card_hi"],
                button_hover_color=C["border_soft"],
                text_color=C["text"],
                dropdown_fg_color=C["card"],
                font=F_BODY,
            ).pack(fill=tk.X)
            ctk.CTkLabel(
                form,
                text="Vault cleanup",
                font=F_CAPTION,
                text_color=C["muted"],
                anchor="w",
            ).pack(fill=tk.X, pady=(10, 4))
            ctk.CTkOptionMenu(
                form,
                variable=self.bw_shred_mode,
                values=list(BW_SHRED_MODES),
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["surface"],
                button_color=C["card_hi"],
                button_hover_color=C["border_soft"],
                text_color=C["text"],
                dropdown_fg_color=C["card"],
                font=F_BODY,
            ).pack(fill=tk.X)

            def save() -> None:
                self._save_settings()
                self._sheet_close_callback = None
                self._dismiss_sheet()
                self.status.set("Settings saved")

            ctk.CTkButton(
                host,
                text="Save",
                command=save,
                height=36,
                corner_radius=R_CTRL,
                fg_color=C["accent"],
                hover_color=C["accent_hover"],
                text_color=C["paper"],
                font=F_TITLE,
            ).pack(fill=tk.X, pady=(10, 0))

        self._open_sheet("Settings", build, subtitle="Stays in this window")

    def _set_profile_panel_populated(self, populated: bool) -> None:
        """Show employee chrome only after someone is selected from the list."""
        if not hasattr(self, "_profile_top") or not hasattr(self, "profile_viewer"):
            return
        for widget in (
            self._profile_top,
            self._profile_subtitle_label,
            self._role_rail,
            self.profile_viewer,
        ):
            try:
                widget.pack_forget()
            except tk.TclError:
                pass
        if populated:
            self._profile_top.pack(fill=tk.X, padx=18, pady=(16, 4))
            self._profile_subtitle_label.pack(fill=tk.X, padx=18, pady=(0, 10))
            self._role_rail.pack(fill=tk.X, padx=14, pady=(0, 8))
        else:
            self.profile_title.set("")
            self.profile_subtitle.set("")
            if hasattr(self, "actions_hint"):
                self.actions_hint.set("")
        self.profile_viewer.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 14))
        if not populated:
            self._render_profile_viewer(blank=True)

    def _select_employee_profile(self, employee_id: str) -> None:
        """Load the selected employee profile into the main window."""
        profile = self.profile_store.get(employee_id)
        if not profile:
            return
        self.selected_profile_id = employee_id
        self.selected_employee = profile.get("display_name")
        self._clear_profile_secrets()
        self._refresh_active_employees()
        self._set_profile_panel_populated(True)
        self.profile_title.set(profile.get("display_name", "Employee"))
        self.profile_subtitle.set("Loading vault records…")
        self.actions_hint.set(profile.get("email") or profile.get("username") or "")
        self.ledger_filter.set(profile.get("display_name") or "All")
        self.selected_record_role = "identity"
        self._render_profile_viewer("Loading…")
        self._update_profile_actions(profile)
        self._refresh_transaction_list()
        self.status.set(f"Profile · {profile.get('display_name', 'Employee')}")

        def load():
            try:
                bundle = self.profile_sync.get_bundle(employee_id)
                self.after(0, lambda: self._apply_profile_bundle(employee_id, bundle))
            except Exception as exc:
                self.after(0, lambda error=exc: self._profile_load_failed(employee_id, error))

        threading.Thread(target=load, daemon=True).start()

    def _open_employee_modal(self, employee_id: str) -> None:
        """Back-compat: full profile is in-window now."""
        self._select_employee_profile(employee_id)

    def _expand_window(self, large: bool) -> None:
        root = self.app.root
        try:
            root.geometry("860x640+60+30")
            root.minsize(720, 540)
        except tk.TclError:
            pass

    def _refresh_profiles_list(self):
        self._refresh_active_employees()
        if self.selected_profile_id:
            self._select_employee_profile(self.selected_profile_id)

    def _on_profile_selected(self, _event=None):
        if self.selected_profile_id:
            self._select_employee_profile(self.selected_profile_id)

    def _apply_profile_bundle(self, employee_id: str, bundle: Dict[str, Dict[str, Any]]):
        if self.selected_profile_id != employee_id:
            bundle.clear()
            return
        self.profile_bundle = bundle
        filled = 0
        identity = bundle.get("identity") or {}
        if identity and not identity.get("_load_error"):
            rows = self._identity_view_rows(identity)
            filled = sum(1 for _l, v, _s in rows if v and v != "—")
        self.profile_subtitle.set(
            f"{len(bundle)}/5 vault records"
            + (f"  ·  {filled} identity fields" if filled else "")
            + f"  ·  {datetime.now().strftime('%H:%M')}"
        )
        self._show_profile_record(self.selected_record_role)
        profile = self.profile_store.get(employee_id) or {}
        self._update_profile_actions(profile)

    def _profile_load_failed(self, employee_id: str, error: Exception):
        if self.selected_profile_id != employee_id:
            return
        self.profile_bundle = {}
        self.profile_subtitle.set("Vault locked or sync unavailable")
        self._render_profile_viewer(str(error))

    def _clear_profile_secrets(self):
        self.profile_bundle.clear()
        self._revealed_profile_values.clear()

    def _update_profile_actions(self, profile: Dict[str, Any]):
        if not hasattr(self, "profile_edit_button"):
            return
        has_profile = bool(profile.get("employee_id"))
        deletion = profile.get("deletion") or {}
        pending = deletion.get("status") in {"pending", "partial", "purge_failed"}
        try:
            self.profile_restore_button.configure(
                state=tk.NORMAL if has_profile and pending else tk.DISABLED
            )
            self.profile_delete_button.configure(
                state=tk.NORMAL if has_profile and not pending else tk.DISABLED
            )
            self.profile_edit_button.configure(
                state=(
                    tk.NORMAL
                    if has_profile and "identity" in self.profile_bundle and not pending
                    else tk.DISABLED
                )
            )
        except tk.TclError:
            pass

    def _show_profile_record(self, role: str):
        self.selected_record_role = role
        for key, button in self.record_buttons.items():
            exists = key in self.profile_bundle
            try:
                button.configure(
                    fg_color=C["accent"] if key == role else C["surface"],
                    text_color=C["paper"] if key == role else (C["text"] if exists else C["muted"]),
                )
            except tk.TclError:
                pass
        self._render_profile_viewer()

    @staticmethod
    def _identity_view_rows(item: Dict[str, Any]) -> List[Tuple[str, str, bool]]:
        identity = item.get("identity") or {}
        # Legacy Secure Note imports may have dropped native identity fields.
        item_name = str(item.get("name") or "")
        display_name = item_name.rsplit(" — ", 1)[0] if " — " in item_name else item_name
        if not identity.get("firstName") and display_name:
            parts = display_name.split()
            if len(parts) >= 2 and not identity.get("firstName"):
                identity = {
                    **identity,
                    "firstName": identity.get("firstName") or parts[0],
                    "lastName": identity.get("lastName") or " ".join(parts[1:]),
                }
        keys = (
            ("Employee", "_displayName"),
            ("First name", "firstName"),
            ("Middle name", "middleName"),
            ("Last name", "lastName"),
            ("Email", "email"),
            ("Phone", "phone"),
            ("Address", "address1"),
            ("City", "city"),
            ("State", "state"),
            ("Postal code", "postalCode"),
            ("SSN", "ssn"),
            ("Company", "company"),
            ("Username", "username"),
        )
        rows: List[Tuple[str, str, bool]] = []
        for label, key in keys:
            if key == "_displayName":
                value = display_name
            else:
                value = identity.get(key)
            if value in (None, ""):
                continue
            rows.append((label, str(value), key == "ssn"))
        hidden_fields = {EMPLOYEE_ID_FIELD, RECORD_ROLE_FIELD}
        for field in item.get("fields") or []:
            field_name = str(field.get("name") or "").strip()
            if not field_name or field_name in hidden_fields:
                continue
            value = str(field.get("value") or "").strip()
            if not value:
                continue
            sensitive_name = field_name.casefold()
            is_sensitive = any(
                token in sensitive_name
                for token in ("birth", "dob", "social", "ssn", "passport", "license", "password")
            )
            rows.append((field_name, value, is_sensitive))
        notes = str(item.get("notes") or "").strip()
        if notes:
            rows.append(("Notes", notes, False))
        return rows

    def _render_profile_viewer(self, message: Optional[str] = None, *, blank: bool = False):
        if not hasattr(self, "profile_viewer"):
            return
        try:
            if not self.profile_viewer.winfo_exists():
                return
        except tk.TclError:
            return
        for child in self.profile_viewer.winfo_children():
            child.destroy()
        if blank:
            return
        if message:
            ctk.CTkLabel(
                self.profile_viewer,
                text=message,
                text_color=C["muted"],
                font=F_BODY,
                wraplength=440,
                justify="left",
            ).pack(anchor="w", padx=14, pady=14)
            return
        role = self.selected_record_role
        item = self.profile_bundle.get(role)
        if item is None:
            ctk.CTkLabel(
                self.profile_viewer,
                text="Not created yet",
                text_color=C["muted"],
                font=F_TITLE,
            ).pack(anchor="w", padx=14, pady=(14, 4))
            ctk.CTkLabel(
                self.profile_viewer,
                text="Use Resume to provision this account, or wait for HQ auto-import.",
                text_color=C["muted"],
                font=F_BODY,
                wraplength=420,
                justify="left",
            ).pack(anchor="w", padx=14)
            return
        if item.get("_load_error"):
            ctk.CTkLabel(
                self.profile_viewer,
                text="Record unavailable",
                text_color=C["text"],
                font=F_TITLE,
            ).pack(anchor="w", padx=14, pady=(14, 6))
            ctk.CTkLabel(
                self.profile_viewer,
                text="Could not load this Bitwarden item. Sync and try again.",
                text_color=C["muted"],
                font=F_BODY,
                wraplength=420,
                justify="left",
            ).pack(anchor="w", padx=14)
            return

        ctk.CTkLabel(
            self.profile_viewer,
            text=str(item.get("name") or role),
            text_color=C["text"],
            font=F_TITLE,
        ).pack(anchor="w", padx=14, pady=(12, 8))

        if role == "identity":
            rows = self._identity_view_rows(item)
        elif role == "work_card":
            card = item.get("card") or {}
            rows = [
                (label, str(value), sensitive)
                for label, value, sensitive in (
                    ("Cardholder", card.get("cardholderName"), False),
                    ("Brand", card.get("brand"), False),
                    ("Number", card.get("number"), True),
                    ("CVV", card.get("code"), True),
                    ("Expires", f"{card.get('expMonth') or '—'}/{card.get('expYear') or '—'}", False),
                )
                if value not in (None, "", "—/—")
            ]
        else:
            login = item.get("login") or {}
            uris = login.get("uris") or []
            uri = uris[0].get("uri") if uris else None
            rows = [
                (label, str(value), sensitive)
                for label, value, sensitive in (
                    ("Username", login.get("username"), False),
                    ("Password", login.get("password"), True),
                    ("Website", uri, False),
                )
                if value not in (None, "")
            ]

        if not rows:
            ctk.CTkLabel(
                self.profile_viewer,
                text="No fields stored on this item yet.",
                text_color=C["muted"],
                font=F_BODY,
            ).pack(anchor="w", padx=14, pady=8)
            return

        for index, (label, value, sensitive) in enumerate(rows):
            row = ctk.CTkFrame(
                self.profile_viewer,
                fg_color=C["row_a"] if index % 2 == 0 else C["row_b"],
                corner_radius=R_CHIP,
            )
            row.pack(fill=tk.X, padx=10, pady=2)
            ctk.CTkLabel(
                row,
                text=label,
                anchor="w",
                width=100,
                text_color=C["muted"],
                font=F_CAPTION,
            ).pack(side=tk.LEFT, padx=(12, 6), pady=10)
            reveal_key = (role, label)
            shown = value
            if sensitive and reveal_key not in self._revealed_profile_values:
                shown = "••••••••"
            ctk.CTkLabel(
                row,
                text=shown,
                anchor="w",
                text_color=C["text"],
                font=F_DATA,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True, pady=10)
            ctk.CTkButton(
                row,
                text="Copy",
                command=lambda v=value, l=label: self._copy_profile_field(l, v),
                width=52,
                height=26,
                corner_radius=R_CHIP,
                fg_color=C["accent"],
                hover_color=C["accent_hover"],
                text_color=C["paper"],
                font=F_CAPTION,
            ).pack(side=tk.RIGHT, padx=(0, 10), pady=8)
            if sensitive:
                ctk.CTkButton(
                    row,
                    text="Hide" if reveal_key in self._revealed_profile_values else "Show",
                    command=lambda key=reveal_key: self._toggle_profile_reveal(key),
                    width=52,
                    height=26,
                    corner_radius=R_CHIP,
                    fg_color=C["card"],
                    hover_color=C["card_hi"],
                    text_color=C["text"],
                    font=F_CAPTION,
                ).pack(side=tk.RIGHT, padx=(0, 4), pady=8)

    def _copy_profile_field(self, label: str, value: str) -> None:
        if not value:
            self.status.set(f"No value for {label}")
            return
        if copy_to_clipboard(value):
            self.status.set(f"Copied {label}")
        else:
            self.status.set(f"Could not copy {label}")

    def _toggle_profile_reveal(self, key: Tuple[str, str]):
        if key in self._revealed_profile_values:
            self._revealed_profile_values.remove(key)
        else:
            self._revealed_profile_values.add(key)
        self._render_profile_viewer()

    def _sync_profiles(self, *, pull: bool = True):
        self.status.set("Syncing…" if pull else "Refreshing…")
        self._clear_profile_secrets()

        def sync():
            try:
                self.profile_sync.sync_profiles(pull=pull)
                self.after(0, self._profile_sync_complete)
            except Exception as exc:
                self.after(0, lambda error=exc: self._profile_sync_failed(error))

        threading.Thread(target=sync, daemon=True).start()

    def _profile_sync_complete(self):
        self.status.set("Synced")
        self._refresh_profiles_list()
        self._refresh_employee_list()

    def _profile_sync_failed(self, error: Exception):
        self.status.set("Sync failed")
        self.status.set(f"Sync failed: {error}")

    def _resume_profile_accounts(self):
        profile = self.profile_store.get(self.selected_profile_id or "")
        if not profile:
            return
        self.selected_employee = profile.get("display_name")
        self.resume_selected_employee()

    def _edit_selected_identity(self):
        profile = self.profile_store.get(self.selected_profile_id or "")
        item = self.profile_bundle.get("identity")
        if not profile or not item:
            return
        identity = item.get("identity") or {}
        fields = (
            ("First name", "firstName"),
            ("Middle name", "middleName"),
            ("Last name", "lastName"),
            ("Email", "email"),
            ("Phone", "phone"),
            ("Address", "address1"),
            ("City", "city"),
            ("State", "state"),
            ("Postal code", "postalCode"),
        )
        err = tk.StringVar()

        def build(host: ctk.CTkFrame) -> None:
            form = ctk.CTkScrollableFrame(host, fg_color="transparent")
            form.pack(fill=tk.BOTH, expand=True)
            variables: Dict[str, tk.StringVar] = {}
            for label, key in fields:
                ctk.CTkLabel(
                    form,
                    text=label.upper(),
                    font=F_CAPTION,
                    text_color=C["muted"],
                    anchor="w",
                ).pack(fill=tk.X, pady=(8, 3))
                variables[key] = tk.StringVar(value=str(identity.get(key) or ""))
                ctk.CTkEntry(
                    form,
                    textvariable=variables[key],
                    height=32,
                    corner_radius=R_CTRL,
                    fg_color=C["surface"],
                ).pack(fill=tk.X)

            ctk.CTkLabel(
                host,
                textvariable=err,
                font=F_CAPTION,
                text_color=C["danger"],
                anchor="w",
            ).pack(fill=tk.X, pady=(4, 0))

            def save() -> None:
                updates = {key: variable.get().strip() for key, variable in variables.items()}
                if not updates["firstName"] or not updates["lastName"]:
                    err.set("First and last name are required.")
                    return
                self._sheet_close_callback = None
                self._dismiss_sheet()
                self._save_identity_updates(
                    profile["employee_id"], updates, item.get("revisionDate")
                )

            ctk.CTkButton(
                host,
                text="Save",
                command=save,
                height=36,
                corner_radius=R_CTRL,
                fg_color=C["accent"],
                hover_color=C["accent_hover"],
                text_color=C["paper"],
                font=F_TITLE,
            ).pack(fill=tk.X, pady=(10, 0))

        self._open_sheet(
            "Edit identity",
            build,
            subtitle=profile.get("display_name") or "",
        )

    def _save_identity_updates(
        self,
        employee_id: str,
        updates: Dict[str, str],
        expected_revision: Optional[str],
    ):
        self.status.set("Saving identity…")

        def worker():
            try:
                item = self.profile_sync.edit_identity(
                    employee_id,
                    updates,
                    expected_revision,
                )
                self.after(0, lambda: self._identity_saved(employee_id, item))
            except Exception as exc:
                self.after(
                    0,
                    lambda error=exc: self._identity_save_failed(employee_id, error),
                )

        threading.Thread(target=worker, daemon=True).start()

    def _identity_saved(self, employee_id: str, item: Dict[str, Any]):
        if self.selected_profile_id == employee_id:
            self.profile_bundle["identity"] = item
            self._show_profile_record("identity")
        self.status.set("Identity saved")
        self.audit.log_security_event("profile_identity_edit", f"employee_id={employee_id} result=success")

    def _identity_save_failed(self, employee_id: str, error: Exception):
        self.status.set("Identity save failed")
        self.audit.log_security_event(
            "profile_identity_edit",
            f"employee_id={employee_id} result=failed",
        )
        self.status.set(f"Identity save failed: {error}")

    @staticmethod
    def _redacted_item_ids(item_ids: List[str]) -> str:
        return f"{len(item_ids)} item(s)"

    def _delete_selected_profile(self):
        employee_id = self.selected_profile_id
        profile = self.profile_store.get(employee_id or "")
        if not employee_id or not profile:
            return

        def run_delete() -> None:
            def worker():
                try:
                    result = self.profile_sync.trash_bundle(employee_id)
                    self.after(0, lambda: self._profile_trash_complete(employee_id, result))
                except Exception as exc:
                    self.after(
                        0,
                        lambda error=exc: self.status.set(f"Delete failed: {error}"),
                    )

            threading.Thread(target=worker, daemon=True).start()

        self._confirm_in_window(
            "Delete profile",
            f"Trash Bitwarden items for {profile.get('display_name')}?\n"
            "Restore remains available for two days.",
            run_delete,
            yes_label="Trash",
        )

    def _profile_trash_complete(self, employee_id: str, result: Dict[str, List[str]]):
        self.audit.log_security_event(
            "profile_trash",
            f"employee_id={employee_id} trashed={self._redacted_item_ids(result.get('trashed', []))} "
            f"failed={self._redacted_item_ids(result.get('failed', []))}",
        )
        self._clear_profile_secrets()
        self.selected_profile_id = None
        self.selected_employee = None
        self._refresh_employee_list()
        self._set_profile_panel_populated(False)
        self._update_profile_actions({})
        self.ledger_filter.set("All")
        self._refresh_transaction_list()
        self.status.set("Profile moved to trash")

    def _restore_selected_profile(self):
        employee_id = self.selected_profile_id
        if not employee_id:
            return

        def worker():
            try:
                result = self.profile_sync.restore_bundle(employee_id)
                self.after(0, lambda: self._profile_restore_complete(employee_id, result))
            except Exception as exc:
                self.after(
                    0,
                    lambda error=exc: self.status.set(f"Restore failed: {error}"),
                )

        threading.Thread(target=worker, daemon=True).start()

    def _profile_restore_complete(self, employee_id: str, result: Dict[str, List[str]]):
        self.audit.log_security_event(
            "profile_restore",
            f"employee_id={employee_id} restored={self._redacted_item_ids(result.get('restored', []))} "
            f"failed={self._redacted_item_ids(result.get('failed', []))}",
        )
        self.status.set("Profile restored")
        self._refresh_employee_list()
        if self.selected_profile_id == employee_id:
            self._select_employee_profile(employee_id)

    def _set_step(self, key: str, detail: str = "") -> None:
        labels = {
            "intake": "Intake",
            "convert": "Convert",
            "import": "Import",
            "accounts": "Accounts",
            "lockdown": "Cleanup",
            "done": "Done",
        }
        self.workflow_step.set(key)
        text = labels.get(key, key)
        if detail:
            text = f"{text}: {detail}"
        self.status.set(text)

    def _save_settings(self):
        passphrase = self.shared_passphrase.get().strip()
        payload = {
            "collection_name": self.collection_name.get().strip() or "Personal Vault",
            "auto_import": "true" if self.auto_import.get() else "false",
            "sync_on_startup": "true" if self.sync_on_startup.get() else "false",
            "provision_outlook": "true" if self.provision_outlook.get() else "false",
            "provision_hyatt": "true" if self.provision_hyatt.get() else "false",
            "provision_marriott": "true" if self.provision_marriott.get() else "false",
            "local_delete_mode": self.local_delete_mode.get(),
            "bw_shred_mode": self.bw_shred_mode.get(),
        }
        if len(passphrase) >= 8:
            payload["shared_passphrase"] = passphrase
        self.store.update(payload)
        self.status.set("Settings saved")

    def _build_ledger_chips(self, names: List[str]) -> None:
        """Chips removed from layout; keep filter map for spend list helpers."""
        self._ledger_filter_ids = {"All": None}
        for name in names:
            self._ledger_filter_ids[name] = self._ledger_employee_map.get(name)

    def _queued_employee_files(self) -> List[Path]:
        return sorted(
            f for f in DOWNLOADS.glob("HQ-*") if f.is_file() and f.suffix in {".txt", ".rtf"}
        )

    def _refresh_queued_files(self) -> None:
        # queue_list was part of an earlier layout and no longer exists in
        # the current UI; the status bar is the only place this feedback is
        # visible now, so it must not be gated behind that dead widget.
        queued = self._queued_employee_files()
        if hasattr(self, "queue_list"):
            self.queue_list.delete(0, tk.END)
            for f in queued:
                self.queue_list.insert(tk.END, f.name)
            if not queued:
                self.queue_list.insert(tk.END, "No HQ files queued")
        if queued:
            names = ", ".join(f.name for f in queued[:3])
            if len(queued) > 3:
                names += f", +{len(queued) - 3} more"
            # _set_step() also writes self.status — call it last so its
            # summary is what's actually shown, but keep it informative.
            self._set_step("intake", f"{len(queued)} ready — {names}")
        else:
            self.status.set("No files queued")

    def _browse_files(self, _event: tk.Event | None = None):
        files = filedialog.askopenfilenames(
            title="Select employee files",
            filetypes=[("HQ exports", "*.txt *.rtf"), ("All", "*.*")],
        )
        if files:
            self._queue_files(files)

    def _open_manual_employee_dialog(self) -> None:
        err = tk.StringVar()

        def build(host: ctk.CTkFrame) -> None:
            form = ctk.CTkScrollableFrame(host, fg_color="transparent")
            form.pack(fill=tk.BOTH, expand=True)
            field_vars: Dict[str, tk.StringVar] = {}
            first_entry: Optional[ctk.CTkEntry] = None
            for key, label, required in HQ_TEMPLATE_FIELDS:
                mark = " *" if required else ""
                ctk.CTkLabel(
                    form,
                    text=f"{label}{mark}",
                    font=F_CAPTION,
                    text_color=C["muted"],
                    anchor="w",
                ).pack(fill=tk.X, pady=(8, 2))
                var = tk.StringVar()
                field_vars[key] = var
                show = "•" if key in {"ssn", "cc", "cvv"} else ""
                entry = ctk.CTkEntry(
                    form,
                    textvariable=var,
                    height=32,
                    corner_radius=R_CTRL,
                    fg_color=C["surface"],
                    show=show,
                    font=("Menlo", 11) if key in {"ssn", "cc", "cvv", "dob"} else F_BODY,
                )
                entry.pack(fill=tk.X)
                if first_entry is None:
                    first_entry = entry

            ctk.CTkLabel(
                host,
                textvariable=err,
                font=F_CAPTION,
                text_color=C["danger"],
                anchor="w",
            ).pack(fill=tk.X, pady=(4, 0))

            def save(*, run_after: bool) -> None:
                values = {key: var.get() for key, var in field_vars.items()}
                try:
                    path = write_hq_file(values, DOWNLOADS)
                except ValueError as exc:
                    err.set(str(exc))
                    return
                self.log_msg(f"Queued manual employee {path.name}")
                self._refresh_queued_files()
                self.status.set(f"Saved {path.name} · press Run when ready")
                self._sheet_close_callback = None
                self._dismiss_sheet()
                if run_after:
                    self.run_pipeline(quiet=False)

            actions = ctk.CTkFrame(host, fg_color="transparent")
            actions.pack(fill=tk.X, pady=(8, 0))
            ctk.CTkButton(
                actions,
                text="Save & Run",
                command=lambda: save(run_after=True),
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["accent"],
                hover_color=C["accent_hover"],
                text_color=C["paper"],
                font=F_TITLE,
            ).pack(side=tk.LEFT)
            ctk.CTkButton(
                actions,
                text="Save only",
                command=lambda: save(run_after=False),
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["surface"],
                hover_color=C["card_hi"],
                text_color=C["ink"],
                font=F_BODY,
            ).pack(side=tk.LEFT, padx=6)
            if first_entry is not None:
                first_entry.focus()

        self._open_sheet(
            "Manual employee",
            build,
            subtitle="Same fields as an HQ export · saves HQ-*.txt to Downloads/Secure Downloads",
        )

    def _on_drop(self, event: Any) -> None:
        files = self.app.root.splitlist(event.data)
        self._queue_files(files)

    def _queue_files(self, files: Tuple[str, ...]):
        n = 0
        for file_path in files:
            path = Path(file_path)
            if not (path.name.startswith("HQ-") and path.suffix in {".txt", ".rtf"}):
                self.log_msg(f"Skipped (not HQ export): {path.name}")
                continue
            dest = DOWNLOADS / path.name
            try:
                shutil.copy2(path, dest)
                n += 1
                self.log_msg(f"Queued {path.name}")
            except Exception as e:
                self.log_msg(f"Queue error {path.name}: {e}")
        self._refresh_queued_files()
        if n and self.auto_import.get():
            self.run_pipeline(quiet=True)

    def _monitor_downloads(self):
        seen: Set[Path] = set(self._queued_employee_files())
        while True:
            try:
                for f in self._queued_employee_files():
                    if f not in seen:
                        seen.add(f)
                        self.log_msg(f"Detected {f.name}")
                        self.after(0, self._refresh_queued_files)
                        if self.auto_import.get():
                            self.after(0, lambda: self.run_pipeline(quiet=True))
                time.sleep(5)
            except Exception as e:
                self.log_msg(f"Monitor error: {e!r}")
                time.sleep(10)

    def _bind_assist_hotkeys(self) -> None:
        root = self.app.root
        for index, key in enumerate(ASSIST_FIELD_KEYS, start=1):
            root.bind_all(
                f"<Command-Key-{index}>",
                lambda _e, field=key: self._assist_paste_field(field),
            )
            root.bind_all(
                f"<Control-Key-{index}>",
                lambda _e, field=key: self._assist_paste_field(field),
            )

    def _assist_paste_field(self, field_key: str) -> str:
        if not self._assist_personal:
            return "break"
        value = assist_field_value(self._assist_personal, field_key)
        if not value:
            self.status.set(f"No value for {ASSIST_FIELD_LABELS.get(field_key, field_key)}")
            return "break"
        self.after(120, lambda v=value, k=field_key: self._do_assist_paste(v, k))
        return "break"

    def _do_assist_paste(self, value: str, field_key: str) -> None:
        ok = paste_field_value(value)
        label = ASSIST_FIELD_LABELS.get(field_key, field_key)
        self.status.set(f"Pasted {label}" if ok else f"Copied {label} — click field & ⌘V")

    def _assist_copy_field(self, field_key: str) -> None:
        value = assist_field_value(self._assist_personal, field_key)
        if not value:
            return
        copy_to_clipboard(value)
        self.status.set(f"Copied {ASSIST_FIELD_LABELS.get(field_key, field_key)}")

    def _assist_copy_payload(self) -> None:
        payload = format_assist_payload(
            self._assist_personal,
            self._assist_personal.get("username")
            or self._assist_personal.get("email")
            or "",
            service=self._assist_service,
        )
        copy_to_clipboard(payload)
        self.status.set("Copied assist payload")

    def _close_assist_panel(self, decision: str) -> None:
        if self._assist_event.is_set() and self._assist_window is None and self._assist_panel is None:
            return
        self._assist_decision = decision
        self._assist_panel = None
        win = self._assist_window
        self._assist_window = None
        self._sheet_close_callback = None
        if win is not None:
            try:
                win.destroy()
            except tk.TclError:
                pass
        try:
            self._dismiss_sheet()
        except Exception:
            pass
        self._assist_event.set()

    def _assist_current_fields(self) -> List[str]:
        # "Next field" walks in the order the target site's form actually
        # asks for fields (per service); ⌘1-6 still always paste the same
        # field regardless, since those hotkeys are bound to
        # ASSIST_FIELD_KEYS directly and don't go through this method.
        order = ASSIST_FIELD_WALK_ORDER.get(self._assist_service, ASSIST_FIELD_KEYS)
        keys: List[str] = []
        for key in order:
            value = assist_field_value(self._assist_personal, key)
            if key == "email" and self._assist_service == "Outlook" and not value:
                value = assist_field_value(self._assist_personal, "username")
            if value:
                keys.append(key)
        return keys or list(order)

    def _refresh_assist_companion(self) -> None:
        win = self._assist_window
        if win is None:
            return
        keys = self._assist_current_fields()
        if not keys:
            return
        self._assist_field_index = max(0, min(self._assist_field_index, len(keys) - 1))
        key = keys[self._assist_field_index]
        value = assist_field_value(self._assist_personal, key)
        if key == "email" and self._assist_service == "Outlook" and not value:
            value = assist_field_value(self._assist_personal, "username")
        label = ASSIST_FIELD_LABELS.get(key, key)
        preview = "••••••••" if "password" in key else value
        if len(preview) > 42:
            preview = preview[:41] + "…"
        try:
            win._step_var.set(f"Field {self._assist_field_index + 1} of {len(keys)}")
            win._field_var.set(label)
            win._value_var.set(preview or "—")
            win._paste_key = key
        except tk.TclError:
            pass

    def _assist_step(self, delta: int) -> None:
        keys = self._assist_current_fields()
        if not keys:
            return
        self._assist_field_index = (self._assist_field_index + delta) % len(keys)
        self._refresh_assist_companion()

    def _show_assist_panel(
        self,
        service: str,
        employee: Dict[str, str],
        result: Dict[str, Any],
    ) -> None:
        personal = dict(result.get("personal_data") or {})
        if not personal:
            personal = {
                "full_name": employee.get("full_name", ""),
                "first_name": employee.get("first_name", ""),
                "last_name": employee.get("last_name", ""),
                "email": employee.get("email", ""),
                "username": employee.get("username", ""),
                "password": "",
            }
        self._assist_personal = personal
        self._assist_service = service
        self._assist_decision = "skip"
        self._assist_field_index = 0
        self._assist_event.clear()

        if self._assist_window is not None:
            try:
                self._assist_window.destroy()
            except tk.TclError:
                pass
            self._assist_window = None

        status = str(result.get("status") or "manual_only")
        status_label = {
            "prefilled": "Prefill done — finish captcha/submit in the browser",
            "bot_blocked": "Bot wall — use Bitwarden Auto-fill + Paste backup",
            "manual_only": "Use Bitwarden Auto-fill on the signup page",
            "manual_completion_required": "Use Bitwarden Auto-fill on the signup page",
            "error": "Error — Retry or complete manually",
        }.get(status, status)
        if result.get("autofill_ready"):
            status_label = "Temp autofill profile pushed to Bitwarden"
        url = result.get("url") or ""
        autofill_message = str(result.get("autofill_message") or "")
        linked_fields = list(result.get("autofill_linked_fields") or [])
        note = (
            "Skip Outlook keeps Hyatt/Marriott pending."
            if service == "Outlook"
            else "Press Done only after the account exists."
        )
        employee_name = employee.get("full_name") or "Employee"

        # Keep Provision visible; float a compact field companion beside the browser.
        arrange = arrange_windows_for_assist(app_title="Provision")
        if arrange.get("detail"):
            logging.info("Assist layout: %s", arrange["detail"])

        win = ctk.CTkToplevel(self.app.root)
        self._assist_window = win
        win.title(f"{service} assist")
        win.resizable(False, False)
        win.configure(fg_color=C["bg"])
        try:
            win.attributes("-topmost", True)
        except tk.TclError:
            pass
        width, height = 360, 460
        try:
            screen_w = max(win.winfo_screenwidth(), width + 40)
            screen_h = max(win.winfo_screenheight(), height + 40)
            x = max(screen_w - width - 28, 40)
            y = max((screen_h - height) // 4, 48)
            win.geometry(f"{width}x{height}+{x}+{y}")
        except tk.TclError:
            win.geometry(f"{width}x{height}+80+80")

        card = _ui_panel(win)
        card.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        ctk.CTkLabel(
            card,
            text=f"{service} assist",
            font=F_TITLE,
            text_color=C["ink"],
            anchor="w",
        ).pack(fill=tk.X, padx=16, pady=(16, 2))
        ctk.CTkLabel(
            card,
            text=employee_name,
            font=F_CAPTION,
            text_color=C["muted"],
            anchor="w",
        ).pack(fill=tk.X, padx=16)
        ctk.CTkLabel(
            card,
            text=status_label,
            font=F_CAPTION,
            text_color=C["accent"],
            anchor="w",
            wraplength=300,
            justify="left",
        ).pack(fill=tk.X, padx=16, pady=(8, 2))
        if autofill_message:
            ctk.CTkLabel(
                card,
                text=autofill_message,
                font=F_CAPTION,
                text_color=C["muted"],
                anchor="w",
                wraplength=300,
                justify="left",
            ).pack(fill=tk.X, padx=16, pady=(0, 2))
        if linked_fields:
            ctk.CTkLabel(
                card,
                text="Linked fields: " + ", ".join(linked_fields[:8])
                + ("…" if len(linked_fields) > 8 else ""),
                font=F_CAPTION,
                text_color=C["status"],
                anchor="w",
                wraplength=300,
                justify="left",
            ).pack(fill=tk.X, padx=16, pady=(0, 4))
        if url:
            ctk.CTkLabel(
                card,
                text=url,
                font=F_CAPTION,
                text_color=C["status"],
                anchor="w",
                wraplength=300,
                justify="left",
            ).pack(fill=tk.X, padx=16, pady=(0, 8))

        step = ctk.CTkFrame(card, fg_color=C["surface"], corner_radius=R_CTRL)
        step.pack(fill=tk.X, padx=16, pady=(4, 8))
        win._step_var = tk.StringVar(value="")
        win._field_var = tk.StringVar(value="")
        win._value_var = tk.StringVar(value="")
        win._paste_key = ASSIST_FIELD_KEYS[0]
        ctk.CTkLabel(
            step,
            textvariable=win._step_var,
            font=F_CAPTION,
            text_color=C["muted"],
            anchor="w",
        ).pack(fill=tk.X, padx=14, pady=(12, 2))
        ctk.CTkLabel(
            step,
            textvariable=win._field_var,
            font=F_DISPLAY,
            text_color=C["ink"],
            anchor="w",
        ).pack(fill=tk.X, padx=14)
        ctk.CTkLabel(
            step,
            textvariable=win._value_var,
            font=F_DATA,
            text_color=C["muted"],
            anchor="w",
        ).pack(fill=tk.X, padx=14, pady=(4, 12))

        def paste_current() -> None:
            self._assist_paste_field(getattr(win, "_paste_key", ASSIST_FIELD_KEYS[0]))
            # Advance after a successful paste so walkthrough stays one field ahead.
            self.after(180, lambda: self._assist_step(1))

        _ui_button(
            card,
            text="Paste this field into browser",
            command=paste_current,
            style="primary",
            height=44,
            font=F_TITLE,
        ).pack(fill=tk.X, padx=16, pady=(4, 8))

        nav = ctk.CTkFrame(card, fg_color="transparent")
        nav.pack(fill=tk.X, padx=16, pady=(0, 8))
        _ui_button(
            nav,
            text="Back",
            command=lambda: self._assist_step(-1),
            style="ghost",
            height=34,
            font=F_CAPTION,
            width=90,
        ).pack(side=tk.LEFT)
        _ui_button(
            nav,
            text="Next field",
            command=lambda: self._assist_step(1),
            style="ghost",
            height=34,
            font=F_CAPTION,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))

        ctk.CTkLabel(
            card,
            text=(
                "Preferred: Bitwarden extension → Auto-fill the TEMP item. "
                f"Backup: click a signup field, then Paste. {note}"
            ),
            font=F_CAPTION,
            text_color=C["muted"],
            wraplength=300,
            justify="left",
            anchor="w",
        ).pack(fill=tk.X, padx=16, pady=(4, 10))

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.pack(fill=tk.X, padx=16, pady=(0, 16))
        _ui_button(
            actions,
            text="Done",
            command=lambda: self._close_assist_panel("done"),
            style="primary",
            height=34,
            font=F_CAPTION,
            width=78,
        ).pack(side=tk.LEFT)
        _ui_button(
            actions,
            text="Skip",
            command=lambda: self._close_assist_panel("skip"),
            style="ghost",
            height=34,
            font=F_CAPTION,
            width=64,
        ).pack(side=tk.LEFT, padx=6)
        _ui_button(
            actions,
            text="Retry",
            command=lambda: self._close_assist_panel("retry"),
            style="ghost",
            height=34,
            font=F_CAPTION,
            width=64,
        ).pack(side=tk.LEFT)
        _ui_button(
            actions,
            text="Payload",
            command=self._assist_copy_payload,
            style="ink",
            height=34,
            font=F_CAPTION,
            width=72,
        ).pack(side=tk.RIGHT)

        def on_close() -> None:
            self._close_assist_panel("skip")

        win.protocol("WM_DELETE_WINDOW", on_close)
        self._refresh_assist_companion()
        try:
            win.lift()
            win.focus_force()
        except tk.TclError:
            pass

    def _confirm_account_stage(
        self,
        service: str,
        employee: Dict[str, str],
        result: Dict[str, Any],
    ) -> str:
        """Non-modal assist panel; returns done | skip | retry."""
        self._assist_event.clear()
        self.app.root.after(
            0,
            lambda: self._show_assist_panel(service, employee, result),
        )
        self._assist_event.wait()
        self._assist_personal = {}
        return self._assist_decision

    def resume_selected_employee(self):
        if self._pipeline_running:
            self.status.set("Wait for the current run to finish")
            return
        if not self.selected_employee:
            self.status.set("Select an employee before creating accounts")
            return
        passphrase = self._resolve_passphrase()
        if not passphrase:
            return
        config = OnboardingConfig(
            bw=BitwardenConfig(
                collection_name=self.collection_name.get().strip() or "Personal Vault"
            ),
            local_delete_mode=self.local_delete_mode.get(),
            bw_shred_mode=self.bw_shred_mode.get(),
            provision_outlook=self.provision_outlook.get(),
            provision_hyatt=self.provision_hyatt.get(),
            provision_marriott=self.provision_marriott.get(),
        )
        employee_name = self.selected_employee

        def on_progress(step: str, detail: str = ""):
            self.app.root.after(
                0,
                lambda current_step=step, current_detail=detail: self._set_step(
                    current_step,
                    current_detail,
                ),
            )

        def worker():
            try:
                self.onboarding.resume_accounts(
                    employee_name,
                    passphrase,
                    config,
                    progress_callback=on_progress,
                    account_confirmation_callback=self._confirm_account_stage,
                )
                self.app.root.after(0, self._refresh_active_employees)
                self.app.root.after(
                    0,
                    lambda: self.status.set(f"Accounts updated for {employee_name}"),
                )
            except Exception as error:
                logging.error("Account resume failed", exc_info=True)
                self.app.root.after(
                    0,
                    lambda current_error=error: self.status.set(
                        f"Resume failed: {current_error}"
                    ),
                )
            finally:
                self.app.root.after(0, self._pipeline_finished)

        self._pipeline_running = True
        self.status.set(f"Resuming {employee_name}…")
        threading.Thread(target=worker, daemon=True).start()

    def _resolve_passphrase(self) -> Optional[str]:
        passphrase = self.shared_passphrase.get().strip()
        if len(passphrase) < 8:
            passphrase = self.store.get("shared_passphrase", "").strip()
            if passphrase:
                self.shared_passphrase.set(passphrase)
        if len(passphrase) >= 8:
            return passphrase
        self.status.set("Set shared passphrase in Settings (8+ characters)")
        self._open_settings_modal()
        return None

    # --- Pipeline -----------------------------------------------------
    def run_pipeline(self, *, quiet: bool = False):
        if self._pipeline_running:
            if not quiet:
                self.status.set("Wait for the current run to finish")
            return
        queued = self._queued_employee_files()
        if not queued:
            if not quiet:
                self.status.set("Nothing queued — drop HQ-*.txt / HQ-*.rtf into Downloads/Secure Downloads")
            return
        passphrase = self._resolve_passphrase()
        if not passphrase:
            return
        collection = self.collection_name.get().strip() or "Personal Vault"
        self.store.update({"collection_name": collection})
        previous_employee_ids = {
            profile["employee_id"]
            for profile in self.profile_store.list_profiles(include_purged=True)
        }

        config = OnboardingConfig(
            bw=BitwardenConfig(collection_name=collection),
            local_delete_mode=self.local_delete_mode.get(),
            bw_shred_mode=self.bw_shred_mode.get(),
            provision_outlook=self.provision_outlook.get(),
            provision_hyatt=self.provision_hyatt.get(),
            provision_marriott=self.provision_marriott.get(),
        )

        def on_progress(step: str, detail: str = ""):
            self.app.root.after(0, lambda: self._set_step(step, detail))

        def worker():
            try:
                status = self.bw.get_status()
                if status == "locked" or (status == "unlocked" and not self.bw.session_key):
                    self.app.root.after(
                        0,
                        lambda: self.status.set(
                            "Vault locked — quit and reopen Provision to sign in"
                        ),
                    )
                    return
                if status == "unauthenticated":
                    self.app.root.after(
                        0,
                        lambda: self.status.set(
                            "Bitwarden session missing — restart and sign in"
                        ),
                    )
                    return

                self.onboarding.run(
                    DOWNLOADS,
                    passphrase,
                    config,
                    session_log_path=self.app.session_log_path,
                    progress_callback=on_progress,
                    account_confirmation_callback=self._confirm_account_stage,
                )
                self.app.root.after(
                    0,
                    lambda: self._on_onboarding_complete(previous_employee_ids),
                )
            except Exception as e:
                logging.error("Pipeline failed", exc_info=True)
                self.app.root.after(
                    0,
                    lambda error=e: self.status.set(f"Pipeline failed: {error}"),
                )
            finally:
                self.app.root.after(0, self._pipeline_finished)

        self._pipeline_running = True
        self.status.set(f"Importing {len(queued)} HQ file(s)…")
        threading.Thread(target=worker, daemon=True).start()

    def _pipeline_finished(self):
        self._pipeline_running = False

    def _on_onboarding_complete(self, previous_employee_ids: Set[str]):
        self._refresh_queued_files()
        self._refresh_employee_list()
        self._prompt_new_employee_budgets(previous_employee_ids)
        self.status.set("Onboarding complete")
        self._sync_profiles()

    # --- Logging ------------------------------------------------------
    def _configure_logging(self):
        handler = QueueHandler(self.log_queue)
        handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))
        logging.getLogger().addHandler(handler)

    def _poll_log_queue(self):
        # QueueHandler already logged these once — only mirror into the status bar.
        while True:
            try:
                msg = self.log_queue.get_nowait()
            except queue.Empty:
                break
            short = msg if len(msg) < 72 else msg[:69] + "…"
            try:
                self.status.set(short)
            except tk.TclError:
                pass
        self.after(120, self._poll_log_queue)

    def log_msg(self, msg: str):
        logging.info(msg)
        short = msg if len(msg) < 72 else msg[:69] + "…"
        try:
            self.status.set(short)
        except tk.TclError:
            pass

    # --- Transactions helpers -----------------------------------------
    def _refresh_employee_list(self):
        profiles = self.profile_store.list_profiles()
        self._ledger_employee_map = {
            profile["display_name"]: profile["employee_id"]
            for profile in profiles
        }
        names = sorted(self._ledger_employee_map)
        if self.ledger_filter.get() not in {"All", *names}:
            self.ledger_filter.set("All")
        self._build_ledger_chips(names)
        self._refresh_active_employees()

    def _refresh_active_employees(self):
        if not hasattr(self, "employee_grid"):
            return
        profiles = self.profile_store.list_profiles()
        for child in self.employee_grid.winfo_children():
            child.destroy()
        self.employee_count.set(str(len(profiles)))
        if not profiles:
            ctk.CTkLabel(
                self.employee_grid,
                text="No employees yet — Manual entry or File → Run",
                font=F_BODY,
                text_color=C["muted"],
                wraplength=180,
                justify="left",
            ).pack(anchor="w", padx=8, pady=24)
            return
        for profile in profiles:
            name = profile.get("display_name", "Unknown")
            employee_id = profile["employee_id"]
            selected = employee_id == self.selected_profile_id
            parts = [p for p in str(name).split() if p]
            initials = (
                f"{parts[0][0]}{parts[-1][0]}"
                if len(parts) >= 2
                else (parts[0][:2] if parts else "—")
            )
            row = ctk.CTkFrame(
                self.employee_grid,
                fg_color=C["accent_dim"] if selected else "transparent",
                corner_radius=R_CTRL,
                cursor="hand2",
                height=44,
            )
            row.pack(fill=tk.X, pady=2)
            row.pack_propagate(False)
            mark_bg = C["accent_dim"] if selected else C["card"]
            mark = InitialsMark(
                row,
                initials,
                size=28,
                selected=selected,
                bg=mark_bg,
            )
            mark.pack(side=tk.LEFT, padx=(8, 0), pady=8)
            label = ctk.CTkLabel(
                row,
                text=name,
                font=F_TITLE if selected else F_BODY,
                text_color=C["ink"],
                anchor="w",
            )
            label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)

            def select(_event=None, eid=employee_id):
                self._select_employee_profile(eid)

            for widget in (row, label, mark):
                widget.bind("<Button-1>", select)

    def _select_employee(self, employee_name: str):
        self.selected_employee = employee_name
        profile = next(
            (
                p
                for p in self.profile_store.list_profiles()
                if p.get("display_name") == employee_name
            ),
            None,
        )
        if profile:
            self._select_employee_profile(profile["employee_id"])

    def _refresh_transaction_list(self):
        if not hasattr(self, "trans_tree"):
            return
        for item in self.trans_tree.get_children():
            self.trans_tree.delete(item)
        selected_name = self.ledger_filter.get()
        employee_id = None
        if selected_name not in {"All", "All employees", ""}:
            employee_id = getattr(self, "_ledger_employee_map", {}).get(selected_name)
        if employee_id:
            transactions = self.transaction_db.get_transactions_by_employee_id(employee_id)
        else:
            transactions = self.transaction_db.get_all_transactions()
        for trans in transactions[:40]:
            self.trans_tree.insert(
                "",
                "end",
                iid=str(trans["id"]),
                values=(
                    trans["date"],
                    trans["merchant"],
                    f"{trans['amount']:.0f}",
                ),
            )
        filter_name = selected_name if selected_name not in {"All", ""} else "All employees"
        self._refresh_budget_overview(filter_name)

    def _add_transaction_dialog(self):
        names = sorted(getattr(self, "_ledger_employee_map", {}))
        if not names:
            self.status.set("No employees yet — import or add one first")
            return
        default = self.selected_employee if self.selected_employee in names else names[0]
        merchant = tk.StringVar()
        amount = tk.StringVar()
        employee = tk.StringVar(value=default)
        err = tk.StringVar()

        def build(host: ctk.CTkFrame) -> None:
            for label, var in (("Merchant", merchant), ("Amount", amount)):
                ctk.CTkLabel(
                    host,
                    text=label.upper(),
                    font=F_CAPTION,
                    text_color=C["muted"],
                    anchor="w",
                ).pack(fill=tk.X, pady=(10, 3))
                ctk.CTkEntry(
                    host,
                    textvariable=var,
                    height=34,
                    corner_radius=R_CTRL,
                    fg_color=C["surface"],
                ).pack(fill=tk.X)
            ctk.CTkLabel(
                host,
                text="EMPLOYEE",
                font=F_CAPTION,
                text_color=C["muted"],
                anchor="w",
            ).pack(fill=tk.X, pady=(10, 3))
            ctk.CTkOptionMenu(
                host,
                variable=employee,
                values=names,
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["surface"],
                button_color=C["card_hi"],
                text_color=C["text"],
            ).pack(fill=tk.X)
            ctk.CTkLabel(
                host,
                textvariable=err,
                font=F_CAPTION,
                text_color=C["danger"],
                anchor="w",
            ).pack(fill=tk.X, pady=(8, 0))

            def save() -> None:
                self.employee_merchant.set(merchant.get())
                self.employee_amount.set(amount.get())
                self.employee_combo_var.set(employee.get())
                if not self._add_transaction():
                    err.set(self.status.get())
                    return
                self._sheet_close_callback = None
                self._dismiss_sheet()

            ctk.CTkButton(
                host,
                text="Add",
                command=save,
                height=36,
                corner_radius=R_CTRL,
                fg_color=C["accent"],
                hover_color=C["accent_hover"],
                text_color=C["paper"],
                font=F_TITLE,
            ).pack(fill=tk.X, pady=(12, 0))

        self._open_sheet("Log spend", build)

    def _refresh_budget_overview(self, selected_name: str = "All employees"):
        if not hasattr(self, "budget_overview"):
            return
        for child in self.budget_overview.winfo_children():
            child.destroy()
        budget_by_id = {
            budget["employee_id"]: budget
            for budget in self.transaction_db.get_employee_budgets()
        }
        profiles = self.profile_store.list_profiles()
        if selected_name not in {"All employees", "All", ""}:
            profiles = [
                profile
                for profile in profiles
                if profile.get("display_name") == selected_name
            ]
        visible = profiles[:5]
        if not visible:
            ctk.CTkLabel(
                self.budget_overview,
                text="Spend limits appear after import",
                text_color=C["muted"],
                font=F_CAPTION,
            ).pack(anchor="w", padx=4, pady=4)
            return
        for profile in visible:
            budget = budget_by_id.get(profile["employee_id"])
            row = ctk.CTkFrame(self.budget_overview, fg_color="transparent")
            row.pack(fill=tk.X, pady=2)
            name = profile.get("display_name", "Employee").split()[0]
            ctk.CTkLabel(
                row,
                text=name,
                width=56,
                anchor="w",
                font=F_CAPTION,
                text_color=C["text"],
            ).pack(side=tk.LEFT)
            if budget is None:
                ctk.CTkLabel(
                    row,
                    text="no limit",
                    font=F_CAPTION,
                    text_color=C["muted"],
                ).pack(side=tk.LEFT)
                continue
            spent = budget["total_spent"]
            limit = budget["spend_limit"]
            ratio = spent / limit if limit else 0
            bar = ctk.CTkProgressBar(
                row,
                height=6,
                corner_radius=3,
                fg_color="#dedee3",
                progress_color=C["danger"] if ratio >= 1 else C["text"],
            )
            bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
            bar.set(min(max(ratio, 0), 1))
            ctk.CTkLabel(
                row,
                text=f"${spent:.0f}/${limit:.0f}",
                font=F_CAPTION,
                text_color=C["muted"],
            ).pack(side=tk.RIGHT)

    def _configure_selected_budget(self):
        employee_id = self.selected_profile_id
        if not employee_id:
            selected_name = self.ledger_filter.get()
            employee_id = getattr(self, "_ledger_employee_map", {}).get(selected_name)
        if not employee_id:
            self.status.set("Select an employee before setting a spend limit")
            return
        profile = self.profile_store.get(employee_id)
        if profile:
            self._prompt_employee_budget(profile)

    def _prompt_employee_budget(
        self,
        profile: Dict[str, Any],
        *,
        on_done: Optional[Callable[[], None]] = None,
    ) -> None:
        name = profile.get("display_name", "Employee")
        spent_var = tk.StringVar(value="0")
        limit_var = tk.StringVar()
        err = tk.StringVar()

        def build(host: ctk.CTkFrame) -> None:
            ctk.CTkLabel(
                host,
                text="CURRENT SPEND",
                font=F_CAPTION,
                text_color=C["muted"],
                anchor="w",
            ).pack(fill=tk.X, pady=(8, 3))
            ctk.CTkEntry(
                host,
                textvariable=spent_var,
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["surface"],
            ).pack(fill=tk.X)
            ctk.CTkLabel(
                host,
                text="SPEND LIMIT",
                font=F_CAPTION,
                text_color=C["muted"],
                anchor="w",
            ).pack(fill=tk.X, pady=(10, 3))
            ctk.CTkEntry(
                host,
                textvariable=limit_var,
                height=34,
                corner_radius=R_CTRL,
                fg_color=C["surface"],
            ).pack(fill=tk.X)
            ctk.CTkLabel(
                host,
                textvariable=err,
                font=F_CAPTION,
                text_color=C["danger"],
                anchor="w",
            ).pack(fill=tk.X, pady=(8, 0))

            def finish() -> None:
                self._sheet_close_callback = None
                self._dismiss_sheet()
                if on_done:
                    on_done()

            def persist(spent: float, spend_limit: float) -> None:
                saved = self.transaction_db.set_employee_budget(
                    profile["employee_id"],
                    name,
                    spent,
                    spend_limit,
                )
                if not saved:
                    err.set("Could not save spend limit.")
                    return
                self._refresh_transaction_list()
                self.status.set(f"Budget set for {name}")
                finish()

            def save() -> None:
                try:
                    spent = float(spent_var.get().strip() or "0")
                    spend_limit = float(limit_var.get().strip())
                except ValueError:
                    err.set("Enter numeric spend and limit values.")
                    return
                if spent < 0 or spend_limit <= 0:
                    err.set("Spend must be ≥ 0 and limit must be > 0.")
                    return
                if spent > spend_limit:
                    err.set("Spend exceeds limit — press Save anyway to keep it.")
                    save_btn.configure(text="Save anyway")
                    save_btn.configure(command=lambda: persist(spent, spend_limit))
                    return
                persist(spent, spend_limit)

            actions = ctk.CTkFrame(host, fg_color="transparent")
            actions.pack(fill=tk.X, pady=(12, 0))
            save_btn = ctk.CTkButton(
                actions,
                text="Save budget",
                command=save,
                height=36,
                corner_radius=R_CTRL,
                fg_color=C["accent"],
                hover_color=C["accent_hover"],
                text_color=C["paper"],
                font=F_TITLE,
            )
            save_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
            if on_done is not None:
                ctk.CTkButton(
                    actions,
                    text="Skip",
                    command=finish,
                    width=72,
                    height=36,
                    corner_radius=R_CTRL,
                    fg_color=C["surface"],
                    hover_color=C["card_hi"],
                    text_color=C["ink"],
                    font=F_BODY,
                ).pack(side=tk.LEFT, padx=(8, 0))

        self._open_sheet(
            "Budget",
            build,
            subtitle=name,
            on_close=on_done,
        )

    def _prompt_new_employee_budgets(self, previous_employee_ids: Set[str]):
        existing_budget_ids = {
            budget["employee_id"]
            for budget in self.transaction_db.get_employee_budgets()
        }
        self._budget_queue = [
            profile
            for profile in self.profile_store.list_profiles()
            if profile["employee_id"] not in previous_employee_ids
            and profile["employee_id"] not in existing_budget_ids
        ]
        self._show_next_budget_sheet()

    def _show_next_budget_sheet(self) -> None:
        if not self._budget_queue:
            return
        profile = self._budget_queue.pop(0)
        self._prompt_employee_budget(profile, on_done=self._show_next_budget_sheet)

    def _add_transaction(self) -> bool:
        amount_str = self.employee_amount.get().strip()
        merchant = self.employee_merchant.get().strip()
        employee = self.employee_combo_var.get().strip()
        date = datetime.now().strftime("%Y-%m-%d")
        if not all([amount_str, merchant, employee]):
            self.status.set("Merchant, amount, and employee are required")
            return False
        try:
            amount = float(amount_str)
        except ValueError:
            self.status.set("Amount must be a number")
            return False
        card_number = f"****-{employee[-4:]}" if len(employee) >= 4 else "****-****"
        employee_id = getattr(self, "_ledger_employee_map", {}).get(employee)
        if not employee_id:
            self.status.set("Select a valid employee")
            return False
        if self.transaction_db.add_transaction(
            date,
            amount,
            merchant,
            employee,
            card_number,
            employee_id=employee_id,
        ):
            self.audit.log_transaction_added(employee, amount, merchant)
            self.employee_amount.set("")
            self.employee_merchant.set("")
            self._refresh_transaction_list()
            self.status.set("Spend added")
            return True
        self.status.set("Failed to add transaction")
        return False

    def _export_transactions(self):
        import csv

        selected_name = self.ledger_filter.get()
        employee_id = getattr(self, "_ledger_employee_map", {}).get(selected_name)
        transactions = (
            self.transaction_db.get_transactions_by_employee_id(employee_id)
            if employee_id
            else self.transaction_db.get_all_transactions()
        )
        if not transactions:
            self.status.set("No transactions to export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Date", "Amount", "Merchant", "Employee", "Card"])
            for t in transactions:
                w.writerow([t["date"], t["amount"], t["merchant"], t["employee_name"], t["card_number"]])
        self.status.set(f"Exported {len(transactions)} rows")

    def _delete_selected_transaction(self):
        sel = self.trans_tree.selection()
        if not sel:
            self.status.set("Select a spend row to delete")
            return
        try:
            txn_id = int(sel[0])
        except ValueError:
            self.status.set("Bad row id")
            return

        def do_delete() -> None:
            if self.transaction_db.delete_transaction(txn_id):
                self.audit.log_deletion("transaction", str(txn_id), method="manual")
                self._refresh_transaction_list()
                self.status.set("Spend deleted")
            else:
                self.status.set("Delete failed")

        self._confirm_in_window(
            "Delete spend",
            "Delete the selected transaction?",
            do_delete,
            yes_label="Delete",
        )


if __name__ == "__main__":
    AppGUI().run()
