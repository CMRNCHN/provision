# Provision - Employee Onboarding Appliance

An automated desktop tool for streamlining new employee onboarding tasks. The application monitors `~/Downloads/Secure Downloads` — a locked-down subfolder created and hardened by the app itself (owner-only permissions, excluded from Spotlight and Time Machine) — for specific employee data files, converts them for Bitwarden import, optionally opens partner signup pages, and includes local transaction logging for company card expenses.

## Security Features

- **Bitwarden unlock** — workspace opens after Bitwarden master password login/unlock (no separate app password)
- **Local credential store** — settings and remembered Bitwarden email in a chmod-600 JSON file under `~/.provision/` (not Keychain-backed — unsigned `.app` launches would trigger a Keychain permission prompt on every read)
- **Transaction Logging** — SQLCipher-encrypted local SQLite, owner-only (`0o600`) permissions on top (FileVault still recommended — see [SECURITY_FEATURES.md](SECURITY_FEATURES.md))
- **Local disposal modes** — standard unlink, overwrite-then-delete, or best-effort secure erase (APFS/SSD: FileVault is the real protection)
- **Automated Data Retention** — 5/10/15/20 day lifecycle
- **Audit logging** — auth, imports, transactions, retention, config

See [SECURITY_FEATURES.md](SECURITY_FEATURES.md) for details.

## Onboarding Workflow

1. **Sign in with Bitwarden** (master password)
2. **Intake** — Manual entry (same HQ fields), or drop/browse `HQ-*.txt` / `HQ-*.rtf`
3. **Shared passphrase** — one passphrase for every new employee login (they change it later)
4. **Run** — convert → Bitwarden import → Outlook / Hyatt / Marriott assist → dispose local files
5. **Usernames** — `firstnamelastnameYEAR` (birth year)
6. **Profiles** — live Identity, Email Login, Hyatt, Marriott, and Work Card from Bitwarden
7. **Resume or edit** — resume missing accounts or edit Identity without rewriting unknown vault fields
8. **Recoverable deletion** — trash bound item IDs, restore for two days, then permanent purge

### First launch

1. Sign in with Bitwarden (email + master password, + 2FA if enabled)
2. Enter the **shared employee passphrase** and choose the Bitwarden destination:
   **Personal Vault** for personal accounts, or an exact organization collection name.
   Missing/unavailable organization collections stop the run; they never silently fall back to a personal vault.
3. Add an employee via **Manual** or queue an HQ file, then **Run**
4. Configure disposal / partner toggles under **Settings**

## Developer Setup

### Automated (macOS)

```bash
chmod +x setup.sh
./setup.sh
```

### Manual

1. Python 3.8+ with Tkinter (`brew install python-tk` on macOS)
2. Bitwarden CLI
3. Clone and install:

```bash
git clone https://github.com/CMRNCHN/provision.git
cd provision
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Run

```bash
source .venv/bin/activate   # or: .venv/bin/python run.py
python3 run.py
```

App-password and Bitwarden authentication happen inside the app. The Bitwarden CLI session key is kept in memory and passed to subsequent `bw` calls via `BW_SESSION`.

**Launch checklist**

1. Bitwarden CLI on PATH (`bw --version`) and vault unlockable
2. Shared employee passphrase ready (8+ chars)
3. For ⌘1–⌘6 paste into signup fields: grant **Accessibility** to Terminal/Python (or the Provision app) in System Settings → Privacy & Security
4. Optional Selenium prefill: install `chromedriver` on PATH (or set `PROVISION_CHROMEDRIVER`). Without it, signup uses system-browser handoff + the assist panel (recommended default when sites bot-block automation)

### Build installer

```bash
pip install '.[dev]'
chmod +x build.sh
./build.sh
```

## Honest limitations

- Transaction DB is SQLCipher-encrypted (`chmod 600` on top) — still enable **FileVault** on macOS (the app warns at launch if FileVault is Off): the encryption key itself lives in the same local credential store as everything else, so FileVault is what protects the whole local-storage layer, not just this one file.
- Partner signup is **assisted**, not fully automated: Provision opens the page, prefills what it can (or hands off to the system browser on bot blocks), and shows an in-app Account assist panel with per-field Copy/Paste plus ⌘1–⌘6 hotkeys. CAPTCHA and final submit always stay with you.
- Outlook must be marked Done before Hyatt/Marriott for that employee; Skip leaves accounts pending; Retry recreates the signup attempt.
- Structured clipboard payloads (`key: value` lines) are Keysmith-ready if you want an optional overlay macro — Keysmith is not required, and there is no KeyCue integration.
- Day-20 log retention shreds **tracked** log paths and per-employee `logs/employees/<name>/` dirs; shared session logs are line-scrubbed (not whole-file deleted).
- No Microsoft Graph email provisioning in this build
