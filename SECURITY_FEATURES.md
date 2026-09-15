# Provision Security Features

## Overview

Security controls for application and Bitwarden authentication, local settings, transaction data, retention, and audit logging.

## Features

### 1. Local Credential Store

- Settings and the remembered Bitwarden email are stored as JSON at `~/.provision/credentials.json`, inside a `0o700` directory, written via a temp-file-then-atomic-replace and `chmod 0o600` on every save
- **Not Keychain-backed** — an earlier build used macOS Keychain via `keyring`, but unsigned `.app` launches trigger a Keychain "allow access" prompt on every read, so the store was switched to a plain permission-guarded file. There is no OS-level secret gate on this file beyond standard Unix file permissions
- On first run after upgrade, plaintext `~/.onboarding_credentials.json` is migrated into this store
- After a successful migration the source file is **securely overwritten and deleted** (no `.json.backup` left behind)
- If migration fails mid-way, the original file is left intact and an error is logged

### 2. Bitwarden Authentication

- The main window opens only after a successful `bw login` or `bw unlock` with the Bitwarden master password
- The Bitwarden master password is passed to the CLI through a process environment variable and is not persisted by Provision
- The returned `BW_SESSION` value is held in process memory and passed only to child `bw` commands
- Failed login/unlock and cancelled 2FA clear the in-memory session
- Authentication success/failure/cancellation events are written to the audit log
- There is no separate Provision app password gate

### 3. Transaction Logging

- SQLCipher-encrypted at `~/.provision_transactions.db` — genuinely unreadable without the key, not just permission-gated (a plain `sqlite3` connection to the file fails with "file is not a database")
- File mode is enforced as **`0o600`** before every SQLite connection
- The encryption key is a random 256-bit value generated once and stored in the same chmod-600 `CredentialStore` as every other local secret in this document — not tied to the Bitwarden master password or PIN, so the DB opens independent of vault-unlock state (e.g. retention's day-15 shred check)
- A DB written before this was added migrates in place on first launch: detected via probe-connect, every table copied into a freshly encrypted file, original replaced — logged either way
- Add / list / export CSV / delete by database id (Treeview `iid`)

### 4. Automated Data Retention

Independent milestone checks (overdue day-15/20 are not blocked by unfinished day-5/10):

| Day | Action |
|-----|--------|
| 5 | GUI prompt: is employee still active? |
| 10 | GUI prompt: approve shredding? |
| 15 | Auto-shred employee transactions |
| 20 | Secure-delete matching log files; scrub employee lines from audit log (fail closed on errors) |

- Scheduler starts after successful Bitwarden authentication
- Employees are registered from the onboarding pipeline after a successful convert

### 5. Security Audit Logging

File: `~/.provision_audit.log`

Logged events include: authentication, imports, deletions, transaction add/delete, retention actions, collection name config changes.

### 6. Bitwarden CLI Session

- Session key from `bw unlock --raw` / `bw login --raw` is kept on `BitwardenService`
- Subsequent CLI calls set `BW_SESSION` in the subprocess environment
- Session is cleared on failed unlock/login
- Named organization collections must resolve exactly; lookup failures do not fall back to Personal Vault

### 7. Field Autofill Extension

- A locally-bundled (not Chrome Web Store) MV3 extension registered into the Ops Chrome profile alongside the downloaded ones, via the same BiDi `webextension.install` mechanism (`autofill_extension/`)
- Purpose: offers to fill signup fields the Bitwarden extension's own autofill doesn't reach (first/last name, confirm password, zip) — closes the gap the manual ⌘1–⌘6 copy/paste assist keymap exists to work around
- Its content script only runs on the three known partner domains declared in its manifest (`signup.live.com`, `hyatt.com`, `marriott.com`) — no `<all_urls>` access, no other permissions beyond `storage`
- Per-employee field values reach it via a `chrome-extension://<fixed-id>/handoff.html?data=<base64 json>` page opened as an extra tab — never written to a file, never sent over the network; the handoff page stores it into `chrome.storage.local` and immediately closes itself
- The stored profile expires after 20 minutes even if never consumed
- Fills only on explicit click (per-field "Fill" button, or a "Fill all matched" action) and never touches submit/CAPTCHA elements — same "operator completes and submits" boundary as the rest of the assisted-signup flow

### 8. Secure Intake Watch Folder

- HQ files are watched/queued from `~/Downloads/Secure Downloads`, not `~/Downloads` itself — a subfolder the app creates and hardens on launch, since it transiently holds unshredded employee PII (SSN, card numbers, DOB) between drop-off and pipeline disposal
- Directory permissions are set/enforced to owner-only (`0o700`); a symlink found at that path is refused and replaced rather than followed (swap-attack protection)
- Excluded from Spotlight indexing (`.metadata_never_index` sentinel) and, on macOS, from Time Machine backups (`tmutil addexclusion`)
- Best-effort only: these are local-permission/indexing controls, not encryption — FileVault remains the real at-rest protection, same as the other local stores in this document

### 9. Secure Temporary Files

- Import temp files under `~/.provision_temp/` (`0o700` dir, `0o600` files)
- Multi-pass overwrite before unlink

### 10. Bitwarden-Synced Employee Profiles

- Versioned, owner-only metadata at `~/.provision_profiles.json`, keyed by immutable employee UUID
- Local records contain display metadata and vault item references only—never passwords, card numbers, CVVs, SSNs, or DOB
- New imports include hidden employee-ID and record-role fields, then reconcile actual Bitwarden item IDs after `bw sync`
- Legacy records require one unique exact employee/role match; ambiguous matches remain unresolved
- Identity edits reload and compare `revisionDate` before saving and preserve unknown item fields
- Identity, Email Login, Hyatt, Marriott, and Work Card values load only when selected and are cleared from the viewer on close, sync, or session expiry
- Profile deletion trashes only bound item IDs. Restore remains available for two days; permanent purge occurs only after the deadline with an unlocked vault
- Partial trash, restore, and purge failures remain visible and retryable. Audit entries contain employee UUIDs and redacted item IDs, not vault values

## File layout

| Path | Role |
|------|------|
| `integrations.py` | Local credential store and Bitwarden CLI gateway |
| `onboarding.py` | Pipeline orchestrator |
| `bw_import_converter.py` | HQ → Bitwarden JSON (single converter source) |
| `transaction_db.py` | SQLite transactions |
| `data_retention.py` | Retention schedule + shred |
| `employee_profiles.py` | UUID profile metadata, reconciliation, edit, trash/restore/purge |
| `audit_logger.py` | Audit trail |
| `account_automation.py` | Assisted partner signup: Selenium prefill, bot-block handoff, clipboard/hotkey palette |

## Dependencies

- `requests`, `selenium`, `msal`, `tkinterdnd2-universal` (DnD optional; falls back on Python builds without Tk DnD)
- `sqlcipher3` — encrypts the transaction DB at rest

## Best practices

1. Use separate strong app and Bitwarden passwords; enable Bitwarden 2FA
2. Review `~/.provision_audit.log` periodically
3. `~/.provision_transactions.db` is SQLCipher-encrypted, but **FileVault is still required for production** — the encryption key itself lives in the same chmod-600 credential store as everything else, so FileVault is what protects the whole local-storage layer at rest, not just this one file. The app warns at launch if FileVault is Off
4. Respond to retention prompts promptly

## Future work

- Biometric unlock
- Deeper anti-bot partner enrollment automation

## Version

- **0.5.0** — Transaction DB encrypted at rest via SQLCipher, with in-place migration of pre-existing plaintext databases
- **0.4.0** — Field Autofill browser extension (fills signup fields beyond username/password); fixed a dead status-bar update, a Finder AppleScript crash, and the assist walkthrough's fixed field order
- **0.3.1** — Intake watch folder moved from `~/Downloads` to a hardened `~/Downloads/Secure Downloads` subfolder (owner-only permissions, Spotlight/Time Machine excluded)
- **0.3.0** — Renamed from DOWNLOWd to Provision; PIN unlock hardened with failed-attempt lockout and a stronger, versioned KDF
- **0.2.2** — Selenium partner prefill, tracked day-20 logs, FileVault launch warning, Python 3.14 Tk DnD fallback
- Compatibility: macOS 10.15+, Python 3.11+
