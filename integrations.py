"""File-backed credentials, PIN auth, and the Bitwarden CLI gateway."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

CREDENTIALS_FILE = Path.home() / ".onboarding_credentials.json"
SECURE_CREDENTIALS_FILE = Path.home() / ".provision" / "credentials.json"

# Every `bw` CLI call funnels through _run_bw() behind a single lock, so an
# unbounded hang (flaky network, a stuck CLI prompt, a slow Bitwarden server)
# doesn't just freeze the caller — it blocks every other part of the app
# waiting on that same lock (background provisioning, other profile loads,
# retention checks) indefinitely, with no way to recover short of a force
# quit. Every subprocess.run() against `bw` must be bounded.
BW_CLI_TIMEOUT_SECONDS = 30
BW_CLI_SLOW_TIMEOUT_SECONDS = 90  # sync / import: legitimately slower on a large vault

APP_PASSWORD_HASH_KEY = "app_password_hash"
APP_PASSWORD_SALT_KEY = "app_password_salt"
APP_SESSION_TOKEN_KEY = "app_session_token"
APP_SESSION_CREATED_KEY = "app_session_created_at"
APP_PIN_HASH_KEY = "app_pin_hash"
APP_PIN_SALT_KEY = "app_pin_salt"
APP_PIN_ITERS_KEY = "app_pin_iters"
APP_PIN_FAILS_KEY = "app_pin_fails"
APP_PIN_LOCK_UNTIL_KEY = "app_pin_lock_until"
BW_SECRET_KEY = "bw_master_secret"
PBKDF2_ITERATIONS = 200_000
# New PINs use a higher KDF cost to slow offline brute-force of the on-disk
# encrypted master password; legacy PINs keep working via the stored count.
PIN_KDF_ITERATIONS = 600_000
APP_SESSION_TIMEOUT_SECONDS = 3600
PIN_MIN_LEN = 4
PIN_MAX_LEN = 8
# Failed-attempt lockout: after this many wrong PINs, entry is temporarily
# locked with an escalating backoff (mitigates in-app guessing).
PIN_MAX_ATTEMPTS = 5
PIN_LOCK_BASE_SECONDS = 30
PIN_LOCK_MAX_SECONDS = 900

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean_cli_text(text: str) -> str:
    """Strip ANSI / cursor noise from Bitwarden CLI stderr for UI display."""
    if not text:
        return ""
    cleaned = _ANSI_RE.sub("", text)
    cleaned = cleaned.replace("\r", "\n")
    lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
    lines = [ln for ln in lines if not ln.startswith("? Master password")]
    return "\n".join(lines).strip()


class CredentialStore:
    """Settings store: chmod-600 JSON under ~/.provision (no Keychain prompts)."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else SECURE_CREDENTIALS_FILE
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._data = self._load()
        self._migrate_legacy_sources()

    def _secure_delete_file(self, file_path: Path) -> None:
        """Overwrite then unlink a file; raise if unlink fails after overwrite."""
        try:
            if not file_path.exists():
                return
            file_size = file_path.stat().st_size or 1
            with open(file_path, "r+b") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.truncate(file_size)
                    f.flush()
                    os.fsync(f.fileno())
            file_path.unlink()
            logging.debug("Securely deleted file: %s", file_path)
        except Exception as e:
            logging.error("Failed to securely delete file %s: %s", file_path, e)
            raise

    def _load(self) -> Dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                return {str(k): str(v) for k, v in payload.items() if v is not None}
        except (json.JSONDecodeError, OSError) as e:
            logging.error("Could not read credentials file: %s", e)
        return {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _migrate_legacy_sources(self) -> None:
        if not CREDENTIALS_FILE.exists():
            return
        try:
            old_creds = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
            changed = False
            for key, value in old_creds.items():
                if value and key not in self._data:
                    self._data[str(key)] = str(value)
                    changed = True
            if changed:
                self._save()
            self._secure_delete_file(CREDENTIALS_FILE)
            logging.info("Migrated legacy credentials file into %s", self.path)
        except (json.JSONDecodeError, OSError) as e:
            logging.error("Could not migrate legacy credentials file: %s", e)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def get_all(self) -> Dict[str, str]:
        return dict(self._data)

    def update(self, new_creds: Dict[str, str]):
        changed = False
        for key, value in new_creds.items():
            if value:
                if self._data.get(key) != str(value):
                    self._data[key] = str(value)
                    changed = True
            elif key in self._data:
                del self._data[key]
                changed = True
        if changed:
            self._save()


class PinAuth:
    """App PIN (letters and/or digits) that unlocks an encrypted Bitwarden master password."""

    def __init__(self, credential_store: CredentialStore):
        self.store = credential_store

    @staticmethod
    def normalize_pin(pin: str) -> str:
        # Letters + digits only; case-sensitive as typed.
        return "".join(ch for ch in str(pin or "") if ch.isalnum())

    @classmethod
    def validate_pin(cls, pin: str) -> Optional[str]:
        raw = str(pin or "").strip()
        normalized = cls.normalize_pin(raw)
        if len(normalized) < PIN_MIN_LEN or len(normalized) > PIN_MAX_LEN:
            return f"PIN must be {PIN_MIN_LEN}–{PIN_MAX_LEN} letters and/or numbers."
        if normalized != raw:
            return "PIN can only include letters and numbers (no spaces or symbols)."
        return None

    def has_pin(self) -> bool:
        return bool(
            self.store.get(APP_PIN_HASH_KEY)
            and self.store.get(APP_PIN_SALT_KEY)
            and self.store.get(BW_SECRET_KEY)
            and self.store.get("bw_email")
        )

    @staticmethod
    def _hash_pin(pin: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256",
            pin.encode("utf-8"),
            salt,
            iterations,
        ).hex()

    @staticmethod
    def _fernet_for_pin(pin: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS):
        import base64

        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(pin.encode("utf-8")))
        return Fernet(key)

    def _iterations(self) -> int:
        """KDF cost stored with this PIN (legacy PINs default to the old cost)."""
        raw = self.store.get(APP_PIN_ITERS_KEY)
        try:
            return int(raw) if raw else PBKDF2_ITERATIONS
        except (TypeError, ValueError):
            return PBKDF2_ITERATIONS

    def setup(self, *, email: str, master_password: str, pin: str) -> Optional[str]:
        error = self.validate_pin(pin)
        if error:
            return error
        email = email.strip()
        if not email or "@" not in email:
            return "Enter a valid Bitwarden email."
        if not master_password:
            return "Enter your Bitwarden master password."
        pin = self.normalize_pin(pin)
        salt = secrets.token_bytes(16)
        iterations = PIN_KDF_ITERATIONS
        token = self._fernet_for_pin(pin, salt, iterations).encrypt(
            master_password.encode("utf-8")
        )
        self.store.update(
            {
                "bw_email": email,
                APP_PIN_SALT_KEY: salt.hex(),
                APP_PIN_HASH_KEY: self._hash_pin(pin, salt, iterations),
                APP_PIN_ITERS_KEY: str(iterations),
                BW_SECRET_KEY: token.decode("ascii"),
                APP_PIN_FAILS_KEY: "0",
                APP_PIN_LOCK_UNTIL_KEY: "0",
            }
        )
        return None

    def verify_pin(self, pin: str) -> bool:
        pin = self.normalize_pin(pin)
        stored_hash = self.store.get(APP_PIN_HASH_KEY)
        salt_hex = self.store.get(APP_PIN_SALT_KEY)
        if not stored_hash or not salt_hex or not pin:
            return False
        try:
            salt = bytes.fromhex(str(salt_hex))
        except ValueError:
            return False
        return secrets.compare_digest(
            self._hash_pin(pin, salt, self._iterations()), str(stored_hash)
        )

    def unlock_master_password(self, pin: str) -> Optional[str]:
        if not self.verify_pin(pin):
            return None
        salt_hex = self.store.get(APP_PIN_SALT_KEY)
        secret = self.store.get(BW_SECRET_KEY)
        if not salt_hex or not secret:
            return None
        try:
            salt = bytes.fromhex(str(salt_hex))
            return (
                self._fernet_for_pin(self.normalize_pin(pin), salt, self._iterations())
                .decrypt(str(secret).encode("ascii"))
                .decode("utf-8")
            )
        except Exception:
            logging.error("Failed to decrypt Bitwarden secret with PIN", exc_info=True)
            return None

    # --- Failed-attempt lockout -------------------------------------------
    def _fail_count(self) -> int:
        try:
            return int(self.store.get(APP_PIN_FAILS_KEY) or 0)
        except (TypeError, ValueError):
            return 0

    def lock_remaining(self) -> int:
        """Seconds until PIN entry is allowed again (0 when not locked)."""
        raw = self.store.get(APP_PIN_LOCK_UNTIL_KEY)
        try:
            until = float(raw) if raw else 0.0
        except (TypeError, ValueError):
            until = 0.0
        return max(0, int(round(until - time.time())))

    def reset_failures(self) -> None:
        self.store.update({APP_PIN_FAILS_KEY: "0", APP_PIN_LOCK_UNTIL_KEY: "0"})

    def _register_failure(self) -> int:
        fails = self._fail_count() + 1
        updates = {APP_PIN_FAILS_KEY: str(fails)}
        if fails >= PIN_MAX_ATTEMPTS:
            over = fails - PIN_MAX_ATTEMPTS
            lock = min(PIN_LOCK_BASE_SECONDS * (2 ** over), PIN_LOCK_MAX_SECONDS)
            updates[APP_PIN_LOCK_UNTIL_KEY] = str(time.time() + lock)
        self.store.update(updates)
        return fails

    def attempt_unlock(self, pin: str) -> Dict[str, Any]:
        """Verify a PIN with lockout enforcement.

        Returns a dict with ``status`` one of ``ok`` | ``bad_pin`` | ``locked``,
        the recovered ``password`` (on ok), ``remaining`` lock seconds, and
        ``attempts_left`` before the next timed lockout.
        """
        remaining = self.lock_remaining()
        if remaining > 0:
            return {
                "status": "locked",
                "remaining": remaining,
                "attempts_left": 0,
                "password": None,
            }
        password = self.unlock_master_password(pin)
        if password is None:
            fails = self._register_failure()
            rem = self.lock_remaining()
            return {
                "status": "locked" if rem > 0 else "bad_pin",
                "remaining": rem,
                "attempts_left": max(0, PIN_MAX_ATTEMPTS - fails),
                "password": None,
            }
        self.reset_failures()
        return {
            "status": "ok",
            "remaining": 0,
            "attempts_left": PIN_MAX_ATTEMPTS,
            "password": password,
        }

    def clear(self) -> None:
        self.store.update(
            {
                APP_PIN_HASH_KEY: "",
                APP_PIN_SALT_KEY: "",
                APP_PIN_ITERS_KEY: "",
                BW_SECRET_KEY: "",
                APP_PIN_FAILS_KEY: "0",
                APP_PIN_LOCK_UNTIL_KEY: "0",
            }
        )


class SessionManager:
    """PBKDF2 app-password authentication with a one-hour session token."""

    def __init__(
        self,
        credential_store: CredentialStore,
        session_timeout: int = APP_SESSION_TIMEOUT_SECONDS,
    ):
        self.credential_store = credential_store
        self.session_timeout = session_timeout

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        ).hex()

    def has_password(self) -> bool:
        return bool(
            self.credential_store.get(APP_PASSWORD_HASH_KEY)
            and self.credential_store.get(APP_PASSWORD_SALT_KEY)
        )

    def set_password(self, password: str) -> bool:
        if len(password) < 8:
            return False
        salt = secrets.token_bytes(16)
        expected_hash = self._hash_password(password, salt)
        self.credential_store.update(
            {
                APP_PASSWORD_SALT_KEY: salt.hex(),
                APP_PASSWORD_HASH_KEY: expected_hash,
            }
        )
        return bool(
            secrets.compare_digest(
                str(self.credential_store.get(APP_PASSWORD_HASH_KEY, "")),
                expected_hash,
            )
            and secrets.compare_digest(
                str(self.credential_store.get(APP_PASSWORD_SALT_KEY, "")),
                salt.hex(),
            )
        )

    def verify_password(self, password: str) -> bool:
        stored_hash = self.credential_store.get(APP_PASSWORD_HASH_KEY)
        salt_hex = self.credential_store.get(APP_PASSWORD_SALT_KEY)
        if not stored_hash or not salt_hex:
            return False
        try:
            salt = bytes.fromhex(str(salt_hex))
        except ValueError:
            return False
        candidate = self._hash_password(password, salt)
        return secrets.compare_digest(candidate, str(stored_hash))

    def create_session(self, password: str) -> bool:
        if not self.verify_password(password):
            return False
        token = secrets.token_urlsafe(32)
        created_at = str(time.time())
        self.credential_store.update(
            {
                APP_SESSION_TOKEN_KEY: token,
                APP_SESSION_CREATED_KEY: created_at,
            }
        )
        return bool(
            secrets.compare_digest(
                str(self.credential_store.get(APP_SESSION_TOKEN_KEY, "")),
                token,
            )
            and secrets.compare_digest(
                str(self.credential_store.get(APP_SESSION_CREATED_KEY, "")),
                created_at,
            )
        )

    def is_authenticated(self) -> bool:
        if not self.has_password():
            self.invalidate_session()
            return False
        token = self.credential_store.get(APP_SESSION_TOKEN_KEY)
        created_at = self.credential_store.get(APP_SESSION_CREATED_KEY)
        if not token or not created_at:
            return False
        try:
            active = 0 <= time.time() - float(created_at) < self.session_timeout
        except (TypeError, ValueError):
            active = False
        if not active:
            self.invalidate_session()
        return active

    def invalidate_session(self) -> None:
        self.credential_store.update(
            {
                APP_SESSION_TOKEN_KEY: "",
                APP_SESSION_CREATED_KEY: "",
            }
        )


class BitwardenService:
    """Gateway for Bitwarden CLI interactions with session key propagation."""

    def __init__(self):
        self.session_key: Optional[str] = None
        # The `bw` CLI keeps a single on-disk state (data.json); running two
        # invocations at once (e.g. a profile load while accounts are being
        # provisioned) can corrupt that state or hang. Serialize every call.
        self._cli_lock = threading.RLock()

    def _env_with_session(self) -> Dict[str, str]:
        env = os.environ.copy()
        if self.session_key:
            env["BW_SESSION"] = self.session_key
        else:
            env.pop("BW_SESSION", None)
        return env

    def _run_bw(self, args: List[str], **kwargs) -> subprocess.CompletedProcess:
        """Run a bw CLI command with BW_SESSION set when available.

        Serialized behind a lock so concurrent callers (background account
        provisioning + foreground profile loads) never invoke `bw` at once.
        Always bounded — see BW_CLI_TIMEOUT_SECONDS — unless the caller
        passes its own `timeout`.
        """
        kwargs.setdefault("timeout", BW_CLI_TIMEOUT_SECONDS)
        with self._cli_lock:
            return subprocess.run(
                ["bw", *args],
                env=self._env_with_session(),
                **kwargs,
            )

    def clear_session(self) -> None:
        self.session_key = None

    def get_status(self) -> str:
        """Return 'unlocked', 'locked', or 'unauthenticated'."""
        logging.info("Checking Bitwarden CLI status...")
        try:
            proc = self._run_bw(
                ["status", "--raw"],
                capture_output=True,
                text=True,
                check=True,
            )
            status = json.loads(proc.stdout).get("status")
            return status
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            FileNotFoundError,
            json.JSONDecodeError,
        ) as e:
            logging.error("Failed to check Bitwarden status. Is 'bw' CLI installed? Details: %s", e)
            raise

    def unlock(self, password: str) -> bool:
        """Unlock vault and store session key for subsequent CLI calls."""
        logging.info("Attempting to unlock Bitwarden vault...")
        try:
            env = self._env_with_session()
            env["BW_PASSWORD"] = password
            with self._cli_lock:
                proc = subprocess.run(
                    ["bw", "unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
                    env=env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=BW_CLI_TIMEOUT_SECONDS,
                )
            self.session_key = proc.stdout.strip() or None
            if not self.session_key:
                logging.error("Unlock succeeded but no session key returned.")
                return False
            logging.info("Bitwarden vault unlocked successfully.")
            return True
        except subprocess.CalledProcessError as e:
            self.clear_session()
            logging.error(
                "Failed to unlock Bitwarden. The password may be incorrect. Details: %s",
                (e.stderr or e.stdout or "").strip(),
            )
            return False
        except subprocess.TimeoutExpired:
            self.clear_session()
            logging.error(
                "Bitwarden unlock timed out after %ss — CLI may be hung or waiting on network.",
                BW_CLI_TIMEOUT_SECONDS,
            )
            return False
        except OSError as e:
            self.clear_session()
            logging.error("Could not run Bitwarden CLI: %s", e)
            return False

    def login(self, email: str, password: str, two_factor_code: Optional[str] = None) -> Dict[str, Any]:
        """Log into Bitwarden CLI and store session key (non-interactive)."""
        logging.info("Attempting to log into Bitwarden CLI for %s...", email)
        command = ["bw", "login", email, "--passwordenv", "BW_PASSWORD", "--raw"]
        if two_factor_code:
            command.extend(["--method", "0", "--code", str(two_factor_code)])

        try:
            env = self._env_with_session()
            env["BW_PASSWORD"] = password
            with self._cli_lock:
                proc = subprocess.run(
                    command,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=BW_CLI_TIMEOUT_SECONDS,
                )
            self.session_key = proc.stdout.strip() or None
            if not self.session_key:
                logging.error("Login succeeded but no session key returned.")
                return {"success": False, "two_factor_required": False, "error": "No session key"}
            logging.info("Bitwarden login successful.")
            return {"success": True, "two_factor_required": False}
        except subprocess.CalledProcessError as e:
            self.clear_session()
            stderr = (e.stderr or e.stdout or "")
            stderr_l = stderr.lower()
            if "two-step login is required" in stderr_l or "two-step" in stderr_l:
                return {"success": False, "two_factor_required": True}
            logging.error("Failed to log into Bitwarden. Details: %s", stderr.strip())
            return {
                "success": False,
                "two_factor_required": False,
                "error": _clean_cli_text(stderr) or "Login failed.",
            }
        except subprocess.TimeoutExpired:
            self.clear_session()
            logging.error(
                "Bitwarden login timed out after %ss — CLI may be hung or waiting on network.",
                BW_CLI_TIMEOUT_SECONDS,
            )
            return {
                "success": False,
                "two_factor_required": False,
                "error": "Bitwarden CLI timed out. Check your network and try again.",
            }
        except OSError as e:
            self.clear_session()
            logging.error("Could not run Bitwarden CLI: %s", e)
            return {
                "success": False,
                "two_factor_required": False,
                "error": "Bitwarden CLI is unavailable.",
            }

    def resolve_collection(self, collection_name: str) -> Optional[Dict[str, Any]]:
        """Resolve an exact organization collection; return None for personal vault.

        Bitwarden collections only exist inside organizations. Personal accounts
        import directly into the personal vault and do not have a collection ID.
        """
        name = (collection_name or "").strip()
        if not name or name.lower() in {"personal", "personal vault", "my vault"}:
            logging.info("Using personal Bitwarden vault (no organization collection).")
            return None

        logging.info("Looking for Bitwarden organization collection '%s'...", name)
        try:
            proc = self._run_bw(
                ["list", "collections", "--search", name, "--raw"],
                capture_output=True,
                text=True,
                check=True,
            )
            collections = json.loads(proc.stdout or "[]")
            exact_matches = [
                collection
                for collection in collections
                if str(collection.get("name", "")).casefold() == name.casefold()
            ]
            if len(exact_matches) > 1:
                organization_ids = sorted(
                    {
                        str(collection.get("organizationId") or "unknown")
                        for collection in exact_matches
                    }
                )
                raise RuntimeError(
                    f"Bitwarden collection '{name}' is ambiguous across organizations "
                    f"({', '.join(organization_ids)}). Use a unique collection name."
                )
            if exact_matches:
                exact = exact_matches[0]
                logging.info(
                    "Using organization collection '%s' (%s).",
                    exact.get("name"),
                    exact.get("id"),
                )
                return exact

            raise RuntimeError(
                f"Bitwarden collection '{name}' does not exist. "
                "Select 'Personal Vault' explicitly to import outside an organization."
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            raise RuntimeError(
                f"Could not resolve Bitwarden collection '{name}'."
            ) from e

    def import_json(
        self,
        bw_json: str,
        collection: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Import Bitwarden JSON into personal vault or an organization collection."""
        secure_temp_dir = Path.home() / ".provision_temp"
        secure_temp_dir.mkdir(exist_ok=True, mode=0o700)
        collection_id = str(collection.get("id")) if collection else "personal"
        organization_id = (
            str(collection.get("organizationId"))
            if collection and collection.get("organizationId")
            else None
        )
        temp_file = secure_temp_dir / f"temp_import_{collection_id}.json"

        try:
            import_payload = bw_json
            if collection:
                # Bitwarden JSON supports organizationId + collectionIds on items.
                # Populate them so organization imports land in the chosen collection.
                parsed = json.loads(bw_json)
                for item in parsed.get("items", []):
                    item["organizationId"] = organization_id
                    item["collectionIds"] = [collection_id]
                import_payload = json.dumps(parsed, indent=2)

            temp_file.write_text(import_payload, encoding="utf-8")
            temp_file.chmod(0o600)
            target_name = collection.get("name") if collection else "Personal Vault"
            logging.info("Importing data into Bitwarden target %s...", target_name)
            args = ["import"]
            if organization_id:
                args.extend(["--organizationid", organization_id])
            args.extend(["bitwardenjson", str(temp_file)])
            try:
                self._run_bw(
                    args,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=BW_CLI_SLOW_TIMEOUT_SECONDS,
                )
            except subprocess.CalledProcessError as e:
                detail = _clean_cli_text(e.stderr or e.stdout or "")
                raise RuntimeError(
                    f"Bitwarden import failed for {target_name}: "
                    f"{detail or 'unknown CLI error'}"
                ) from e
            except subprocess.TimeoutExpired as e:
                raise RuntimeError(
                    f"Bitwarden import for {target_name} timed out after "
                    f"{BW_CLI_SLOW_TIMEOUT_SECONDS}s."
                ) from e
        finally:
            if temp_file.exists():
                self._secure_delete_file(temp_file)

    def _secure_delete_file(self, file_path: Path) -> None:
        try:
            file_size = file_path.stat().st_size or 1
            with open(file_path, "r+b") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.truncate(file_size)
                    f.flush()
                    os.fsync(f.fileno())
            file_path.unlink()
            logging.debug("Securely deleted temporary file: %s", file_path)
        except Exception as e:
            logging.error("Failed to securely delete file %s: %s", file_path, e)
            try:
                file_path.unlink(missing_ok=True)
            except Exception:
                pass

    def list_items(self, collection_id: Optional[str] = None) -> List[Dict[str, Any]]:
        args = ["list", "items"]
        if collection_id:
            args.extend(["--collectionid", collection_id])
        args.append("--raw")
        proc = self._run_bw(
            args,
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout)

    def sync(self) -> None:
        self._run_bw(
            ["sync"],
            capture_output=True,
            text=True,
            check=True,
            timeout=BW_CLI_SLOW_TIMEOUT_SECONDS,
        )

    def get_item(self, item_id: str) -> Dict[str, Any]:
        proc = self._run_bw(
            ["get", "item", item_id, "--raw"],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout)

    def _encode_payload(self, payload: Dict[str, Any]) -> str:
        proc = self._run_bw(
            ["encode"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=True,
        )
        encoded = proc.stdout.strip()
        if not encoded:
            raise RuntimeError("Bitwarden returned an empty encoded payload.")
        return encoded

    def create_item(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        encoded = self._encode_payload(payload)
        proc = self._run_bw(
            ["create", "item", encoded],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout)

    def edit_item(self, item_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        encoded = self._encode_payload(payload)
        proc = self._run_bw(
            ["edit", "item", item_id, encoded],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout)

    def trash_item(self, item_id: str) -> None:
        self._run_bw(
            ["delete", "item", item_id],
            capture_output=True,
            text=True,
            check=True,
        )

    def restore_item(self, item_id: str) -> Dict[str, Any]:
        proc = self._run_bw(
            ["restore", "item", item_id],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout) if proc.stdout.strip() else {}

    def delete_item_permanently(self, item_id: str) -> None:
        self._run_bw(
            ["delete", "item", item_id, "--permanent"],
            capture_output=True,
            text=True,
            check=True,
        )

    def delete_item(self, item_id: str) -> None:
        """Backward-compatible trash operation."""
        self.trash_item(item_id)
