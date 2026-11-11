"""
╔══════════════════════════════════════════════════════════════╗
║          VAULT — AES-256-GCM Encrypted Password Manager      ║
║      Dark Luxury Edition | Tier 3 — Advanced Features        ║
╚══════════════════════════════════════════════════════════════╝

Security model:
  • Master password → Argon2id KDF → 32-byte AES-256-GCM key (never stored).
  • Entire vault is encrypted as a single JSON blob; only KDF params + salt
    are stored in plaintext in the file header.
  • Wrong password → GCM authentication tag fails → decryption error.
    No separate password hash is stored.
  • Re-entry of master password required each time a saved password is
    revealed or edited; revealed password auto-hides after REVEAL_AUTO_HIDE_SEC seconds.
  • Wrong-password back-off: 1 s, 2 s, 4 s … with LOCKOUT_DURATION_SEC lockout
    after LOCKOUT_AFTER_FAILS failures.
  • Atomic writes (write tmp → os.replace) + one .bak copy.

Tier 3 additions:
  18. Edit an existing entry with master password re-authentication.
  19. Search / filter field dynamically across website/label and username.
  20. Replaced manual canvas list with styled ttk.Treeview (passwords always masked).
  21. Cryptographically secure random password generator using stdlib `secrets`.
  22. Change master password flow (re-encrypts the entire vault with fresh salt & key).
  23. Encrypted export and import backup (.vlt) with merge/replace options.

Known limitations (Python-level, not fixable):
  • Python cannot reliably wipe secrets from memory (CPython string interning,
    GC, reference counting). Clearing references is best-effort only.
  • The Windows clipboard history (Win+V) and third-party clipboard managers
    may retain copies of revealed passwords after our auto-clear fires. We
    cannot control those stores.

Dependencies:
    pip install cryptography argon2-cffi
    (stdlib only for all other features)
"""

# ─── STANDARD LIBRARY ────────────────────────────────────────────────────────
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import base64
import json
import logging
import logging.handlers
import os
import re
import secrets
import string
import time
import unicodedata
from datetime import datetime

# ─── THIRD-PARTY (crypto) ────────────────────────────────────────────────────
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type as Argon2Type


# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

# ── File paths ────────────────────────────────────────────────────────────────
DB_FILE        = os.path.join(os.path.expanduser("~"), "vault_database.vlt")
DB_LEGACY      = os.path.join(os.path.expanduser("~"), "vault_database.xml")
LOG_FILE       = os.path.join(os.path.expanduser("~"), "vault.log")

# ── Vault format ──────────────────────────────────────────────────────────────
VAULT_FORMAT_VERSION = 1

# ── Argon2id KDF ─────────────────────────────────────────────────────────────
ARGON2_TIME_COST    = 2        # iterations
ARGON2_MEMORY_KIB   = 65536   # 64 MiB; raise to 102400 on beefy hardware
ARGON2_PARALLELISM  = 4
ARGON2_HASH_LEN     = 32      # bytes → AES-256 key
ARGON2_SALT_LEN     = 16      # bytes

# ── Security / lockout ────────────────────────────────────────────────────────
MIN_MASTER_PW_LEN       = 12   # characters
MIN_ENTRY_PW_LEN        = 8
MAX_LABEL_LEN           = 100
MAX_USERNAME_LEN        = 100
MAX_PASSWORD_LEN        = 256
LOCKOUT_AFTER_FAILS     = 5    # wrong attempts before lockout
LOCKOUT_DURATION_SEC    = 60   # seconds of lockout
DEFAULT_GEN_PW_LEN      = 16   # generated password length

# ── Auto-lock ─────────────────────────────────────────────────────────────────
AUTO_LOCK_MINUTES       = 5                           # minutes of inactivity
AUTO_LOCK_MS            = AUTO_LOCK_MINUTES * 60_000  # ms for after()

# ── Reveal / clipboard ────────────────────────────────────────────────────────
REVEAL_AUTO_HIDE_SEC    = 15   # seconds before revealed password re-masks
CLIPBOARD_CLEAR_SECONDS = 20   # seconds before clipboard auto-cleared

# ── UI timing ─────────────────────────────────────────────────────────────────
CLOCK_INTERVAL_MS   = 1_000   # clock refresh
TOAST_DURATION_MS   = 2_500

# ── Fonts ─────────────────────────────────────────────────────────────────────
FONT_MONO       = "Courier New"
FONT_SERIF      = "Georgia"
FONT_LABEL_SM   = (FONT_MONO, 7, "bold")
FONT_LABEL_MED  = (FONT_MONO, 8, "bold")
FONT_LABEL_LG   = (FONT_MONO, 9, "bold")
FONT_BODY       = (FONT_MONO, 9)
FONT_INPUT      = (FONT_MONO, 11)
FONT_HEADING_SM = (FONT_MONO, 11, "bold")
FONT_HEADING    = (FONT_MONO, 12, "bold")
FONT_LOGO       = (FONT_MONO, 20, "bold")
FONT_ICON       = (FONT_MONO, 20)
FONT_ICON_LG    = (FONT_MONO, 24)
FONT_TOAST_ICON = (FONT_MONO, 14, "bold")
FONT_TOAST_MSG  = (FONT_SERIF, 10)

# ── Padding / spacing ─────────────────────────────────────────────────────────
PAD_OUTER    = 24
PAD_CARD     = 28
PAD_CARD_Y   = 20
PAD_SECTION  = 16
PAD_ROW      = 8
PAD_FIELD    = 12
PAD_FIELD_Y  = 8
PAD_BTN      = 20
PAD_BTN_Y    = 8
HEIGHT_SEP   = 1
HEIGHT_BAR   = 2

# Trivially weak master passwords rejected on creation
_TRIVIAL_MASTER_PASSWORDS = {
    "password", "password1", "password123",
    "123456789012", "111111111111", "qwertyuiop",
    "abcdefghijkl",
}


# ══════════════════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════════════════

class Theme:
    """Midnight-luxury dark palette. Read-only class attributes."""
    bg          = "#0D0F1A"   # near-black midnight blue
    surface     = "#13172B"   # raised surface
    card        = "#1A1F38"   # card background
    border      = "#252A45"   # subtle border
    accent      = "#C9A84C"   # antique gold
    accent2     = "#7B61FF"   # electric violet
    accent_dim  = "#8B6E2E"   # dimmed gold
    text        = "#E8E6F0"   # soft white
    text_muted  = "#6B6E8A"   # muted lavender-grey
    text_dim    = "#3D4060"   # very dim
    success     = "#4EC994"   # emerald
    danger      = "#E05C7A"   # rose red
    warning     = "#F0A850"   # amber
    input_bg    = "#0F1225"   # input field bg
    hover       = "#22284A"   # hover state
    tag_bg      = "#1E2240"   # tag background

T = Theme


# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════════════

def _setup_logging() -> logging.Logger:
    fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s")
    fh  = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=1_048_576, backupCount=3, encoding="utf-8", delay=True
    )
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger = logging.getLogger("vault")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logger.addHandler(fh)
        logger.addHandler(sh)
    return logger

log = _setup_logging()


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION STATE
# ══════════════════════════════════════════════════════════════════════════════

_session_key:  bytes | None = None
_session_salt: bytes | None = None


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO LAYER
# ══════════════════════════════════════════════════════════════════════════════

def _derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from master_password + salt via Argon2id."""
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Argon2Type.ID,
    )


def _aes_encrypt(plaintext_bytes: bytes, key: bytes) -> str:
    """AES-256-GCM encrypt. Returns base64url(12-byte-nonce || ciphertext+tag)."""
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext_bytes, None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def _aes_decrypt(blob: str, key: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises InvalidTag on wrong key / tampered data."""
    raw       = base64.urlsafe_b64decode(blob.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


# ══════════════════════════════════════════════════════════════════════════════
#  VAULT FILE I/O
# ══════════════════════════════════════════════════════════════════════════════

def _build_header(salt: bytes) -> dict:
    return {
        "v": VAULT_FORMAT_VERSION,
        "salt": salt.hex(),
        "t": ARGON2_TIME_COST,
        "m": ARGON2_MEMORY_KIB,
        "p": ARGON2_PARALLELISM,
    }


def load_vault() -> list[dict]:
    """Decrypt and return all entries."""
    global _session_key
    if _session_key is None:
        raise RuntimeError("Vault is locked — call unlock_vault() first.")
    try:
        with open(DB_FILE, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        log.error("Could not open vault file: %s", exc)
        raise

    if len(lines) < 2 or not lines[1].strip():
        return []
    try:
        plaintext = _aes_decrypt(lines[1].strip(), _session_key)
    except InvalidTag:
        log.error("Vault decryption failed — authentication tag mismatch.")
        raise
    except Exception as exc:
        log.error("Vault decryption error: %s", type(exc).__name__)
        raise
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        log.error("Vault JSON decode error: %s", type(exc).__name__)
        raise ValueError("Vault data is corrupt.") from exc


def save_vault(entries: list[dict]) -> None:
    """Encrypt all entries and atomically write the vault file."""
    global _session_key, _session_salt
    if _session_key is None or _session_salt is None:
        raise RuntimeError("Vault is locked — cannot save.")
    try:
        blob = _aes_encrypt(
            json.dumps(entries, ensure_ascii=False).encode("utf-8"),
            _session_key,
        )
        content  = json.dumps(_build_header(_session_salt)) + "\n" + blob + "\n"
        tmp_path = DB_FILE + ".tmp"
        bak_path = DB_FILE + ".bak"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        if os.path.exists(DB_FILE):
            try:
                if os.path.exists(bak_path):
                    os.remove(bak_path)
                os.replace(DB_FILE, bak_path)
            except OSError as exc:
                log.warning("Could not rotate backup: %s", exc)
        os.replace(tmp_path, DB_FILE)
        log.info("Vault saved — %d entries.", len(entries))
    except OSError as exc:
        log.error("Vault save failed (I/O): %s", exc)
        raise
    except Exception as exc:
        log.error("Vault save failed: %s", type(exc).__name__)
        raise


def unlock_vault(master_password: str) -> None:
    """Derive session key from an existing vault file and verify it."""
    global _session_key, _session_salt
    try:
        with open(DB_FILE, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        log.error("Cannot open vault file for unlock: %s", exc)
        raise

    try:
        hdr  = json.loads(lines[0])
        salt = bytes.fromhex(hdr["salt"])
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        log.error("Vault header corrupt: %s", type(exc).__name__)
        raise ValueError("Vault file header is corrupt.") from exc

    key = _derive_key(master_password, salt)
    if len(lines) >= 2 and lines[1].strip():
        _aes_decrypt(lines[1].strip(), key)

    _session_key  = key
    _session_salt = salt
    log.info("Vault unlocked successfully.")


def initialize_vault(master_password: str) -> None:
    """Create a fresh vault with a new random salt and an empty entry list."""
    global _session_key, _session_salt
    salt = os.urandom(ARGON2_SALT_LEN)
    key  = _derive_key(master_password, salt)
    _session_key  = key
    _session_salt = salt
    save_vault([])
    log.info("New vault initialized.")


def lock_vault() -> None:
    """Drop the session key reference."""
    global _session_key, _session_salt
    _session_key  = None
    _session_salt = None
    log.info("Vault locked.")


def add_vault_entry(label: str, username: str, password: str) -> None:
    entries = load_vault()
    entries.append({
        "label":    label,
        "username": username,
        "password": password,
        "created":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    save_vault(entries)
    log.info("Entry added — label: '%s'.", label)


def edit_vault_entry(index: int, label: str, username: str, password: str) -> None:
    """Edit an existing vault entry at index."""
    entries = load_vault()
    if 0 <= index < len(entries):
        entries[index]["label"]    = label
        entries[index]["username"] = username
        entries[index]["password"] = password
        entries[index]["updated"]  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_vault(entries)
        log.info("Entry edited — label: '%s'.", label)
    else:
        raise IndexError("Entry index out of range.")


def delete_vault_entry(index: int) -> None:
    entries = load_vault()
    if 0 <= index < len(entries):
        label = entries[index].get("label", "?")
        entries.pop(index)
        save_vault(entries)
        log.info("Entry deleted — label: '%s'.", label)


def change_master_password(current_password: str, new_password: str) -> None:
    """Re-encrypt the whole vault with a new salt and key derived from new_password."""
    global _session_key, _session_salt
    if _session_key is None or _session_salt is None:
        raise RuntimeError("Vault is locked.")

    current_key = _derive_key(current_password, _session_salt)
    if current_key != _session_key:
        raise ValueError("Current master password is incorrect.")

    entries = load_vault()
    new_salt = os.urandom(ARGON2_SALT_LEN)
    new_key  = _derive_key(new_password, new_salt)

    blob = _aes_encrypt(
        json.dumps(entries, ensure_ascii=False).encode("utf-8"),
        new_key,
    )
    header   = _build_header(new_salt)
    content  = json.dumps(header) + "\n" + blob + "\n"
    tmp_path = DB_FILE + ".tmp"
    bak_path = DB_FILE + ".bak"

    with open(tmp_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    if os.path.exists(DB_FILE):
        try:
            if os.path.exists(bak_path):
                os.remove(bak_path)
            os.replace(DB_FILE, bak_path)
        except OSError:
            pass
    os.replace(tmp_path, DB_FILE)

    _session_key  = new_key
    _session_salt = new_salt
    log.info("Master password successfully changed and vault re-encrypted.")


# ══════════════════════════════════════════════════════════════════════════════
#  RANDOM PASSWORD GENERATOR (Item 21)
# ══════════════════════════════════════════════════════════════════════════════

def generate_password(length: int = DEFAULT_GEN_PW_LEN, include_symbols: bool = True) -> str:
    """Generate a cryptographically secure random password using secrets module."""
    if length < 8:
        length = 8
    lowers  = string.ascii_lowercase
    uppers  = string.ascii_uppercase
    digits  = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?" if include_symbols else ""
    pool    = lowers + uppers + digits + symbols

    # Guarantee at least one character from each character category
    guaranteed = [
        secrets.choice(lowers),
        secrets.choice(uppers),
        secrets.choice(digits),
    ]
    if include_symbols:
        guaranteed.append(secrets.choice(symbols))

    remaining = [secrets.choice(pool) for _ in range(length - len(guaranteed))]
    combo     = guaranteed + remaining

    # Secure shuffle using Fisher-Yates with secrets.randbelow
    for i in range(len(combo) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combo[i], combo[j] = combo[j], combo[i]

    return "".join(combo)


# ══════════════════════════════════════════════════════════════════════════════
#  INPUT VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def _strip_control(s: str) -> str:
    """Remove ASCII control characters and Unicode categories Cc/Cf (except space)."""
    return "".join(
        ch for ch in s
        if ch == " " or (unicodedata.category(ch) not in ("Cc", "Cf") and ord(ch) >= 32)
    )


def validate_entry(label: str, username: str, password: str) -> list[str]:
    """Validate entry fields."""
    errors: list[str] = []

    clean_label = _strip_control(label).strip()
    if not clean_label:
        errors.append("Label / Site is required.")
    elif len(clean_label) > MAX_LABEL_LEN:
        errors.append(f"Label must be ≤ {MAX_LABEL_LEN} characters.")

    clean_user = _strip_control(username).strip()
    if not clean_user:
        errors.append("Username is required.")
    elif len(clean_user) > MAX_USERNAME_LEN:
        errors.append(f"Username must be ≤ {MAX_USERNAME_LEN} characters.")

    if not password:
        errors.append("Password is required.")
    elif password.strip() == "":
        errors.append("Password must not be whitespace-only.")
    elif len(password) < MIN_ENTRY_PW_LEN:
        errors.append(f"Password must be at least {MIN_ENTRY_PW_LEN} characters.")
    elif len(password) > MAX_PASSWORD_LEN:
        errors.append(f"Password must be ≤ {MAX_PASSWORD_LEN} characters.")

    return errors


def validate_master_password(pw: str, confirm: str) -> list[str]:
    """Validate a new master password."""
    errors: list[str] = []

    if not pw:
        errors.append("Master password cannot be empty.")
        return errors

    if len(pw) < MIN_MASTER_PW_LEN:
        errors.append(f"Master password must be at least {MIN_MASTER_PW_LEN} characters.")

    if pw.lower() in _TRIVIAL_MASTER_PASSWORDS:
        errors.append("That password is too common — choose something unique.")

    if len(set(pw)) == 1:
        errors.append("Password cannot be a single repeated character.")

    if re.fullmatch(r"[a-z]+", pw.lower()) and pw.lower() == "".join(
        chr(ord(pw[0]) + i) for i in range(len(pw))
    ):
        errors.append("Password cannot be a simple alphabet sequence.")

    if re.fullmatch(r"\d+", pw):
        digits = [int(c) for c in pw]
        diffs  = [(digits[i+1] - digits[i]) % 10 for i in range(len(digits)-1)]
        if len(set(diffs)) == 1:
            errors.append("Password cannot be a simple numeric sequence.")

    if pw != confirm:
        errors.append("Passwords do not match.")

    return errors


# ══════════════════════════════════════════════════════════════════════════════
#  PASSWORD STRENGTH
# ══════════════════════════════════════════════════════════════════════════════

def _pw_strength(pw: str) -> tuple[str, str]:
    """Return (label, colour) for a rough strength score."""
    score = 0
    if len(pw) >= 10: score += 1
    if len(pw) >= 16: score += 1
    if any(c.isupper() for c in pw): score += 1
    if any(c.islower() for c in pw): score += 1
    if any(c.isdigit() for c in pw): score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/`~" for c in pw): score += 1
    if score <= 2: return "WEAK",   T.danger
    if score <= 4: return "FAIR",   T.warning
    return "STRONG", T.success


# ══════════════════════════════════════════════════════════════════════════════
#  WIDGETS
# ══════════════════════════════════════════════════════════════════════════════

class StyledEntry(tk.Frame):
    """Input field with label + gold underline focus effect."""
    def __init__(self, master, label="", placeholder="", show=None, **kwargs):
        super().__init__(master, bg=T.bg, **kwargs)
        self._ph      = placeholder
        self._show_ch = show

        if label:
            tk.Label(self, text=label.upper(), fg=T.text_muted, bg=T.bg,
                     font=FONT_LABEL_MED, anchor="w").pack(fill="x", padx=2)

        container = tk.Frame(self, bg=T.input_bg,
                             padx=PAD_FIELD, pady=PAD_FIELD_Y,
                             highlightbackground=T.border, highlightthickness=1)
        container.pack(fill="x")

        self.var = tk.StringVar()
        kw = dict(textvariable=self.var, bg=T.input_bg, fg=T.text,
                  insertbackground=T.accent, relief="flat", bd=0,
                  font=FONT_INPUT, highlightthickness=0)
        if show:
            kw["show"] = show
        self.entry = tk.Entry(container, **kw)
        self.entry.pack(fill="x")

        self.bar = tk.Frame(self, bg=T.border, height=HEIGHT_BAR)
        self.bar.pack(fill="x")

        self.entry.bind("<FocusIn>",  self._on_focus)
        self.entry.bind("<FocusOut>", self._on_blur)
        if placeholder:
            self._show_placeholder()
            self.entry.bind("<FocusIn>",  self._clear_ph)
            self.entry.bind("<FocusOut>", self._restore_ph)

    def _on_focus(self, _=None): self.bar.config(bg=T.accent)
    def _on_blur(self,  _=None): self.bar.config(bg=T.border)

    def _show_placeholder(self):
        if not self.var.get():
            if self._show_ch:
                self.entry.config(show="")
            self.entry.insert(0, self._ph)
            self.entry.config(fg=T.text_dim)

    def _clear_ph(self, _=None):
        if self.entry.get() == self._ph:
            self.entry.delete(0, "end")
            self.entry.config(fg=T.text)
            if self._show_ch:
                self.entry.config(show=self._show_ch)
        self._on_focus()

    def _restore_ph(self, _=None):
        if not self.entry.get():
            self._show_placeholder()
        self._on_blur()

    def get(self) -> str:
        v = self.var.get()
        return "" if v == self._ph else v

    def set_text(self, val: str):
        self.entry.delete(0, "end")
        self.entry.insert(0, val)
        self.entry.config(fg=T.text)
        if self._show_ch:
            self.entry.config(show=self._show_ch)

    def clear(self):
        self.entry.delete(0, "end")
        if self._ph:
            self._show_placeholder()


class GoldButton(tk.Frame):
    """Gold-bordered button with hover shimmer."""
    _VARIANTS = {
        "primary": (T.accent,  T.accent,     T.accent,  T.bg),
        "danger":  (T.danger,  T.danger,     T.danger,  T.text),
        "ghost":   (T.border,  T.text_muted, T.hover,   T.text_muted),
        "violet":  (T.accent2, T.accent2,    T.accent2, T.text),
    }

    def __init__(self, master, text="", command=None, variant="primary", **kwargs):
        super().__init__(master, bg=T.bg, **kwargs)
        border, fg_off, _bg_on, fg_on = self._VARIANTS.get(variant, self._VARIANTS["primary"])
        self._bg_on  = _bg_on
        self._fg_on  = fg_on
        self._fg_off = fg_off

        self.btn = tk.Label(self, text=text, fg=fg_off, bg=T.bg,
                            font=FONT_LABEL_LG,
                            padx=PAD_BTN, pady=PAD_BTN_Y, cursor="hand2",
                            highlightbackground=border, highlightthickness=1)
        self.btn.pack(fill="both", expand=True)
        self.btn.bind("<Enter>",    self._hover_on)
        self.btn.bind("<Leave>",    self._hover_off)
        self.btn.bind("<Button-1>", lambda _: command() if command else None)

    def _hover_on(self, _):  self.btn.config(bg=self._bg_on,  fg=self._fg_on)
    def _hover_off(self, _): self.btn.config(bg=T.bg,          fg=self._fg_off)


class Toast:
    """Non-blocking toast notification."""
    def __init__(self, root: tk.Tk):
        self.root = root
        self._win = None
        self._job = None

    def show(self, message: str, kind: str = "success", duration: int = TOAST_DURATION_MS):
        self._cancel_job()
        if self._win:
            try:
                self._win.destroy()
            except tk.TclError:
                pass

        color = {
            "success": T.success, "error": T.danger,
            "info": T.accent2,    "warning": T.warning,
        }.get(kind, T.accent)
        icon = {"success": "✦", "error": "✖", "info": "◆", "warning": "▲"}.get(kind, "●")

        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=T.card)

        self.root.update_idletasks()
        win.geometry(
            f"+{self.root.winfo_x() + self.root.winfo_width() - 320}"
            f"+{self.root.winfo_y() + self.root.winfo_height() - 90}"
        )

        frame = tk.Frame(win, bg=T.card, padx=18, pady=12,
                         highlightbackground=color, highlightthickness=1)
        frame.pack()
        tk.Label(frame, text=icon,    fg=color, bg=T.card, font=FONT_TOAST_ICON).pack(side="left", padx=(0, 10))
        tk.Label(frame, text=message, fg=T.text, bg=T.card, font=FONT_TOAST_MSG).pack(side="left")

        self._win = win
        self._job = win.after(duration, self._dismiss)

    def _cancel_job(self):
        if self._job:
            try:
                self.root.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None

    def _dismiss(self):
        self._job = None
        try:
            if self._win:
                self._win.destroy()
                self._win = None
        except tk.TclError:
            pass

    def destroy(self):
        self._cancel_job()
        self._dismiss()


def _build_card(parent: tk.Frame, title: str, title_color: str, subtitle: str = "") -> tk.Frame:
    """Build a card-frame with title bar and separator."""
    outer = tk.Frame(parent, bg=T.card,
                     highlightbackground=T.border, highlightthickness=1)
    outer.pack(fill="both", expand=True, pady=(12, 0))

    title_row = tk.Frame(outer, bg=T.card, pady=PAD_SECTION, padx=PAD_CARD)
    title_row.pack(fill="x")

    tk.Label(title_row, text=title, fg=title_color, bg=T.card,
             font=FONT_HEADING).pack(side="left")
    if subtitle:
        tk.Label(title_row, text=subtitle, fg=T.text_muted, bg=T.card,
                 font=(FONT_MONO, 8)).pack(side="right", pady=(4, 0))

    tk.Frame(outer, bg=T.border, height=HEIGHT_SEP).pack(fill="x")
    return outer


# ══════════════════════════════════════════════════════════════════════════════
#  MODALS
# ══════════════════════════════════════════════════════════════════════════════

class MasterPasswordGate:
    """Toplevel lock screen."""
    def __init__(self, root: tk.Tk, on_success, is_relock: bool = False):
        self.root         = root
        self.on_success   = on_success
        self.is_relock    = is_relock
        self._fail_count  = 0
        self._locked_until = 0.0

        self._legacy = os.path.exists(DB_LEGACY) and not os.path.exists(DB_FILE)
        self._is_new = not os.path.exists(DB_FILE)

        self.win = tk.Toplevel(root)
        self.win.title("VAULT — Security Gateway")
        self.win.configure(bg=T.bg)
        self.win.resizable(False, False)
        h = 420 if (self._is_new or self._legacy) else 360
        self.win.geometry(f"470x{h}")
        self.win.update_idletasks()
        sw, sh = self.win.winfo_screenwidth(), self.win.winfo_screenheight()
        self.win.geometry(f"470x{h}+{(sw-470)//2}+{(sh-h)//2}")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        self.win.grab_set()

        self._build()

    def _build(self):
        outer = tk.Frame(self.win, bg=T.bg, padx=PAD_OUTER, pady=PAD_OUTER)
        outer.pack(fill="both", expand=True)

        hdr = tk.Frame(outer, bg=T.bg)
        hdr.pack(fill="x", pady=(0, 10))
        tk.Label(hdr, text="◈", fg=T.accent, bg=T.bg, font=FONT_ICON).pack(side="left", padx=(0, 6))
        prefix = "🔒  " if self.is_relock else ""
        tk.Label(hdr, text=f"{prefix}VAULT GATEWAY", fg=T.text, bg=T.bg,
                 font=FONT_HEADING_SM).pack(side="left")
        tk.Frame(outer, bg=T.accent, height=HEIGHT_SEP).pack(fill="x", pady=(0, 15))

        self.card = tk.Frame(outer, bg=T.card, padx=PAD_CARD, pady=PAD_CARD_Y,
                             highlightbackground=T.border, highlightthickness=1)
        self.card.pack(fill="both", expand=True)

        if self.is_relock:
            self._build_unlock(relock_msg="Vault auto-locked due to inactivity.")
        elif self._is_new or self._legacy:
            self._build_setup()
        else:
            self._build_unlock()

    def _build_setup(self):
        tk.Label(self.card, text="CREATE MASTER PASSWORD", fg=T.accent,
                 bg=T.card, font=FONT_HEADING_SM, anchor="w").pack(fill="x", pady=(0, 4))

        msg = (
            "An old MD5 vault was detected and will be backed up as\n"
            "'vault_database.xml.bak'. Old passwords cannot be recovered\n"
            "(MD5 is one-way). Start fresh with a master password below."
        ) if self._legacy else (
            "No vault found. Create a master password to initialise an\n"
            f"encrypted vault. Minimum {MIN_MASTER_PW_LEN} chars — write it down;\n"
            "it cannot be recovered if lost."
        )
        tk.Label(self.card, text=msg, fg=T.text_muted, bg=T.card,
                 font=(FONT_MONO, 8), justify="left", anchor="w").pack(fill="x", pady=(0, 14))

        self.pw1 = StyledEntry(self.card, label="Master Password",
                               placeholder=f"Min {MIN_MASTER_PW_LEN} chars", show="●")
        self.pw1.pack(fill="x", pady=(0, PAD_ROW))

        self.pw2 = StyledEntry(self.card, label="Confirm Password",
                               placeholder="Repeat password", show="●")
        self.pw2.pack(fill="x", pady=(0, PAD_ROW))

        self.err_lbl = tk.Label(self.card, text="", fg=T.danger, bg=T.card,
                                font=(FONT_MONO, 9, "bold"), wraplength=380, justify="left")
        self.err_lbl.pack(fill="x", pady=(0, PAD_ROW))

        GoldButton(self.card, "✦  INITIALIZE SECURE VAULT",
                   command=self._do_setup, variant="primary").pack(fill="x")
        self.pw2.entry.bind("<Return>", lambda _: self._do_setup())

    def _do_setup(self):
        pw   = self.pw1.get()
        pw2  = self.pw2.get()
        errs = validate_master_password(pw, pw2)
        if errs:
            self.err_lbl.config(text=errs[0]); return

        if self._legacy:
            bak = DB_LEGACY + ".bak"
            try:
                if os.path.exists(bak):
                    os.remove(bak)
                os.rename(DB_LEGACY, bak)
                log.info("Legacy XML vault backed up to %s", bak)
            except OSError as exc:
                log.warning("Could not rename legacy vault: %s", exc)

        try:
            initialize_vault(pw)
            self.err_lbl.config(text="Vault created! Opening…", fg=T.success)
            self.win.after(800, self._succeed)
        except OSError as exc:
            log.error("Vault initialization I/O error: %s", exc)
            self.err_lbl.config(text=f"I/O error: {exc}")
        except Exception as exc:
            log.error("Vault initialization failed: %s", type(exc).__name__)
            self.err_lbl.config(text="Setup failed — see vault.log.")

    def _build_unlock(self, relock_msg: str = ""):
        tk.Label(self.card, text="UNLOCK SECURE VAULT", fg=T.accent2,
                 bg=T.card, font=FONT_HEADING_SM, anchor="w").pack(fill="x", pady=(0, 4))

        sub_text = relock_msg or "Enter your master password to decrypt and open the vault."
        tk.Label(self.card, text=sub_text, fg=T.warning if relock_msg else T.text_muted,
                 bg=T.card, font=(FONT_MONO, 8), justify="left", anchor="w"
                 ).pack(fill="x", pady=(0, 18))

        self.pw1 = StyledEntry(self.card, label="Master Password",
                               placeholder="Enter your password", show="●")
        self.pw1.pack(fill="x", pady=(0, 20))

        self.err_lbl = tk.Label(self.card, text="", fg=T.danger, bg=T.card,
                                font=(FONT_MONO, 9, "bold"), wraplength=380, justify="left")
        self.err_lbl.pack(fill="x", pady=(0, 12))

        GoldButton(self.card, "🔓  DECRYPT & UNLOCK",
                   command=self._do_unlock, variant="violet").pack(fill="x")
        self.pw1.entry.bind("<Return>", lambda _: self._do_unlock())

    def _do_unlock(self):
        now = time.time()
        if now < self._locked_until:
            remaining = int(self._locked_until - now)
            self.err_lbl.config(
                text=f"Too many failures — wait {remaining}s.", fg=T.warning); return

        pw = self.pw1.get()
        if not pw:
            self.err_lbl.config(text="Password cannot be empty."); return

        self.err_lbl.config(text="Decrypting…", fg=T.text_muted)
        self.win.update_idletasks()

        try:
            unlock_vault(pw)
            self._fail_count = 0
            self.err_lbl.config(text="Access Granted! Loading…", fg=T.success)
            self.win.after(500, self._succeed)
        except InvalidTag:
            self._fail_count += 1
            log.warning("Failed unlock attempt #%d.", self._fail_count)
            if self._fail_count >= LOCKOUT_AFTER_FAILS:
                self._locked_until = time.time() + LOCKOUT_DURATION_SEC
                log.warning("Lockout triggered after %d failures.", self._fail_count)
                self.err_lbl.config(
                    text=f"Too many failures — locked for {LOCKOUT_DURATION_SEC}s.",
                    fg=T.danger)
            else:
                delay = 2 ** (self._fail_count - 1)
                self.err_lbl.config(
                    text=f"Wrong password — wait {delay}s before retrying.",
                    fg=T.danger)
                self.win.after(delay * 1000, lambda: self.err_lbl.config(text=""))
            self.pw1.clear()
        except (OSError, ValueError) as exc:
            log.error("Unlock error: %s", type(exc).__name__)
            self.err_lbl.config(text="Vault file error — see vault.log.")
        except Exception as exc:
            log.error("Unexpected unlock error: %s", type(exc).__name__)
            self.err_lbl.config(text="Unexpected error — see vault.log.")

    def _succeed(self):
        self.win.grab_release()
        self.win.destroy()
        self.on_success()

    def _on_close(self):
        self.win.destroy()
        self.root.destroy()


class ReAuthModal:
    """Modal asking for master password before revealing, copying, or editing."""
    def __init__(self, root: tk.Tk, label_hint: str, plaintext_to_reveal: str | None,
                 on_success, on_cancel=None, clipboard_callback=None, title="Re-authenticate"):
        self.root          = root
        self._label_hint   = label_hint
        self._secret       = plaintext_to_reveal
        self.on_success    = on_success
        self.on_cancel     = on_cancel
        self._clipboard_cb = clipboard_callback
        self._fail_count   = 0
        self._locked_until = 0.0

        self.win = tk.Toplevel(root)
        self.win.title(title)
        self.win.configure(bg=T.bg)
        self.win.resizable(False, False)
        self.win.update_idletasks()
        sw, sh = self.win.winfo_screenwidth(), self.win.winfo_screenheight()
        self.win.geometry(f"420x330+{(sw-420)//2}+{(sh-330)//2}")
        self.win.protocol("WM_DELETE_WINDOW", self._cancel)
        self.win.grab_set()
        self._build()

    def _build(self):
        outer = tk.Frame(self.win, bg=T.bg, padx=PAD_OUTER, pady=PAD_OUTER)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="🔒  CONFIRM IDENTITY", fg=T.accent2, bg=T.bg,
                 font=FONT_HEADING).pack(anchor="w", pady=(0, 6))
        tk.Frame(outer, bg=T.accent, height=HEIGHT_SEP).pack(fill="x", pady=(0, 10))

        if self._label_hint:
            tk.Label(outer, text=f"Target: {self._label_hint}", fg=T.accent, bg=T.bg,
                     font=(FONT_MONO, 8)).pack(anchor="w", pady=(0, 6))

        tk.Label(outer, text="Enter your master password to authenticate this action.",
                 fg=T.text_muted, bg=T.bg, font=(FONT_MONO, 9),
                 justify="left").pack(anchor="w", pady=(0, 10))

        self.pw = StyledEntry(outer, label="Master Password",
                              placeholder="Master password", show="●")
        self.pw.pack(fill="x", pady=(0, PAD_ROW))

        self.err_lbl = tk.Label(outer, text="", fg=T.danger, bg=T.bg,
                                font=(FONT_MONO, 9, "bold"), wraplength=360)
        self.err_lbl.pack(fill="x", pady=(0, PAD_ROW))

        self._copy_row = tk.Frame(outer, bg=T.bg)
        self._copy_row.pack(fill="x", pady=(0, PAD_ROW))
        if self._clipboard_cb and self._secret is not None:
            self._copy_btn = GoldButton(self._copy_row, "📋  COPY PASSWORD", variant="ghost",
                                        command=self._do_copy)

        btn_row = tk.Frame(outer, bg=T.bg)
        btn_row.pack(fill="x")
        GoldButton(btn_row, "CONFIRM", command=self._verify, variant="primary"
                   ).pack(side="left", expand=True, fill="x", padx=(0, 6))
        GoldButton(btn_row, "CANCEL",  command=self._cancel, variant="ghost"
                   ).pack(side="left", expand=True, fill="x")
        self.pw.entry.bind("<Return>", lambda _: self._verify())

    def _verify(self):
        now = time.time()
        if now < self._locked_until:
            remaining = int(self._locked_until - now)
            self.err_lbl.config(text=f"Wait {remaining}s."); return

        pw = self.pw.get()
        if not pw:
            self.err_lbl.config(text="Password required."); return

        try:
            test_key = _derive_key(pw, _session_salt)
            if test_key != _session_key:
                raise ValueError("key mismatch")
            self._fail_count = 0
            if hasattr(self, "_copy_btn"):
                self._copy_btn.pack(side="left")
            log.info("Re-authentication succeeded (hint: '%s').", self._label_hint)
            self.on_success(self._secret)
            # If not a reveal dialog with copy, close immediately
            if not self._clipboard_cb or self._secret is None:
                self.win.grab_release()
                self.win.destroy()
        except (ValueError, TypeError):
            self._fail_count += 1
            log.warning("Re-auth failed attempt #%d (hint: '%s').",
                        self._fail_count, self._label_hint)
            if self._fail_count >= LOCKOUT_AFTER_FAILS:
                self._locked_until = time.time() + LOCKOUT_DURATION_SEC
                log.warning("Re-auth lockout triggered.")
                self.err_lbl.config(text=f"Locked {LOCKOUT_DURATION_SEC}s.", fg=T.danger)
            else:
                delay = 2 ** (self._fail_count - 1)
                self.err_lbl.config(text=f"Wrong password — wait {delay}s.", fg=T.danger)
                self.win.after(delay * 1000, lambda: self.err_lbl.config(text=""))
            self.pw.clear()
        except Exception as exc:
            log.error("Re-auth unexpected error: %s", type(exc).__name__)
            self.err_lbl.config(text="Unexpected error — see vault.log.")

    def _do_copy(self):
        if self._clipboard_cb and self._secret is not None:
            self._clipboard_cb(self._secret)
        self.win.grab_release()
        self.win.destroy()

    def _cancel(self):
        self.win.grab_release()
        self.win.destroy()
        if self.on_cancel:
            self.on_cancel()

    def force_close(self):
        try:
            self.win.grab_release()
            self.win.destroy()
        except tk.TclError:
            pass


class EditEntryModal:
    """Modal to edit an existing credential (Item 18)."""
    def __init__(self, root: tk.Tk, entry_idx: int, entry: dict, on_saved_cb, toast: Toast):
        self.root        = root
        self.entry_idx   = entry_idx
        self.entry       = entry
        self.on_saved_cb = on_saved_cb
        self.toast       = toast

        self.win = tk.Toplevel(root)
        self.win.title("Edit Credential")
        self.win.configure(bg=T.bg)
        self.win.resizable(False, False)
        self.win.update_idletasks()
        sw, sh = self.win.winfo_screenwidth(), self.win.winfo_screenheight()
        self.win.geometry(f"520x460+{(sw-520)//2}+{(sh-460)//2}")
        self.win.grab_set()
        self._build()

    def _build(self):
        outer = tk.Frame(self.win, bg=T.bg, padx=PAD_OUTER, pady=PAD_OUTER)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="✎  EDIT CREDENTIAL", fg=T.accent, bg=T.bg,
                 font=FONT_HEADING).pack(anchor="w", pady=(0, 4))
        tk.Frame(outer, bg=T.accent, height=HEIGHT_SEP).pack(fill="x", pady=(0, 14))

        self.edit_label = StyledEntry(outer, label="Label / Site *", placeholder="e.g. GitHub")
        self.edit_label.pack(fill="x", pady=(0, 10))
        self.edit_label.set_text(self.entry.get("label", ""))

        self.edit_user = StyledEntry(outer, label="Username *", placeholder="Username / Email")
        self.edit_user.pack(fill="x", pady=(0, 10))
        self.edit_user.set_text(self.entry.get("username", ""))

        self.edit_pass = StyledEntry(outer, label="Password *", placeholder="Password", show="●")
        self.edit_pass.pack(fill="x", pady=(0, 8))
        self.edit_pass.set_text(self.entry.get("password", ""))

        # Generator & Mask toggle bar
        opt_bar = tk.Frame(outer, bg=T.bg)
        opt_bar.pack(fill="x", pady=(0, 12))
        GoldButton(opt_bar, "🎲  GENERATE NEW PASSWORD", variant="ghost",
                   command=self._generate_into_field).pack(side="left")
        self._show_state = False
        self._toggle_btn = GoldButton(opt_bar, "👁  SHOW", variant="ghost", command=self._toggle_show)
        self._toggle_btn.pack(side="right")

        self.err_lbl = tk.Label(outer, text="", fg=T.danger, bg=T.bg,
                                font=(FONT_MONO, 9, "bold"), wraplength=460)
        self.err_lbl.pack(fill="x", pady=(0, 10))

        btn_row = tk.Frame(outer, bg=T.bg)
        btn_row.pack(fill="x")
        GoldButton(btn_row, "SAVE CHANGES", command=self._save, variant="primary"
                   ).pack(side="left", expand=True, fill="x", padx=(0, 6))
        GoldButton(btn_row, "CANCEL", command=self._close, variant="ghost"
                   ).pack(side="left", expand=True, fill="x")

    def _generate_into_field(self):
        new_pw = generate_password(DEFAULT_GEN_PW_LEN)
        self.edit_pass.set_text(new_pw)
        self.toast.show(f"Generated secure {DEFAULT_GEN_PW_LEN}-char password.", "info")

    def _toggle_show(self):
        self._show_state = not self._show_state
        if self._show_state:
            self.edit_pass.entry.config(show="")
            self._toggle_btn.btn.config(text="🔒  HIDE")
        else:
            self.edit_pass.entry.config(show="●")
            self._toggle_btn.btn.config(text="👁  SHOW")

    def _save(self):
        label = _strip_control(self.edit_label.get()).strip()
        user  = _strip_control(self.edit_user.get()).strip()
        pw    = self.edit_pass.get()

        errs = validate_entry(label, user, pw)
        if errs:
            self.err_lbl.config(text=errs[0]); return

        try:
            edit_vault_entry(self.entry_idx, label, user, pw)
            self.toast.show(f"Updated credential for '{user}'.", "success")
            self.on_saved_cb()
            self._close()
        except Exception as exc:
            log.error("Failed to edit entry: %s", type(exc).__name__)
            self.err_lbl.config(text="Save failed — see vault.log.")

    def _close(self):
        self.win.grab_release()
        self.win.destroy()


class ChangeMasterPasswordModal:
    """Modal to re-encrypt the entire vault with a new master password (Item 22)."""
    def __init__(self, root: tk.Tk, toast: Toast):
        self.root  = root
        self.toast = toast

        self.win = tk.Toplevel(root)
        self.win.title("Change Master Password")
        self.win.configure(bg=T.bg)
        self.win.resizable(False, False)
        self.win.update_idletasks()
        sw, sh = self.win.winfo_screenwidth(), self.win.winfo_screenheight()
        self.win.geometry(f"480x420+{(sw-480)//2}+{(sh-420)//2}")
        self.win.grab_set()
        self._build()

    def _build(self):
        outer = tk.Frame(self.win, bg=T.bg, padx=PAD_OUTER, pady=PAD_OUTER)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="🔑  CHANGE MASTER PASSWORD", fg=T.accent, bg=T.bg,
                 font=FONT_HEADING).pack(anchor="w", pady=(0, 4))
        tk.Frame(outer, bg=T.accent, height=HEIGHT_SEP).pack(fill="x", pady=(0, 14))

        self.cur_pw = StyledEntry(outer, label="Current Master Password", placeholder="Current password", show="●")
        self.cur_pw.pack(fill="x", pady=(0, 10))

        self.new_pw1 = StyledEntry(outer, label="New Master Password",
                                   placeholder=f"Min {MIN_MASTER_PW_LEN} chars", show="●")
        self.new_pw1.pack(fill="x", pady=(0, 10))

        self.new_pw2 = StyledEntry(outer, label="Confirm New Master Password",
                                   placeholder="Repeat new password", show="●")
        self.new_pw2.pack(fill="x", pady=(0, 10))

        self.err_lbl = tk.Label(outer, text="", fg=T.danger, bg=T.bg,
                                font=(FONT_MONO, 9, "bold"), wraplength=440)
        self.err_lbl.pack(fill="x", pady=(0, 10))

        btn_row = tk.Frame(outer, bg=T.bg)
        btn_row.pack(fill="x")
        GoldButton(btn_row, "UPDATE PASSWORD", command=self._do_change, variant="primary"
                   ).pack(side="left", expand=True, fill="x", padx=(0, 6))
        GoldButton(btn_row, "CANCEL", command=self._close, variant="ghost"
                   ).pack(side="left", expand=True, fill="x")

    def _do_change(self):
        cur  = self.cur_pw.get()
        new1 = self.new_pw1.get()
        new2 = self.new_pw2.get()

        if not cur:
            self.err_lbl.config(text="Current password is required."); return

        errs = validate_master_password(new1, new2)
        if errs:
            self.err_lbl.config(text=errs[0]); return

        try:
            change_master_password(cur, new1)
            self.toast.show("Master password updated & vault re-encrypted!", "success")
            self._close()
        except ValueError as exc:
            self.err_lbl.config(text=str(exc))
        except Exception as exc:
            log.error("Failed to change master password: %s", type(exc).__name__)
            self.err_lbl.config(text="Update failed — see vault.log.")

    def _close(self):
        self.win.grab_release()
        self.win.destroy()


class ImportBackupModal:
    """Modal to decrypt and import an encrypted .vlt backup (Item 23)."""
    def __init__(self, root: tk.Tk, filepath: str, toast: Toast, on_success_cb):
        self.root          = root
        self.filepath      = filepath
        self.toast         = toast
        self.on_success_cb = on_success_cb

        self.win = tk.Toplevel(root)
        self.win.title("Import Encrypted Backup")
        self.win.configure(bg=T.bg)
        self.win.resizable(False, False)
        self.win.update_idletasks()
        sw, sh = self.win.winfo_screenwidth(), self.win.winfo_screenheight()
        self.win.geometry(f"500x380+{(sw-500)//2}+{(sh-380)//2}")
        self.win.grab_set()
        self._build()

    def _build(self):
        outer = tk.Frame(self.win, bg=T.bg, padx=PAD_OUTER, pady=PAD_OUTER)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="⬇  IMPORT BACKUP FILE", fg=T.accent2, bg=T.bg,
                 font=FONT_HEADING).pack(anchor="w", pady=(0, 4))
        tk.Frame(outer, bg=T.accent, height=HEIGHT_SEP).pack(fill="x", pady=(0, 10))

        short_path = os.path.basename(self.filepath)
        tk.Label(outer, text=f"File: {short_path}", fg=T.accent, bg=T.bg,
                 font=(FONT_MONO, 8)).pack(anchor="w", pady=(0, 8))

        self.bpw = StyledEntry(outer, label="Backup Master Password",
                               placeholder="Password for this backup", show="●")
        self.bpw.pack(fill="x", pady=(0, 10))

        self.mode_var = tk.StringVar(value="merge")
        opt_frame = tk.Frame(outer, bg=T.card, padx=12, pady=10,
                             highlightbackground=T.border, highlightthickness=1)
        opt_frame.pack(fill="x", pady=(0, 12))

        rb1 = tk.Radiobutton(opt_frame, text="Merge with existing entries (keep existing)",
                             variable=self.mode_var, value="merge",
                             bg=T.card, fg=T.text, selectcolor=T.bg,
                             activebackground=T.card, activeforeground=T.accent,
                             font=(FONT_MONO, 8))
        rb1.pack(anchor="w")

        rb2 = tk.Radiobutton(opt_frame, text="Replace current vault completely",
                             variable=self.mode_var, value="replace",
                             bg=T.card, fg=T.danger, selectcolor=T.bg,
                             activebackground=T.card, activeforeground=T.danger,
                             font=(FONT_MONO, 8))
        rb2.pack(anchor="w", pady=(4, 0))

        self.err_lbl = tk.Label(outer, text="", fg=T.danger, bg=T.bg,
                                font=(FONT_MONO, 9, "bold"), wraplength=460)
        self.err_lbl.pack(fill="x", pady=(0, 10))

        btn_row = tk.Frame(outer, bg=T.bg)
        btn_row.pack(fill="x")
        GoldButton(btn_row, "DECRYPT & IMPORT", command=self._do_import, variant="primary"
                   ).pack(side="left", expand=True, fill="x", padx=(0, 6))
        GoldButton(btn_row, "CANCEL", command=self._close, variant="ghost"
                   ).pack(side="left", expand=True, fill="x")

    def _do_import(self):
        pw = self.bpw.get()
        if not pw:
            self.err_lbl.config(text="Backup password is required."); return

        try:
            with open(self.filepath, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            if len(lines) < 2 or not lines[1].strip():
                raise ValueError("Empty or invalid backup file format.")

            hdr  = json.loads(lines[0])
            salt = bytes.fromhex(hdr["salt"])
            key  = _derive_key(pw, salt)
            blob = lines[1].strip()

            plaintext   = _aes_decrypt(blob, key)
            new_entries = json.loads(plaintext.decode("utf-8"))

            curr_entries = load_vault()
            if self.mode_var.get() == "replace":
                merged = new_entries
            else:
                # Merge: avoid identical duplicates (same label, username, password)
                merged = list(curr_entries)
                existing_keys = {(e.get("label"), e.get("username"), e.get("password")) for e in curr_entries}
                for ne in new_entries:
                    k = (ne.get("label"), ne.get("username"), ne.get("password"))
                    if k not in existing_keys:
                        merged.append(ne)

            save_vault(merged)
            log.info("Vault imported from %s (%d total entries, mode: %s).",
                     self.filepath, len(merged), self.mode_var.get())
            self.toast.show(f"Imported successfully — {len(merged)} total credentials.", "success")
            self.on_success_cb()
            self._close()
        except InvalidTag:
            self.err_lbl.config(text="Incorrect password or corrupted backup.")
        except Exception as exc:
            log.error("Import backup error: %s", type(exc).__name__)
            self.err_lbl.config(text=f"Import failed: {str(exc)}")

    def _close(self):
        self.win.grab_release()
        self.win.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class VaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VAULT — AES-256-GCM Encrypted Password Manager")
        self.root.geometry("1020x740")
        self.root.minsize(920, 640)
        self.root.configure(bg=T.bg)
        self.root.resizable(True, True)

        self.toast = Toast(self.root)

        self._clock_job:        int | None = None
        self._autolock_job:     int | None = None
        self._clipboard_job:    int | None = None
        self._reveal_hide_jobs: list[int]  = []

        self._clipboard_value: str | None = None
        self._open_modal       = None
        self._main_outer: tk.Frame | None = None

        # Style ttk widgets
        self._init_ttk_styles()

        log.info("VAULT application started.")
        self.root.withdraw()
        MasterPasswordGate(self.root, self._on_unlock)

    def _init_ttk_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # Treeview styling (Item 20)
        style.configure(
            "Vault.Treeview",
            background=T.card,
            foreground=T.text,
            fieldbackground=T.card,
            bordercolor=T.border,
            darkcolor=T.border,
            lightcolor=T.border,
            rowheight=32,
            font=FONT_BODY,
        )
        style.map(
            "Vault.Treeview",
            background=[("selected", T.hover)],
            foreground=[("selected", T.accent)],
        )
        style.configure(
            "Vault.Treeview.Heading",
            background=T.tag_bg,
            foreground=T.text_muted,
            font=FONT_LABEL_MED,
            relief="flat",
            padding=6,
        )
        style.map(
            "Vault.Treeview.Heading",
            background=[("active", T.surface)],
            foreground=[("active", T.accent)],
        )

    # ── Unlock / Lock ─────────────────────────────────────────────────────────
    def _on_unlock(self):
        self.root.deiconify()
        self._build_ui()
        self._refresh_vault_list()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._bind_activity()
        self._reset_autolock_timer()
        self.root.bind("<Unmap>", self._on_minimise)
        log.info("Vault UI loaded.")

    def _on_minimise(self, event):
        if event.widget is self.root:
            log.info("Window minimised — triggering auto-lock.")
            self._do_lock()

    def _do_lock(self):
        self._cancel_job("_clock_job")
        self._cancel_job("_autolock_job")
        self._cancel_job("_clipboard_job")
        for jid in self._reveal_hide_jobs:
            try: self.root.after_cancel(jid)
            except tk.TclError: pass
        self._reveal_hide_jobs.clear()

        self._clear_clipboard_if_ours()

        if self._open_modal and hasattr(self._open_modal, "force_close"):
            try: self._open_modal.force_close()
            except Exception: pass
        self._open_modal = None

        if self._main_outer:
            try: self._main_outer.destroy()
            except tk.TclError: pass
            self._main_outer = None

        lock_vault()

        log.info("Auto-lock complete — presenting lock screen.")
        self.root.withdraw()
        MasterPasswordGate(self.root, self._on_unlock, is_relock=True)

    def _bind_activity(self):
        for event in ("<KeyPress>", "<ButtonPress>", "<Motion>"):
            self.root.bind(event, self._on_activity, add="+")

    def _on_activity(self, _=None):
        self._reset_autolock_timer()

    def _reset_autolock_timer(self):
        self._cancel_job("_autolock_job")
        self._autolock_job = self.root.after(AUTO_LOCK_MS, self._trigger_autolock)

    def _trigger_autolock(self):
        self._autolock_job = None
        log.info("Inactivity timeout (%d min) — locking vault.", AUTO_LOCK_MINUTES)
        self._do_lock()

    # ── Clipboard ─────────────────────────────────────────────────────────────
    def _copy_to_clipboard(self, text: str):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except tk.TclError as exc:
            log.error("Clipboard copy failed: %s", exc)
            self.toast.show("Clipboard unavailable.", "error")
            return

        self._clipboard_value = text
        self._cancel_job("_clipboard_job")
        self._clipboard_job   = self.root.after(
            CLIPBOARD_CLEAR_SECONDS * 1000,
            self._auto_clear_clipboard,
        )
        log.info("Value copied to clipboard — will auto-clear in %ds.", CLIPBOARD_CLEAR_SECONDS)
        self.toast.show(f"Copied — clears in {CLIPBOARD_CLEAR_SECONDS}s.", "info")

    def _auto_clear_clipboard(self):
        self._clipboard_job = None
        self._clear_clipboard_if_ours()

    def _clear_clipboard_if_ours(self):
        if self._clipboard_value is None:
            return
        try:
            current = self.root.clipboard_get()
        except tk.TclError:
            current = ""
        if current == self._clipboard_value:
            try:
                self.root.clipboard_clear()
                log.info("Clipboard cleared.")
            except tk.TclError as exc:
                log.warning("Clipboard clear failed: %s", exc)
        else:
            log.info("Clipboard not cleared — contents changed since copy.")
        self._clipboard_value = None

    # ── Shutdown ──────────────────────────────────────────────────────────────
    def _on_close(self):
        log.info("VAULT application closing.")
        for attr in ("_clock_job", "_autolock_job", "_clipboard_job"):
            self._cancel_job(attr)
        for jid in self._reveal_hide_jobs:
            try: self.root.after_cancel(jid)
            except tk.TclError: pass
        self._reveal_hide_jobs.clear()
        self.toast.destroy()
        self._clear_clipboard_if_ours()
        lock_vault()
        for h in log.handlers:
            try: h.flush()
            except Exception: pass
        self.root.destroy()

    def _cancel_job(self, attr: str):
        jid = getattr(self, attr, None)
        if jid is not None:
            try:
                self.root.after_cancel(jid)
            except tk.TclError:
                pass
            setattr(self, attr, None)

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self, parent: tk.Frame):
        hdr = tk.Frame(parent, bg=T.bg)
        hdr.pack(fill="x", pady=(0, 2))

        logo = tk.Frame(hdr, bg=T.bg)
        logo.pack(side="left")
        tk.Label(logo, text="◈", fg=T.accent, bg=T.bg, font=FONT_ICON_LG).pack(side="left", padx=(0, 8))
        tk.Label(logo, text="VAULT", fg=T.text, bg=T.bg, font=FONT_LOGO).pack(side="left")
        tk.Label(logo, text=" AES-256 SECURE STORE", fg=T.text_muted, bg=T.bg,
                 font=(FONT_MONO, 9)).pack(side="left", padx=(6, 0), pady=(8, 0))

        # Header utility buttons
        tools_row = tk.Frame(hdr, bg=T.bg)
        tools_row.pack(side="right", padx=(8, 0))

        GoldButton(tools_row, "🔑  KEY", variant="ghost",
                   command=self._open_change_pw_modal).pack(side="left", padx=2)
        GoldButton(tools_row, "⬆  EXPORT", variant="ghost",
                   command=self._export_backup).pack(side="left", padx=2)
        GoldButton(tools_row, "⬇  IMPORT", variant="ghost",
                   command=self._import_backup).pack(side="left", padx=2)

        self.clock_lbl = tk.Label(hdr, fg=T.text_dim, bg=T.bg, font=(FONT_MONO, 9))
        self.clock_lbl.pack(side="right", padx=6)
        self._tick_clock()

        tk.Label(hdr, text=f"🔒 {AUTO_LOCK_MINUTES}m", fg=T.text_dim, bg=T.bg,
                 font=(FONT_MONO, 8)).pack(side="right", padx=4)

        tk.Frame(parent, bg=T.accent,  height=HEIGHT_SEP).pack(fill="x", pady=(4, 0))
        tk.Frame(parent, bg=T.bg,      height=HEIGHT_SEP).pack(fill="x")
        tk.Frame(parent, bg=T.border,  height=HEIGHT_SEP).pack(fill="x")

    def _tick_clock(self):
        self.clock_lbl.config(text=datetime.now().strftime("⏱  %H:%M:%S"))
        self._clock_job = self.root.after(CLOCK_INTERVAL_MS, self._tick_clock)

    # ── Main UI ───────────────────────────────────────────────────────────────
    def _build_ui(self):
        if self._main_outer:
            try: self._main_outer.destroy()
            except tk.TclError: pass

        outer = tk.Frame(self.root, bg=T.bg, padx=PAD_OUTER, pady=PAD_SECTION)
        outer.pack(fill="both", expand=True)
        self._main_outer = outer

        self._build_header(outer)

        tab_row = tk.Frame(outer, bg=T.bg)
        tab_row.pack(fill="x", pady=(12, 0))

        self.tabs        = {}
        self.tab_frames  = {}
        self.active_tab  = "add"

        for name, icon in [("add", "⊕  ADD ENTRY"), ("retrieve", "⌕  RETRIEVE"), ("vault", "▤  VAULT")]:
            btn = tk.Label(tab_row, text=icon,
                           fg=T.accent if name == "add" else T.text_muted,
                           bg=T.card   if name == "add" else T.bg,
                           font=FONT_LABEL_LG, padx=18, pady=8, cursor="hand2",
                           highlightbackground=T.accent if name == "add" else T.border,
                           highlightthickness=1)
            btn.pack(side="left", padx=(0, 4))
            btn.bind("<Button-1>", lambda e, n=name: self._switch_tab(n))
            self.tabs[name] = btn

        content = tk.Frame(outer, bg=T.bg)
        content.pack(fill="both", expand=True)

        self.tab_frames["add"]      = self._build_add_tab(content)
        self.tab_frames["retrieve"] = self._build_retrieve_tab(content)
        self.tab_frames["vault"]    = self._build_vault_tab(content)

        self._switch_tab("add")

    def _switch_tab(self, name: str):
        for n, f in self.tab_frames.items():
            f.pack_forget()
        self.tab_frames[name].pack(fill="both", expand=True)
        self.active_tab = name
        for n, btn in self.tabs.items():
            active = (n == name)
            btn.config(fg=T.accent if active else T.text_muted,
                       bg=T.card   if active else T.bg,
                       highlightbackground=T.accent if active else T.border)
        if name == "vault":
            self._refresh_vault_list()

    # ── TAB: ADD ENTRY (Item 21: Generator & Strength) ────────────────────────
    def _build_add_tab(self, parent: tk.Frame) -> tk.Frame:
        frame = tk.Frame(parent, bg=T.bg)
        card  = _build_card(frame, "ADD NEW CREDENTIAL", T.accent,
                            subtitle="AES-256-GCM · Argon2id")

        form = tk.Frame(card, bg=T.card, padx=PAD_CARD, pady=PAD_CARD_Y)
        form.pack(fill="both", expand=True)
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        self.add_user  = StyledEntry(form, label="Username *",
                                     placeholder=f"Required, max {MAX_USERNAME_LEN} chars")
        self.add_user.grid(row=0, column=0, sticky="ew", padx=(0, 12), pady=(0, PAD_SECTION))

        self.add_label = StyledEntry(form, label="Label / Site *",
                                     placeholder=f"Required, max {MAX_LABEL_LEN} chars")
        self.add_label.grid(row=0, column=1, sticky="ew", pady=(0, PAD_SECTION))

        self.add_pass  = StyledEntry(form, label="Password *",
                                     placeholder=f"Min {MIN_ENTRY_PW_LEN} chars", show="●")
        self.add_pass.grid(row=1, column=0, sticky="ew", padx=(0, 12), pady=(0, 8))

        self.add_pass2 = StyledEntry(form, label="Confirm Password *",
                                     placeholder="Repeat password", show="●")
        self.add_pass2.grid(row=1, column=1, sticky="ew", pady=(0, 8))

        # Generator & Option bar (Item 21)
        gen_bar = tk.Frame(form, bg=T.card)
        gen_bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        GoldButton(gen_bar, "🎲  GENERATE RANDOM PASSWORD", variant="ghost",
                   command=self._generate_add_password).pack(side="left")

        # Strength meter
        sf = tk.Frame(form, bg=T.input_bg,
                      highlightbackground=T.border, highlightthickness=1)
        sf.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SECTION))
        sf_in = tk.Frame(sf, bg=T.input_bg, padx=14, pady=PAD_ROW)
        sf_in.pack(fill="x")
        tk.Label(sf_in, text="PASSWORD STRENGTH", fg=T.text_dim, bg=T.input_bg,
                 font=FONT_LABEL_SM).pack(anchor="w")
        self.strength_lbl = tk.Label(sf_in, text="Type a password…",
                                     fg=T.text_dim, bg=T.input_bg,
                                     font=FONT_INPUT, anchor="w")
        self.strength_lbl.pack(fill="x")
        self.add_pass.entry.bind("<KeyRelease>", self._update_strength)

        btn_row = tk.Frame(form, bg=T.card)
        btn_row.grid(row=4, column=0, columnspan=2, sticky="ew")
        btn_row.columnconfigure(0, weight=1)
        GoldButton(btn_row, "⊕  STORE CREDENTIAL", command=self._do_add,
                   variant="primary").grid(row=0, column=1, padx=(0, 10))
        GoldButton(btn_row, "↺  CLEAR", command=self._clear_add,
                   variant="ghost").grid(row=0, column=2)

        return frame

    def _generate_add_password(self):
        new_pw = generate_password(DEFAULT_GEN_PW_LEN)
        self.add_pass.set_text(new_pw)
        self.add_pass2.set_text(new_pw)
        self._update_strength()
        self.toast.show(f"Generated secure {DEFAULT_GEN_PW_LEN}-char password.", "info")

    def _update_strength(self, _=None):
        pw = self.add_pass.get()
        if not pw:
            self.strength_lbl.config(text="Type a password…", fg=T.text_dim); return
        label, color = _pw_strength(pw)
        self.strength_lbl.config(
            text=f"Length: {len(pw)} chars  │  Strength: {label}", fg=color)

    def _do_add(self):
        raw_user    = self.add_user.get()
        pw          = self.add_pass.get()
        pw2         = self.add_pass2.get()
        raw_label   = self.add_label.get()

        clean_label = _strip_control(raw_label).strip()
        clean_user  = _strip_control(raw_user).strip()

        if pw != pw2:
            self.toast.show("Passwords do not match.", "warning"); return

        errs = validate_entry(clean_label, clean_user, pw)
        if errs:
            self.toast.show(errs[0], "error"); return

        try:
            add_vault_entry(clean_label, clean_user, pw)
            self.toast.show(f"Credential stored for '{clean_user}'.", "success")
            self._clear_add()
            self._refresh_vault_list()
        except (OSError, RuntimeError) as exc:
            log.error("Failed to add entry: %s", type(exc).__name__)
            self.toast.show("Save failed — see vault.log.", "error")
        except Exception as exc:
            log.error("Unexpected error adding entry: %s", type(exc).__name__)
            self.toast.show("Unexpected error — see vault.log.", "error")

    def _clear_add(self):
        for w in [self.add_user, self.add_pass, self.add_pass2, self.add_label]:
            w.clear()
        self.strength_lbl.config(text="Type a password…", fg=T.text_dim)

    # ── TAB: RETRIEVE ─────────────────────────────────────────────────────────
    def _build_retrieve_tab(self, parent: tk.Frame) -> tk.Frame:
        frame = tk.Frame(parent, bg=T.bg)
        card  = _build_card(frame, "RETRIEVE PASSWORD", T.accent2,
                            subtitle="Passwords always masked — Reveal requires re-auth")

        form = tk.Frame(card, bg=T.card, padx=PAD_CARD, pady=PAD_CARD_Y)
        form.pack(fill="x")
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        self.ret_user  = StyledEntry(form, label="Username (optional)", placeholder="Filter by username")
        self.ret_user.grid(row=0, column=0, sticky="ew", padx=(0, 12), pady=(0, PAD_SECTION))

        self.ret_label = StyledEntry(form, label="Label / Site (optional)", placeholder="Filter by label/site")
        self.ret_label.grid(row=0, column=1, sticky="ew", pady=(0, PAD_SECTION))

        btn_row = tk.Frame(form, bg=T.card)
        btn_row.grid(row=1, column=0, columnspan=2, sticky="ew")
        btn_row.columnconfigure(0, weight=1)
        GoldButton(btn_row, "⌕  SEARCH VAULT", command=self._do_retrieve,
                   variant="violet").grid(row=0, column=1, padx=(0, 10))
        GoldButton(btn_row, "↺  CLEAR", command=self._clear_retrieve,
                   variant="ghost").grid(row=0, column=2)

        self._ret_results_frame = tk.Frame(card, bg=T.card, padx=PAD_CARD)
        self._ret_results_frame.pack(fill="both", expand=True)

        tk.Label(
            self._ret_results_frame,
            text="◈  Enter a username or label above and click Search\n\nResults appear here with masked passwords",
            fg=T.text_dim, bg=T.card, font=FONT_INPUT, justify="center",
        ).place(relx=0.5, rely=0.5, anchor="center")

        return frame

    def _do_retrieve(self):
        u_filter = self.ret_user.get().strip().lower()
        l_filter = self.ret_label.get().strip().lower()

        try:
            entries = load_vault()
        except (InvalidTag, ValueError) as exc:
            log.error("Retrieve failed — vault decrypt error: %s", type(exc).__name__)
            self.toast.show("Vault decryption failed — wrong key?", "error"); return
        except OSError as exc:
            log.error("Retrieve failed — I/O error: %s", exc)
            self.toast.show("Could not read vault file.", "error"); return
        except RuntimeError as exc:
            log.error("Retrieve called while locked: %s", exc)
            self.toast.show("Vault is locked.", "error"); return

        results = [
            (idx, e) for idx, e in enumerate(entries)
            if (not u_filter or u_filter in e["username"].lower())
            and (not l_filter or l_filter in e["label"].lower())
        ]

        for w in self._ret_results_frame.winfo_children():
            w.destroy()

        if not results:
            tk.Label(self._ret_results_frame, text="✖  No matching credentials found.",
                     fg=T.danger, bg=T.card, font=FONT_HEADING).place(relx=0.5, rely=0.4, anchor="center")
            self.toast.show("No matching credentials.", "warning"); return

        hdr = tk.Frame(self._ret_results_frame, bg=T.tag_bg, padx=PAD_ROW, pady=6)
        hdr.pack(fill="x", pady=(4, 0))
        for col, w in [("#", 3), ("LABEL", 16), ("USERNAME", 18), ("PASSWORD", 20), ("CREATED", 20), ("", 10)]:
            tk.Label(hdr, text=col, fg=T.text_muted, bg=T.tag_bg,
                     font=FONT_LABEL_MED, width=w, anchor="w").pack(side="left", padx=4)

        canvas = tk.Canvas(self._ret_results_frame, bg=T.card, highlightthickness=0)
        sb     = tk.Scrollbar(self._ret_results_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body   = tk.Frame(canvas, bg=T.card)
        win_id = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>",   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win_id, width=e.width))

        for di, (vault_idx, e) in enumerate(results):
            row_bg = T.card if di % 2 == 0 else T.surface
            row    = tk.Frame(body, bg=row_bg, padx=PAD_ROW, pady=PAD_ROW)
            row.pack(fill="x")

            for text, w, color in [
                (f"  {di+1}", 3,  T.text_dim),
                (e["label"],  16, T.accent2),
                (e["username"], 18, T.accent),
                ("●●●●●●●●",  20, T.text_muted),
                (e["created"], 20, T.text_dim),
            ]:
                tk.Label(row, text=text[:w], fg=color, bg=row_bg,
                         font=FONT_BODY, width=w, anchor="w").pack(side="left", padx=4)

            mask_lbl = row.winfo_children()[3]
            GoldButton(row, "REVEAL", variant="violet",
                       command=lambda pw=e["password"], lbl=e["label"], ml=mask_lbl:
                           self._reveal(pw, lbl, ml)
                       ).pack(side="left", padx=4)

        self.toast.show(f"Found {len(results)} result(s).", "info")

    def _reveal(self, plaintext_password: str, label_hint: str, mask_lbl: tk.Label):
        def on_success(pw: str):
            mask_lbl.config(text=pw[:40], fg=T.success)
            jid = self.root.after(
                REVEAL_AUTO_HIDE_SEC * 1000,
                lambda: mask_lbl.config(text="●●●●●●●●", fg=T.text_muted),
            )
            self._reveal_hide_jobs.append(jid)
            self.toast.show(f"Revealed — hides in {REVEAL_AUTO_HIDE_SEC}s.", "info")

        modal = ReAuthModal(
            self.root,
            label_hint=label_hint,
            plaintext_to_reveal=plaintext_password,
            on_success=on_success,
            clipboard_callback=self._copy_to_clipboard,
        )
        self._open_modal = modal

    def _clear_retrieve(self):
        self.ret_user.clear()
        self.ret_label.clear()
        for w in self._ret_results_frame.winfo_children():
            w.destroy()
        tk.Label(
            self._ret_results_frame,
            text="◈  Enter a username or label above and click Search\n\nResults appear here with masked passwords",
            fg=T.text_dim, bg=T.card, font=FONT_INPUT, justify="center",
        ).place(relx=0.5, rely=0.5, anchor="center")

    # ── TAB: VAULT (Items 18, 19, 20: Treeview, Dynamic Filter & Edit) ────────
    def _build_vault_tab(self, parent: tk.Frame) -> tk.Frame:
        frame = tk.Frame(parent, bg=T.bg)
        card  = _build_card(frame, "VAULT CONTENTS", T.accent)

        # Top control bar: search/filter + count + action buttons
        ctl_bar = tk.Frame(card, bg=T.card, padx=PAD_CARD, pady=PAD_ROW)
        ctl_bar.pack(fill="x")

        # Dynamic search filter (Item 19)
        self.vault_filter_var = tk.StringVar()
        sf_frame = tk.Frame(ctl_bar, bg=T.input_bg, padx=8, pady=4,
                            highlightbackground=T.border, highlightthickness=1)
        sf_frame.pack(side="left", fill="x", expand=True, padx=(0, 10))

        tk.Label(sf_frame, text="⌕ ", fg=T.accent, bg=T.input_bg,
                 font=(FONT_MONO, 10, "bold")).pack(side="left")
        self.vault_search_entry = tk.Entry(
            sf_frame, textvariable=self.vault_filter_var, bg=T.input_bg, fg=T.text,
            insertbackground=T.accent, relief="flat", bd=0, font=FONT_BODY
        )
        self.vault_search_entry.pack(side="left", fill="x", expand=True)
        self.vault_filter_var.trace_add("write", lambda *args: self._filter_treeview())

        # Buttons in control bar
        GoldButton(ctl_bar, "👁  REVEAL", variant="violet",
                   command=self._reveal_selected_tree).pack(side="left", padx=2)
        GoldButton(ctl_bar, "✎  EDIT", variant="primary",
                   command=self._edit_selected_tree).pack(side="left", padx=2)
        GoldButton(ctl_bar, "✖  DELETE", variant="danger",
                   command=self._delete_selected_tree).pack(side="left", padx=2)
        GoldButton(ctl_bar, "⟳  REFRESH", variant="ghost",
                   command=self._refresh_vault_list).pack(side="left", padx=2)

        # Separator
        tk.Frame(card, bg=T.border, height=HEIGHT_SEP).pack(fill="x", pady=(4, 0))

        # Status / count row
        status_row = tk.Frame(card, bg=T.card, padx=PAD_CARD, pady=4)
        status_row.pack(fill="x")
        self.entry_count_lbl = tk.Label(status_row, text="", fg=T.text_muted,
                                        bg=T.card, font=(FONT_MONO, 8))
        self.entry_count_lbl.pack(side="left")

        # Treeview Container (Item 20)
        tree_container = tk.Frame(card, bg=T.card, padx=PAD_CARD, pady=(0, PAD_ROW))
        tree_container.pack(fill="both", expand=True)

        columns = ("idx", "label", "username", "password", "created")
        self.tree = ttk.Treeview(
            tree_container,
            columns=columns,
            show="headings",
            style="Vault.Treeview",
            selectmode="browse",
        )

        self.tree.heading("idx",      text="#")
        self.tree.heading("label",    text="LABEL / SITE")
        self.tree.heading("username", text="USERNAME")
        self.tree.heading("password", text="PASSWORD (MASKED)")
        self.tree.heading("created",  text="STORED ON")

        self.tree.column("idx",      width=45,  anchor="center", stretch=False)
        self.tree.column("label",    width=200, anchor="w")
        self.tree.column("username", width=220, anchor="w")
        self.tree.column("password", width=170, anchor="w")
        self.tree.column("created",  width=170, anchor="w")

        tree_scroll = tk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        # Double click row to reveal
        self.tree.bind("<Double-1>", lambda _: self._reveal_selected_tree())

        # Bottom path badge
        db_bar = tk.Frame(card, bg=T.input_bg, padx=PAD_CARD, pady=4)
        db_bar.pack(fill="x")
        tk.Label(db_bar, text=f"◈ Vault: {DB_FILE}", fg=T.text_dim,
                 bg=T.input_bg, font=(FONT_MONO, 8)).pack(side="left")

        return frame

    def _refresh_vault_list(self):
        try:
            self._cached_entries = load_vault()
        except (InvalidTag, ValueError):
            log.error("Vault list refresh: decryption failed.")
            self.toast.show("Vault decryption failed — wrong key?", "error")
            self._cached_entries = []
        except Exception as exc:
            log.error("Vault list refresh error: %s", type(exc).__name__)
            self._cached_entries = []

        self._filter_treeview()

    def _filter_treeview(self):
        """Populate treeview based on search filter (Item 19)."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.vault_filter_var.get().strip().lower()
        entries = getattr(self, "_cached_entries", [])

        visible_count = 0
        for real_idx, e in enumerate(entries):
            lbl  = e.get("label", "")
            user = e.get("username", "")
            if query and (query not in lbl.lower() and query not in user.lower()):
                continue

            visible_count += 1
            # Passwords ALWAYS masked in treeview (Item 20)
            self.tree.insert(
                "",
                "end",
                iid=str(real_idx),
                values=(
                    str(visible_count),
                    lbl,
                    user,
                    "●●●●●●●●",
                    e.get("created", ""),
                ),
            )

        total = len(entries)
        if query:
            self.entry_count_lbl.config(text=f"Showing {visible_count} of {total} credential(s)")
        else:
            self.entry_count_lbl.config(text=f"{total} credential{'s' if total != 1 else ''} stored")

    def _get_selected_index(self) -> int | None:
        sel = self.tree.selection()
        if not sel:
            self.toast.show("Select an entry first.", "warning")
            return None
        return int(sel[0])

    def _reveal_selected_tree(self):
        idx = self._get_selected_index()
        if idx is None:
            return
        entries = getattr(self, "_cached_entries", [])
        if 0 <= idx < len(entries):
            entry = entries[idx]
            modal = ReAuthModal(
                self.root,
                label_hint=f"{entry.get('label')} ({entry.get('username')})",
                plaintext_to_reveal=entry.get("password"),
                on_success=lambda pw: self.toast.show(f"Password: {pw}", "info"),
                clipboard_callback=self._copy_to_clipboard,
            )
            self._open_modal = modal

    def _edit_selected_tree(self):
        """Edit selected entry with re-authentication (Item 18)."""
        idx = self._get_selected_index()
        if idx is None:
            return
        entries = getattr(self, "_cached_entries", [])
        if 0 <= idx < len(entries):
            entry = entries[idx]
            # Must re-authenticate with master password before opening edit dialog
            def on_reauth_success(_):
                EditEntryModal(
                    self.root,
                    entry_idx=idx,
                    entry=entry,
                    on_saved_cb=self._refresh_vault_list,
                    toast=self.toast,
                )

            modal = ReAuthModal(
                self.root,
                label_hint=f"Edit '{entry.get('label')}'",
                plaintext_to_reveal=None,
                on_success=on_reauth_success,
                title="Re-authenticate to Edit",
            )
            self._open_modal = modal

    def _delete_selected_tree(self):
        idx = self._get_selected_index()
        if idx is None:
            return
        entries = getattr(self, "_cached_entries", [])
        if 0 <= idx < len(entries):
            name  = entries[idx].get("username")
            label = entries[idx].get("label")
            if messagebox.askyesno("Confirm Delete",
                                   f"Delete credential for '{name}' ({label})?\nThis cannot be undone.",
                                   parent=self.root):
                try:
                    delete_vault_entry(idx)
                    self.toast.show(f"Deleted entry for '{name}'.", "success")
                    self._refresh_vault_list()
                except Exception as exc:
                    log.error("Delete failed: %s", type(exc).__name__)
                    self.toast.show("Delete failed — see vault.log.", "error")

    # ── Utilities (Items 22 & 23) ─────────────────────────────────────────────
    def _open_change_pw_modal(self):
        ChangeMasterPasswordModal(self.root, self.toast)

    def _export_backup(self):
        """Export encrypted .vlt backup file (Item 23)."""
        if not os.path.exists(DB_FILE):
            self.toast.show("No vault file to export.", "warning"); return

        dest = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export Encrypted Vault Backup",
            defaultextension=".vlt",
            filetypes=[("Vault Backup", "*.vlt"), ("All Files", "*.*")],
            initialfile=f"vault_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.vlt",
        )
        if not dest:
            return

        try:
            with open(DB_FILE, "r", encoding="utf-8") as src_f:
                content = src_f.read()
            with open(dest, "w", encoding="utf-8") as dst_f:
                dst_f.write(content)
            log.info("Encrypted backup exported to %s.", dest)
            self.toast.show("Encrypted backup exported!", "success")
        except Exception as exc:
            log.error("Backup export failed: %s", type(exc).__name__)
            self.toast.show("Export failed — see vault.log.", "error")

    def _import_backup(self):
        """Import encrypted .vlt backup file (Item 23)."""
        src = filedialog.askopenfilename(
            parent=self.root,
            title="Import Encrypted Vault Backup",
            filetypes=[("Vault Backup", "*.vlt"), ("All Files", "*.*")],
        )
        if not src:
            return

        ImportBackupModal(
            self.root,
            filepath=src,
            toast=self.toast,
            on_success_cb=self._refresh_vault_list,
        )

    # ── Run ───────────────────────────────────────────────────────────────────
    def run(self):
        self.root.mainloop()


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = VaultApp()
    app.run()
