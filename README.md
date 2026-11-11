# ◈ VAULT — AES-256-GCM Encrypted Password Manager
### Dark Luxury Edition · Tier 3 · Python + Tkinter

---

## Overview

**VAULT** is a local-first, offline, single-user GUI password manager.  
All credentials are **encrypted at rest** using AES-256-GCM.  
The master password is **never stored** — it is used to derive a 32-byte key via Argon2id each time the vault is opened.

---

## Security Architecture

| Property | Implementation |
|---|---|
| KDF | Argon2id — `time=2`, `memory=64 MiB`, `parallelism=4`, `hash_len=32` |
| Cipher | AES-256-GCM (authenticated encryption — wrong key → decryption error) |
| Storage | Encrypted JSON blob; only KDF params + salt stored in plaintext header |
| Nonce | 12-byte random nonce prepended to each ciphertext — unique per save |
| Writes | Atomic (`os.replace`) + 1 `.bak` copy — crash-safe |
| Reveal & Edit | Requires master password re-entry; revealed password auto-hides after 15 seconds |
| Clipboard | Copy button on reveal modal; auto-clears after 20 seconds if unchanged |
| Auto-lock | Locks after 5 minutes of inactivity; also locks when window is minimized |
| Back-off | Increasing delay (1 s, 2 s, 4 s…) + 60 s lockout after 5 wrong attempts |
| Password Gen | Cryptographically secure random password generator using Python's `secrets` module |
| Master Key Change | Full vault re-encryption using new salt and new Argon2id derived key |
| Backups | Encrypted `.vlt` export and import with conflict-free merge or full replace |
| Logging | Rotating file handler (`vault.log`, 1 MB, 3 backups) — events only |

---

## Security Notes & Limitations

> ⚠️ **Memory Wiping:** Python cannot reliably zero-fill strings or bytes in memory due to CPython's string interning, garbage collection, and reference counting. Dropping references on lock or exit is **best-effort only**. This is a known, fundamental CPython constraint.

> ⚠️ **Clipboard Stores:** The Windows Clipboard History (`Win+V`) and third-party clipboard managers (e.g. Ditto) may capture passwords copied via the "Copy" button. Our 20-second auto-clear only removes the value from the active OS clipboard buffer — it cannot purge third-party history stores.

> ⚠️ **No Network Calls:** VAULT is strictly offline. It never makes HTTP requests, dials out, or collects telemetry.

---

## Requirements

| Package | Version |
|---|---|
| Python | 3.9 or higher |
| tkinter | Bundled with standard Python |
| cryptography | ≥ 42.0.0 |
| argon2-cffi | ≥ 23.1.0 |

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## How to Run

```bash
python password_vault.py
```

Or press **F5** in Spyder (set Graphics backend to **Automatic** under Tools → Preferences if the window freezes).

### Run unit tests

```bash
python tests_tier2.py
python tests_tier3.py
```

---

## Tabs & Features

| Tab | Purpose |
|---|---|
| `⊕ ADD ENTRY` | Store a new credential (username, password, label). Includes live strength meter and `🎲 GENERATE RANDOM PASSWORD` button powered by `secrets`. |
| `⌕ RETRIEVE` | Search by username or label. Passwords always masked. Click **REVEAL** → re-enter master password → option to **COPY** (auto-clears in 20 s) and inline plaintext reveals for 15 s. |
| `▤ VAULT` | Browse all entries via styled **`ttk.Treeview`** (passwords always masked). Live dynamic search/filter across website/label and username. Select entries to **REVEAL**, **EDIT** (requires master password re-auth), or **DELETE**. Double-click any row to reveal. |
| `Header Utilities` | **KEY** (Change Master Password & re-encrypt vault), **EXPORT** (save encrypted `.vlt` backup), **IMPORT** (decrypt & import backup with merge/replace options). |

---

## Colour Palette (Dark Luxury)

| Role | Hex | Description |
|---|---|---|
| Background | `#0D0F1A` | Midnight navy |
| Card | `#1A1F38` | Component background |
| Border | `#252A45` | Subtle container border |
| Accent Gold | `#C9A84C` | Primary actions & logos |
| Accent Violet | `#7B61FF` | Secondary actions & modals |
| Success | `#4EC994` | Emerald green |
| Danger | `#E05C7A` | Rose red |
| Text | `#E8E6F0` | Soft white |

---

## Project Structure

```
password_vault.py         # Single-file application — UI, crypto, and logic
tests_tier2.py            # Unit tests for validation, sanitization, and lockout
tests_tier3.py            # Unit tests for password generator and entry editing
requirements.txt          # pip dependencies
vault_database.vlt        # Auto-created encrypted vault (home directory)
vault.log                 # Rotating event log (no secrets ever logged)
README.md
```

---

## Tier Roadmap

- [x] **Tier 1** — Encryption core, master password gate, Retrieve tab, wrong-password back-off, atomic writes
- [x] **Tier 2** — Input validation, auto-lock on inactivity/minimize, clipboard copy + auto-clear, named constants, deduplicated UI cards, Theme class, rotating logging, shutdown cleanup
- [x] **Tier 3** — Edit entries with re-auth, dynamic search/filter across fields, ttk.Treeview, `secrets` password generator, change master password, encrypted backup export/import
- [ ] **Tier 4** — User-defined extra additions (placeholder)
