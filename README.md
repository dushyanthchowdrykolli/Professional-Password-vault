# ◈ VAULT — MD5 Password Manager
### Dark Luxury Edition · Built with Python & Tkinter

---

## Overview

**VAULT** is a local-first, GUI-based password manager that converts credentials into MD5 hashes and stores them in a structured XML database on your machine. It features a dark luxury interface built entirely with Python's standard library — no internet connection, no third-party services, and no data leaving your device.

Designed to run directly from **Spyder IDE** or any Python interpreter. A future `.exe` upgrade path is documented at the bottom of this file.

---

## Screenshots / Interface

The app has three main tabs:

| Tab | Purpose |
|-----|---------|
| `⊕ ADD ENTRY` | Store a new username + password as MD5 hashes |
| `⌕ LOOKUP` | Verify credentials and reveal a stored entry in readable form |
| `▤ VAULT` | Browse, inspect, and delete all stored credentials |

---

## Features

- **MD5 Hashing** — All passwords (and usernames) are converted to MD5 before storage. Plain-text passwords are never written to disk.
- **Live Hash Preview** — As you type a password in the Add tab, the MD5 hash updates in real time so you can see exactly what will be stored.
- **Credential Lookup** — Enter a username and password to verify them against the vault. If they match, the full stored entry is revealed including both hashes, label, and creation timestamp.
- **XML Local Database** — All data is saved to a human-readable, pretty-printed XML file in your home directory.
- **Dark Luxury UI** — Midnight navy background, antique gold accents, electric violet highlights. A refined aesthetic that avoids the cliché green-on-black look.
- **Toast Notifications** — Non-blocking popup messages for success, error, warning, and info states.
- **Live Clock** — Timestamp displayed in the header and recorded for each stored credential.
- **Zero External Dependencies** — Uses only Python's standard library (`tkinter`, `hashlib`, `xml`, `os`, `datetime`).

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.9 or higher |
| tkinter | Bundled with standard Python |
| Spyder IDE | Any recent version (optional — any Python terminal works) |

> **No `pip install` needed.** Every library used (`tkinter`, `hashlib`, `xml.etree.ElementTree`, `xml.dom.minidom`, `os`, `datetime`, `threading`) ships with Python by default.

### Verify tkinter is available

```python
import tkinter
tkinter._test()
```

If a small test window opens, you're ready to go. If not, reinstall Python from [python.org](https://python.org) and make sure to check **"tcl/tk and IDLE"** during installation.

---

## Installation

1. **Download** `password_vault.py` to any folder on your computer.
2. **Open** it in Spyder (or any Python-compatible editor).
3. **Run** it — no setup, no configuration required.

---

## How to Run

### In Spyder

1. Open `password_vault.py` in the Spyder editor.
2. Press **F5** — or go to **Run → Run File**.
3. The VAULT window will open as a separate GUI window.

> ⚠️ **Spyder Note:** If the window appears frozen or doesn't respond, go to **Tools → Preferences → IPython Console → Graphics** and set the backend to **"Automatic"** or **"tkinter"**. Then restart the console kernel.

### From Command Line / Terminal

```bash
python password_vault.py
```

### From Any Python IDE

Open the file and run it. The `if __name__ == "__main__":` guard at the bottom ensures it launches correctly.

---

## Database File

Credentials are stored in:

```
Windows:   C:\Users\<YourName>\vault_database.xml
macOS:     /Users/<YourName>/vault_database.xml
Linux:     /home/<YourName>/vault_database.xml
```

### XML Structure

```xml
<?xml version="1.0" ?>
<vault version="1.0" updated="2025-02-23T14:30:00">
  <entry>
    <username>johndoe</username>
    <username_hash>4d186321c1a7f0f354b297e8914ab240</username_hash>
    <password_hash>5f4dcc3b5aa765d61d8327deb882cf99</password_hash>
    <label>GitHub</label>
    <created>2025-02-23 14:30:00</created>
  </entry>
</vault>
```

Each `<entry>` contains:

| Field | Description |
|-------|-------------|
| `username` | Plain-text username (stored for display) |
| `username_hash` | MD5 hash of the username |
| `password_hash` | MD5 hash of the password |
| `label` | Optional site or service label |
| `created` | Timestamp of when the entry was created |

> The plain-text **password is never stored** — only its MD5 hash. The username is stored in plain text for display purposes in the Vault tab.

---

## Usage Guide

### Adding a Credential

1. Click the **⊕ ADD ENTRY** tab.
2. Fill in **Username**, **Label / Site**, **Password**, and **Confirm Password**.
3. Watch the **MD5 PREVIEW** bar update in real time as you type.
4. Click **⊕ STORE CREDENTIAL**.
5. A success toast confirms storage. The entry is now in `vault_database.xml`.

### Looking Up a Credential

1. Click the **⌕ LOOKUP** tab.
2. Enter the **Username** and **Password** you want to verify.
3. Click **⌕ LOOKUP CREDENTIAL**.
4. If the credentials match a stored entry, the full record is revealed — username, both hashes (with segment breakdown), label, and creation date.
5. If no match is found, an error panel is displayed.

### Browsing the Vault

1. Click the **▤ VAULT** tab.
2. All stored entries are displayed in a scrollable table.
3. **Click any row** to select it (a radio button appears on the left).
4. Click **✖ DELETE SELECTED** to remove that entry (with confirmation dialog).
5. Click **⟳ REFRESH** to reload the list from disk.

---

## Security Notes

> **VAULT is intended for educational and local personal use.** Please read these notes before relying on it for sensitive data.

- **MD5 is not cryptographically secure** for password storage in production systems. It is fast to compute, has known collision vulnerabilities, and is susceptible to rainbow table attacks. Modern systems use bcrypt, Argon2, or PBKDF2 instead.
- **No salt is applied** to hashes in this implementation. Two users with the same password will produce the same hash.
- **The username is stored in plain text.** Only the password is hashed.
- **No encryption is applied to the XML file.** Anyone with access to your filesystem can read the file.
- This tool is suitable for learning how hashing works, local credential organization, and as a base to build upon — not as a replacement for a production password manager.

---

## Colour Palette

| Role | Hex | Description |
|------|-----|-------------|
| Background | `#0D0F1A` | Midnight navy |
| Surface | `#13172B` | Raised panel |
| Card | `#1A1F38` | Component background |
| Accent (Gold) | `#C9A84C` | Antique gold — primary action |
| Accent (Violet) | `#7B61FF` | Electric violet — secondary action |
| Success | `#4EC994` | Emerald green |
| Danger | `#E05C7A` | Rose red |
| Text | `#E8E6F0` | Soft white |

---

## Project Structure

```
password_vault.py          # Single-file application — all logic and UI
vault_database.xml         # Auto-created in your home directory on first save
README.md                  # This file
```

---

## Upgrading to a Standalone .exe (Future Step)

When you're ready to package VAULT as a Windows executable:

### Step 1 — Install PyInstaller

```bash
pip install pyinstaller
```

### Step 2 — Build the executable

```bash
pyinstaller --onefile --windowed --name "VAULT" password_vault.py
```

| Flag | Effect |
|------|--------|
| `--onefile` | Bundles everything into a single `.exe` |
| `--windowed` | Hides the terminal/console window |
| `--name "VAULT"` | Names the output file `VAULT.exe` |

### Step 3 — Find your executable

```
dist/
  VAULT.exe   ← your standalone application
```

> The `vault_database.xml` file will still be created in the user's home directory when they first save a credential. No admin rights required.

---

## Troubleshooting

**The window doesn't appear when I run in Spyder**
→ Go to Tools → Preferences → IPython Console → Graphics → Backend → set to `Automatic`. Restart the kernel.

**`ModuleNotFoundError: No module named 'tkinter'`**
→ Reinstall Python from python.org. On Linux: `sudo apt-get install python3-tk`

**The app opens but the UI looks wrong / unstyled**
→ Ensure you're using Python 3.9+. Older versions have limited tkinter support.

**I deleted the XML file by accident**
→ The app will create a fresh empty vault the next time you add a credential. Old entries cannot be recovered.

**The window freezes after I click a button**
→ This is a known Spyder/tkinter threading quirk on some systems. Try running the file from a plain terminal (`python password_vault.py`) for the smoothest experience.

---

## License

This project is free to use, modify, and distribute for personal and educational purposes.

---

## Author Notes

Built as a foundation for learning about:
- Cryptographic hashing with Python's `hashlib`
- GUI development with `tkinter`
- Local file-based data persistence with XML
- Designing elegant dark-theme desktop UIs without external CSS or web frameworks

*Stage 1 complete. Future upgrades: `.exe` packaging, bcrypt upgrade, master password encryption, import/export, and search/filter in the Vault tab.*
