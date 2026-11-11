# ◈ VAULT — AES-256-GCM Encrypted Password Manager
### Dark Luxury Edition · Standalone Windows Application · v1.0.0

---

## Overview

**VAULT** is a local-first, offline, single-user desktop password manager designed for security professionals and privacy-conscious users.
It runs as a **native standalone Windows application (`VAULT.exe`)** with **no Python installation, no runtime dependencies, and zero network calls**.

All credentials are encrypted at rest using **AES-256-GCM** with keys derived via **Argon2id** (OWASP-compliant parameters). The master password is never stored on disk.

---

## Quick Start (End Users)

### 1. Download & Run
1. Download `VAULT-1.0.0-win64.zip` from the [Releases](https://github.com/dushyanthchowdrykolli/Professional-Password-vault/releases) page.
2. Verify the archive integrity against `SHA256SUMS.txt`:
   ```powershell
   Get-FileHash VAULT-1.0.0-win64.zip -Algorithm SHA256
   ```
3. Extract the ZIP folder to any directory (e.g. `C:\Users\<You>\AppData\Local\Programs\VAULT` or your Desktop).
4. Double-click **`VAULT.exe`**.

> ℹ️ **Windows Defender / SmartScreen Notice:**  
> Because this application is distributed independently without a costly commercial Extended Validation (EV) certificate, Windows SmartScreen may display:  
> *"Windows protected your PC — Microsoft Defender SmartScreen prevented an unrecognized app from starting."*  
> Click **"More info"**, then click **"Run anyway"**.

---

## Where Your Data Lives

Your data is **completely isolated** from the application binaries:

```
Windows Data Location:
%APPDATA%\VAULT\vault_database.vlt
```

- **Upgrades & Deletions:** Deleting, replacing, or reinstalling the application directory **will never touch or delete your vault database**.
- **Audit Logs:** Diagnostic and security events (e.g. unlocks, lockouts, entry updates) are logged to `%APPDATA%\VAULT\vault.log` with a rotating 1 MB limit (max 3 backups). Passwords, keys, salts, and decrypted content are **never logged**.
- **Lock Protection:** An OS-level file lock (`%APPDATA%\VAULT\vault.lock`) prevents multiple instances from running concurrently on the same vault.

---

## How to Update

When a newer version of VAULT is released:

1. **Exit VAULT** completely.
2. Download the new `VAULT-<new-version>-win64.zip`.
3. **Delete the old application folder** completely.  
   *(Always delete the old folder before extracting the new one to prevent orphaned `.dll` files from previous builds).*
4. **Extract the new archive** in its place.
5. Launch the new **`VAULT.exe`**.

### Automated Safety on Upgrade
On the first launch of a new version:
- VAULT automatically creates a timestamped pre-update backup of your database:
  `%APPDATA%\VAULT\vault.pre-update-<old>-to-<new>.bak`
- A toast notification confirms: *"Updated to v<new-version>"*.
- Your existing master password and saved credentials remain completely intact.

---

## Security Architecture

| Feature | Implementation |
|---|---|
| **Cipher** | AES-256-GCM (Authenticated Encryption with Associated Data) |
| **KDF** | Argon2id — `time=2`, `memory=64 MiB`, `parallelism=4`, `hash_len=32` |
| **Storage** | Encrypted JSON payload with unencrypted salt and KDF parameters in the file header |
| **Nonce** | 12-byte random cryptographic nonce generated per atomic save |
| **Integrity** | Tampering or wrong password fails GCM tag authentication directly |
| **Schema Protection** | Embedded `schema_version` with automatic forward migrations and downgrade refusal |
| **Single-Instance** | Kernel file locking via `msvcrt` preventing concurrent database writes |
| **Auto-Lock** | Automatic lock on 5-minute inactivity and window minimize |
| **Clipboard** | 20-second auto-clear timer verifying content before clearing |
| **Password Generator**| Python `secrets` CSPRNG guaranteeing uppercase, lowercase, numbers, and symbols |
| **Backups** | Encrypted export (`.vlt`) and import with conflict-free merge or full replace options |

---

## Security Notes & Limitations

> ⚠️ **Memory Wiping:** Python cannot guarantee zero-filling of freed strings or memory buffers due to CPython's string interning and garbage collection. Dropping references on lock or exit is **best-effort only**. This is an intrinsic CPython characteristic.

> ⚠️ **OS Clipboard History:** Windows Clipboard History (`Win+V`) and third-party tools (e.g. Ditto) hook operating system clipboard events. Our 20-second clear empties the active clipboard buffer, but cannot erase historic entries captured by external tools.

> ⚠️ **Zero Network Surface:** VAULT is strictly offline. It contains no web server, no network callers, no update checkers, and no telemetry.

---

## Building from Source (Developers)

### Requirements
- Windows 10/11 x64
- Python 3.9+ (Python 3.11+ recommended)

### Build Steps
1. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
2. Run test suites:
   ```powershell
   python tests_tier2.py
   python tests_tier3.py
   python tests_tier4.py
   python password_vault.py --selftest
   ```
3. Execute the automated build script:
   ```powershell
   python build.py
   ```
4. Output artifacts are created in `release/`:
   - `VAULT-1.0.0-win64.zip`
   - `SHA256SUMS.txt`

### Optional Inno Setup Installer
If you have [Inno Setup 6+](https://jrsoftware.org/isinfo.php) installed, compile `installer.iss` to produce `VAULT-Setup-1.0.0.exe` for per-user installation.

---

## License

This project is licensed under the MIT License. Built for educational, personal, and professional security use.
