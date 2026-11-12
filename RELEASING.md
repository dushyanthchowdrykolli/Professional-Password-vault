# VAULT — Release Engineering & Security Guide

This document outlines the standard operating procedure (SOP) for building, validating, and releasing new versions of VAULT.

---

## 1. Pre-Release Checklist

Before creating a new release:
1. **Bump Version**: Update `APP_VERSION` in `version.py` following [Semantic Versioning](https://semver.org/).
   - If breaking database schema changes are introduced, increment `VAULT_SCHEMA_VERSION` and implement the corresponding forward migration in `password_vault.py`.
2. **Update Documentation**:
   - Add release notes in `CHANGELOG.md` under the new version header.
   - Verify `README.md` reflects current features and dependencies.
3. **Run Automated Test Suites**:
   ```bash
   python tests_tier2.py
   python tests_tier3.py
   python tests_tier4.py
   python password_vault.py --selftest
   ```
   All test suites must report `OK` / `SELFTEST PASSED`.

---

## 2. Automated Build Execution

Run the build automation script:
```bash
python build.py
```

The build script will automatically:
- Clean stale `build/`, `dist/`, and `release/` artifacts.
- Generate Windows executable metadata from `version.py`.
- Run PyInstaller in `--onedir` windowed mode using `VAULT.spec`.
- Execute the compiled `dist/VAULT/VAULT.exe --selftest` inside an isolated temporary directory to ensure all CFFI extensions and tkinter modules resolved properly.
- Package `release/VAULT-<VERSION>-win64.zip` with `README-FIRST.txt`.
- Compute and write SHA-256 checksums to `release/SHA256SUMS.txt`.

---

## 3. Code Signing & SmartScreen Notes

### Why SmartScreen Triggers
On Windows 10/11, newly downloaded executables without an established reputation or a recognized Authenticode digital signature trigger **Windows Defender SmartScreen**:
> *"Windows protected your PC — Microsoft Defender SmartScreen prevented an unrecognized app from starting."*

Additionally, some heuristic antivirus scanners occasionally flag raw PyInstaller unpackers as generic anomalies.

### How to Fix via Code Signing
To eliminate the warning, sign `VAULT.exe` with a standard or Extended Validation (EV) code signing certificate using Microsoft `signtool.exe`:

```cmd
signtool.exe sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a "dist\VAULT\VAULT.exe"
```

In `build.py`, there is a designated hook `sign_binary(exe_path)` where you can configure your certificate path or environment variables when an Authenticode certificate is available.

---

## 4. Verification on a Clean Machine / VM

Before publishing:
1. Transfer `VAULT-<VERSION>-win64.zip` to a fresh Windows 10 or 11 VM without Python installed.
2. Extract the archive.
3. Verify that `VAULT.exe` launches without requesting missing `.dll` files.
4. Perform an update verification:
   - Place a test vault file in `%APPDATA%\VAULT\vault_database.vlt`.
   - Launch the new `VAULT.exe`.
   - Verify that the vault unlocks cleanly and that a pre-update backup `vault.pre-update-*.bak` was generated in `%APPDATA%\VAULT\`.

---

## 5. Publishing

1. Tag the release commit in Git:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```
2. Create a new GitHub Release matching the tag.
3. Upload:
   - `VAULT-1.0.0-win64.zip`
   - `SHA256SUMS.txt`
   - (Optional) `VAULT-Setup-1.0.0.exe` (if compiled with Inno Setup)
4. Publish the checksum and release notes.

