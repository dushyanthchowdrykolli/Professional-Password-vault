# Changelog

All notable changes to VAULT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-12

### Added
- **Tier 1 — Encryption Core**: AES-256-GCM authenticated encryption at rest, Argon2id key derivation, master password gateway, wrong-password exponential back-off and 60-second lockout, atomic writes with crash recovery backup.
- **Tier 2 — Hardening & Quality**: Pure-function input validation, automatic vault lock on 5-minute inactivity and window minimize, clipboard copy with 20-second auto-clear timer, rotating audit log without secret leakage, clean shutdown after-job cancellation.
- **Tier 3 — Advanced Features**: ttk.Treeview table, live dynamic search filter across label and username, entry editing with re-authentication, `secrets` CSPRNG password generator, master password change with full vault re-encryption, encrypted `.vlt` export/import backups.
- **Tier 4 — Standalone Windows Release**: Standalone onedir Windows distribution (no Python required), decoupled user data in `%APPDATA%\VAULT\`, OS-level single-instance file lock (msvcrt), schema migration framework with downgrade protection, `--selftest` diagnostic flag, automated build script, and Inno Setup installer script.

