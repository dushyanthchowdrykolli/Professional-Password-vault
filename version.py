"""
version.py — Single source of truth for VAULT application & schema versions.

Every component (window title, About dialog, exe version metadata, build scripts,
release archives) must import these constants. Never hardcode version strings elsewhere.
"""

APP_VERSION = "1.0.0"
VAULT_SCHEMA_VERSION = 1
PRODUCT_NAME = "VAULT"
COMPANY_NAME = "VAULT Security"
FILE_DESCRIPTION = "VAULT — AES-256-GCM Encrypted Password Manager"
COPYRIGHT = "Copyright © 2026 VAULT Security. All rights reserved."
