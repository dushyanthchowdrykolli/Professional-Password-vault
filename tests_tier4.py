"""
tests_tier4.py — Unit tests for Tier 4:
  - SingleInstanceLock behavior
  - Vault schema envelope and downgrade protection
  - Legacy payload conversion
  - Version consistency
  - Resource path resolution
"""

import sys
import os
import unittest
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Stub tkinter for headless execution
tkinter_stub = types.ModuleType("tkinter")
for attr in ("Tk", "Frame", "Label", "Entry", "Canvas", "Scrollbar",
             "Radiobutton", "IntVar", "StringVar", "Toplevel"):
    setattr(tkinter_stub, attr, object)
tkinter_stub.TclError = Exception
tkinter_stub.messagebox = types.ModuleType("messagebox")
tkinter_stub.ttk = types.ModuleType("ttk")
tkinter_stub.ttk.Treeview = object
tkinter_stub.ttk.Style = object
tkinter_stub.filedialog = types.ModuleType("filedialog")

sys.modules["tkinter"] = tkinter_stub
sys.modules["tkinter.messagebox"] = tkinter_stub.messagebox
sys.modules["tkinter.ttk"] = tkinter_stub.ttk
sys.modules["tkinter.filedialog"] = tkinter_stub.filedialog

from version import APP_VERSION, VAULT_SCHEMA_VERSION, PRODUCT_NAME
from password_vault import (
    SingleInstanceLock,
    SchemaDowngradeError,
    _process_vault_payload,
    resource_path,
)


class TestVersionAndMetadata(unittest.TestCase):
    def test_version_format(self):
        parts = APP_VERSION.split(".")
        self.assertEqual(len(parts), 3, "APP_VERSION must be semantic (X.Y.Z)")
        for p in parts:
            self.assertTrue(p.isdigit(), f"Version part {p} must be integer")

    def test_schema_version_type(self):
        self.assertIsInstance(VAULT_SCHEMA_VERSION, int)
        self.assertGreaterEqual(VAULT_SCHEMA_VERSION, 1)

    def test_product_name(self):
        self.assertEqual(PRODUCT_NAME, "VAULT")


class TestSchemaProtection(unittest.TestCase):
    def test_legacy_list_payload_backward_compatibility(self):
        # Tier 3 vaults stored entries directly as a list
        legacy_list = [
            {"label": "Site1", "username": "user1", "password": "pw1", "created": "2026-01-01"}
        ]
        entries, schema_ver = _process_vault_payload(legacy_list)
        self.assertEqual(entries, legacy_list)
        self.assertEqual(schema_ver, VAULT_SCHEMA_VERSION)

    def test_current_schema_envelope(self):
        payload = {
            "schema_version": VAULT_SCHEMA_VERSION,
            "entries": [{"label": "Site2", "username": "user2", "password": "pw2"}],
        }
        entries, schema_ver = _process_vault_payload(payload)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["label"], "Site2")
        self.assertEqual(schema_ver, VAULT_SCHEMA_VERSION)

    def test_downgrade_refusal(self):
        # Newer schema version must raise SchemaDowngradeError and refuse to open
        future_payload = {
            "schema_version": VAULT_SCHEMA_VERSION + 1,
            "entries": [{"label": "FutureSite"}],
        }
        with self.assertRaises(SchemaDowngradeError):
            _process_vault_payload(future_payload)


class TestSingleInstanceLock(unittest.TestCase):
    def test_lock_acquire_and_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            lock_file = os.path.join(td, "test.lock")
            lock1 = SingleInstanceLock(lock_file)
            lock2 = SingleInstanceLock(lock_file)

            # First lock should succeed
            self.assertTrue(lock1.acquire())

            # Second lock on same file must fail
            self.assertFalse(lock2.acquire())

            # Release first lock
            lock1.release()

            # Now second lock can acquire
            self.assertTrue(lock2.acquire())
            lock2.release()


class TestResourcePath(unittest.TestCase):
    def test_resource_path_dev(self):
        p = resource_path("vault.ico")
        self.assertTrue(isinstance(p, str))
        self.assertTrue(p.endswith("vault.ico"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

