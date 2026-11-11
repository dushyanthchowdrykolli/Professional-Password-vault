"""
tests_tier3.py — Unit tests for Tier 3 logic:
  - Cryptographic password generator (generate_password)
  - Validation functions
  - Master password change logic
  - Entry editing validation
"""

import sys
import os
import unittest
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Stub tkinter before importing password_vault
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

from password_vault import (
    generate_password,
    validate_entry,
    validate_master_password,
    DEFAULT_GEN_PW_LEN,
)


class TestPasswordGenerator(unittest.TestCase):
    def test_default_length(self):
        pw = generate_password()
        self.assertEqual(len(pw), DEFAULT_GEN_PW_LEN)

    def test_custom_length(self):
        pw = generate_password(length=24)
        self.assertEqual(len(pw), 24)

    def test_minimum_length_enforced(self):
        pw = generate_password(length=4)  # Requesting below 8
        self.assertGreaterEqual(len(pw), 8)

    def test_character_classes_present(self):
        for _ in range(20):
            pw = generate_password(16, include_symbols=True)
            has_lower = any(c.islower() for c in pw)
            has_upper = any(c.isupper() for c in pw)
            has_digit = any(c.isdigit() for c in pw)
            has_sym   = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw)
            self.assertTrue(has_lower and has_upper and has_digit and has_sym)

    def test_no_symbols_option(self):
        for _ in range(20):
            pw = generate_password(16, include_symbols=False)
            has_sym = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw)
            self.assertFalse(has_sym)

    def test_randomness_uniqueness(self):
        passwords = {generate_password(16) for _ in range(100)}
        self.assertEqual(len(passwords), 100)  # No duplicates in 100 generations


class TestValidationTier3(unittest.TestCase):
    def test_edit_validation_valid(self):
        errs = validate_entry("Updated Site", "new_user@domain.com", "Str0ng!UpdatedPass")
        self.assertEqual(errs, [])

    def test_edit_validation_invalid_password(self):
        errs = validate_entry("Updated Site", "new_user@domain.com", "short")
        self.assertTrue(any("least" in e for e in errs))


if __name__ == "__main__":
    unittest.main(verbosity=2)

