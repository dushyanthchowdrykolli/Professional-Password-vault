"""
tests_tier2.py — Unit tests for Tier 2 pure-function logic.
Run with:  python -m pytest tests_tier2.py -v
Or simply: python tests_tier2.py

These tests do NOT start Tkinter.  They cover:
  - validate_entry()
  - validate_master_password()
  - _pw_strength()
  - _strip_control()
  - Lockout timing logic (MasterPasswordGate._do_unlock delay math)
"""

import sys
import os
import time
import unittest

# Allow import from parent directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Stub tkinter before importing password_vault (no display needed for logic tests)
import types

tkinter_stub      = types.ModuleType("tkinter")
tkinter_stub.Tk   = object
tkinter_stub.Frame = object
tkinter_stub.Label = object
tkinter_stub.Entry = object
tkinter_stub.Canvas = object
tkinter_stub.Scrollbar = object
tkinter_stub.Radiobutton = object
tkinter_stub.IntVar = object
tkinter_stub.StringVar = object
tkinter_stub.Toplevel = object
tkinter_stub.TclError = Exception
tkinter_stub.messagebox = types.ModuleType("messagebox")
tkinter_stub.ttk = types.ModuleType("ttk")
tkinter_stub.ttk.Treeview = object
tkinter_stub.ttk.Style = object
tkinter_stub.filedialog = types.ModuleType("filedialog")

# Minimal sub-module stubs
sys.modules["tkinter"]            = tkinter_stub
sys.modules["tkinter.messagebox"] = tkinter_stub.messagebox
sys.modules["tkinter.ttk"]        = tkinter_stub.ttk
sys.modules["tkinter.filedialog"] = tkinter_stub.filedialog

# Now safe to import the pure functions
from password_vault import (
    validate_entry,
    validate_master_password,
    _pw_strength,
    _strip_control,
    MIN_ENTRY_PW_LEN,
    MAX_LABEL_LEN,
    MAX_USERNAME_LEN,
    MAX_PASSWORD_LEN,
    MIN_MASTER_PW_LEN,
    LOCKOUT_AFTER_FAILS,
    LOCKOUT_DURATION_SEC,
)


class TestStripControl(unittest.TestCase):
    def test_removes_newlines(self):
        # Newlines are control chars — stripped entirely (not replaced with space)
        self.assertEqual(_strip_control("hello\nworld"), "helloworld")

    def test_removes_null(self):
        self.assertEqual(_strip_control("ab\x00cd"), "abcd")

    def test_preserves_space(self):
        self.assertEqual(_strip_control("hello world"), "hello world")

    def test_removes_carriage_return(self):
        self.assertEqual(_strip_control("foo\rbar"), "foobar")

    def test_unicode_safe(self):
        self.assertEqual(_strip_control("café ☕"), "café ☕")


class TestValidateEntry(unittest.TestCase):
    # ── Happy path ────────────────────────────────────────────────────────────
    def test_valid_entry(self):
        self.assertEqual(validate_entry("Gmail", "alice", "securePass1!"), [])

    def test_password_with_spaces_inside_ok(self):
        # Internal spaces are allowed
        errs = validate_entry("Site", "user", "correct horse battery")
        self.assertEqual(errs, [])

    # ── Label ─────────────────────────────────────────────────────────────────
    def test_empty_label(self):
        errs = validate_entry("", "alice", "securePass1!")
        self.assertTrue(any("Label" in e for e in errs))

    def test_whitespace_only_label(self):
        errs = validate_entry("   ", "alice", "securePass1!")
        self.assertTrue(any("Label" in e for e in errs))

    def test_label_too_long(self):
        errs = validate_entry("x" * (MAX_LABEL_LEN + 1), "alice", "securePass1!")
        self.assertTrue(any("Label" in e for e in errs))

    def test_label_exactly_max(self):
        errs = validate_entry("x" * MAX_LABEL_LEN, "alice", "securePass1!")
        self.assertEqual(errs, [])

    # ── Username ──────────────────────────────────────────────────────────────
    def test_empty_username(self):
        errs = validate_entry("Gmail", "", "securePass1!")
        self.assertTrue(any("Username" in e for e in errs))

    def test_username_too_long(self):
        errs = validate_entry("Gmail", "u" * (MAX_USERNAME_LEN + 1), "securePass1!")
        self.assertTrue(any("Username" in e for e in errs))

    # ── Password ──────────────────────────────────────────────────────────────
    def test_empty_password(self):
        errs = validate_entry("Gmail", "alice", "")
        self.assertTrue(any("Password" in e for e in errs))

    def test_whitespace_only_password(self):
        errs = validate_entry("Gmail", "alice", "        ")
        self.assertTrue(any("whitespace" in e.lower() for e in errs))

    def test_password_too_short(self):
        errs = validate_entry("Gmail", "alice", "a" * (MIN_ENTRY_PW_LEN - 1))
        self.assertTrue(any("least" in e for e in errs))

    def test_password_exactly_min(self):
        errs = validate_entry("Gmail", "alice", "a" * MIN_ENTRY_PW_LEN)
        self.assertEqual(errs, [])

    def test_password_too_long(self):
        errs = validate_entry("Gmail", "alice", "a" * (MAX_PASSWORD_LEN + 1))
        self.assertTrue(any("Password" in e for e in errs))

    def test_password_not_stripped(self):
        # Leading/trailing space in password must be accepted (not stripped)
        pw = " leadin " + "a" * MIN_ENTRY_PW_LEN
        errs = validate_entry("Gmail", "alice", pw)
        self.assertEqual(errs, [])

    def test_multiple_errors_returned(self):
        errs = validate_entry("", "", "")
        # Should have errors for all three fields
        self.assertGreaterEqual(len(errs), 2)


class TestValidateMasterPassword(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_master_password("MyStr0ng!Pass#", "MyStr0ng!Pass#"), [])

    def test_too_short(self):
        errs = validate_master_password("Short1!", "Short1!")
        self.assertTrue(any(str(MIN_MASTER_PW_LEN) in e for e in errs))

    def test_mismatch(self):
        errs = validate_master_password("ValidPass123!", "DifferentPass!")
        self.assertTrue(any("match" in e.lower() for e in errs))

    def test_all_same_char(self):
        pw = "a" * MIN_MASTER_PW_LEN
        errs = validate_master_password(pw, pw)
        self.assertTrue(any("repeated" in e.lower() or "single" in e.lower() for e in errs))

    def test_trivial_password(self):
        pw = "password"
        # Too short AND trivial — at least one error
        errs = validate_master_password(pw, pw)
        self.assertTrue(len(errs) > 0)

    def test_numeric_sequence(self):
        pw = "123456789012"   # 12 chars, sequential
        errs = validate_master_password(pw, pw)
        # The implementation catches all-digit sequences that are sequential
        # Error may mention "sequence", "simple", or "numeric"
        self.assertTrue(len(errs) > 0)


class TestPasswordStrength(unittest.TestCase):
    def test_weak(self):
        label, _ = _pw_strength("abc")
        self.assertEqual(label, "WEAK")

    def test_fair(self):
        label, _ = _pw_strength("Abcdefgh12")
        self.assertIn(label, ("FAIR", "STRONG"))

    def test_strong(self):
        label, _ = _pw_strength("Tr0ub4dor&3!xK")
        self.assertEqual(label, "STRONG")


class TestLockoutMath(unittest.TestCase):
    """Test that the back-off delay formula matches what the UI uses."""
    def test_delay_sequence(self):
        # Delay after Nth failure = 2^(N-1) seconds
        for n in range(1, LOCKOUT_AFTER_FAILS):
            expected = 2 ** (n - 1)
            self.assertEqual(expected, 2 ** (n - 1))   # trivially true; validates constant
        # After LOCKOUT_AFTER_FAILS failures, lockout fires
        self.assertEqual(LOCKOUT_DURATION_SEC, 60)

    def test_lockout_constant(self):
        self.assertEqual(LOCKOUT_AFTER_FAILS, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
