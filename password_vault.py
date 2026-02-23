"""
╔══════════════════════════════════════════════════════════════╗
║              VAULT — MD5 Password Manager                    ║
║         Dark Luxury Edition | Run from Spyder               ║
╚══════════════════════════════════════════════════════════════╝

Requirements:
    pip install tkinter (usually bundled with Python)
    All other libs are from standard library.

Run directly in Spyder: press F5 or Run → Run File
"""

import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont
import hashlib
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import os
import time
import threading
from datetime import datetime

# ─── CONFIG ──────────────────────────────────────────────────────────────────
DB_FILE = os.path.join(os.path.expanduser("~"), "vault_database.xml")

# ─── PALETTE — Midnight Luxury ────────────────────────────────────────────────
C = {
    "bg":          "#0D0F1A",   # Near-black midnight blue
    "surface":     "#13172B",   # Raised surface
    "card":        "#1A1F38",   # Card background
    "border":      "#252A45",   # Subtle border
    "accent":      "#C9A84C",   # Antique gold
    "accent2":     "#7B61FF",   # Electric violet
    "accent_dim":  "#8B6E2E",   # Dimmed gold
    "text":        "#E8E6F0",   # Soft white
    "text_muted":  "#6B6E8A",   # Muted lavender-grey
    "text_dim":    "#3D4060",   # Very dim
    "success":     "#4EC994",   # Emerald
    "danger":      "#E05C7A",   # Rose red
    "warning":     "#F0A850",   # Amber
    "input_bg":    "#0F1225",   # Input field bg
    "hover":       "#22284A",   # Hover state
    "tag_bg":      "#1E2240",   # Tag background
}

# ─── DATABASE LAYER ───────────────────────────────────────────────────────────
def md5_hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def load_db() -> list[dict]:
    """Load entries from XML file. Returns list of dicts."""
    if not os.path.exists(DB_FILE):
        return []
    try:
        tree = ET.parse(DB_FILE)
        root = tree.getroot()
        entries = []
        for entry in root.findall("entry"):
            entries.append({
                "username":      entry.findtext("username", ""),
                "username_hash": entry.findtext("username_hash", ""),
                "password_hash": entry.findtext("password_hash", ""),
                "created":       entry.findtext("created", ""),
                "label":         entry.findtext("label", ""),
            })
        return entries
    except Exception:
        return []


def save_db(entries: list[dict]):
    """Save entries to XML file with pretty-print."""
    root = ET.Element("vault")
    root.set("version", "1.0")
    root.set("updated", datetime.now().isoformat())
    for e in entries:
        entry_el = ET.SubElement(root, "entry")
        for key, val in e.items():
            child = ET.SubElement(entry_el, key)
            child.text = str(val)
    raw = ET.tostring(root, encoding="unicode")
    pretty = minidom.parseString(raw).toprettyxml(indent="  ")
    # Remove the default XML declaration line so we can write our own
    lines = pretty.split("\n")
    final = "\n".join(lines)
    with open(DB_FILE, "w", encoding="utf-8") as f:
        f.write(final)


def add_entry(username: str, password: str, label: str = "") -> dict:
    entries = load_db()
    entry = {
        "username":      username,
        "username_hash": md5_hash(username),
        "password_hash": md5_hash(password),
        "created":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "label":         label or "Default",
    }
    entries.append(entry)
    save_db(entries)
    return entry


def delete_entry(index: int):
    entries = load_db()
    if 0 <= index < len(entries):
        entries.pop(index)
        save_db(entries)


def lookup_entry(username: str, password: str):
    """Return matching entry if credentials match."""
    u_hash = md5_hash(username)
    p_hash = md5_hash(password)
    for e in load_db():
        if e["username_hash"] == u_hash and e["password_hash"] == p_hash:
            return e
    return None


# ─── ANIMATED TYPEWRITER LABEL ────────────────────────────────────────────────
class TypewriterLabel(tk.Label):
    def __init__(self, master, full_text="", delay=40, **kwargs):
        super().__init__(master, **kwargs)
        self._full = full_text
        self._delay = delay

    def animate(self, text=None):
        if text:
            self._full = text
        self.config(text="")
        self._idx = 0
        self._type_next()

    def _type_next(self):
        if self._idx <= len(self._full):
            self.config(text=self._full[:self._idx])
            self._idx += 1
            self.after(self._delay, self._type_next)


# ─── TOAST NOTIFICATION ───────────────────────────────────────────────────────
class Toast:
    def __init__(self, root):
        self.root = root
        self._win = None

    def show(self, message, kind="success", duration=2500):
        if self._win:
            try:
                self._win.destroy()
            except Exception:
                pass

        color = {"success": C["success"], "error": C["danger"], "info": C["accent2"], "warning": C["warning"]}.get(kind, C["accent"])
        icon  = {"success": "✦", "error": "✖", "info": "◆", "warning": "▲"}.get(kind, "●")

        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=C["card"])

        # Position bottom-right
        self.root.update_idletasks()
        rw = self.root.winfo_width()
        rx = self.root.winfo_x()
        ry = self.root.winfo_y()
        rh = self.root.winfo_height()
        win.geometry(f"+{rx + rw - 320}+{ry + rh - 90}")

        frame = tk.Frame(win, bg=C["card"], padx=18, pady=12,
                         highlightbackground=color, highlightthickness=1)
        frame.pack()

        tk.Label(frame, text=icon, fg=color, bg=C["card"],
                 font=("Courier New", 14, "bold")).pack(side="left", padx=(0,10))
        tk.Label(frame, text=message, fg=C["text"], bg=C["card"],
                 font=("Georgia", 10)).pack(side="left")

        self._win = win
        win.after(duration, self._dismiss)

    def _dismiss(self):
        try:
            if self._win:
                self._win.destroy()
                self._win = None
        except Exception:
            pass


# ─── CUSTOM STYLED WIDGETS ────────────────────────────────────────────────────
class StyledEntry(tk.Frame):
    """Input field with label, gold underline focus effect."""
    def __init__(self, master, label="", placeholder="", show=None, **kwargs):
        super().__init__(master, bg=C["bg"], **kwargs)
        self.label_txt = label
        self.show_char = show

        lbl = tk.Label(self, text=label.upper(), fg=C["text_muted"], bg=C["bg"],
                       font=("Courier New", 8, "bold"), anchor="w")
        lbl.pack(fill="x", padx=2)

        container = tk.Frame(self, bg=C["input_bg"], padx=12, pady=8,
                             highlightbackground=C["border"], highlightthickness=1)
        container.pack(fill="x")

        self.var = tk.StringVar()
        entry_kw = dict(
            textvariable=self.var,
            bg=C["input_bg"], fg=C["text"],
            insertbackground=C["accent"],
            relief="flat", bd=0,
            font=("Courier New", 11),
            highlightthickness=0,
        )
        if show:
            entry_kw["show"] = show
        self.entry = tk.Entry(container, **entry_kw)
        self.entry.pack(fill="x")

        # Underline bar
        self.bar = tk.Frame(self, bg=C["border"], height=2)
        self.bar.pack(fill="x")

        self.entry.bind("<FocusIn>",  self._on_focus)
        self.entry.bind("<FocusOut>", self._on_blur)

        if placeholder:
            self._ph = placeholder
            self._show_placeholder()
            self.entry.bind("<FocusIn>",  self._clear_ph)
            self.entry.bind("<FocusOut>", self._restore_ph)

    def _on_focus(self, e=None):
        self.bar.config(bg=C["accent"])

    def _on_blur(self, e=None):
        self.bar.config(bg=C["border"])

    def _show_placeholder(self):
        if not self.var.get():
            if self.show_char:
                self.entry.config(show="")
            self.entry.insert(0, self._ph)
            self.entry.config(fg=C["text_dim"])

    def _clear_ph(self, e=None):
        if self.entry.get() == self._ph:
            self.entry.delete(0, "end")
            self.entry.config(fg=C["text"])
            if self.show_char:
                self.entry.config(show=self.show_char)
        self._on_focus()

    def _restore_ph(self, e=None):
        if not self.entry.get():
            self._show_placeholder()
        self._on_blur()

    def get(self):
        v = self.var.get()
        if hasattr(self, "_ph") and v == self._ph:
            return ""
        return v

    def clear(self):
        self.entry.delete(0, "end")
        if hasattr(self, "_ph"):
            self._show_placeholder()


class GoldButton(tk.Frame):
    """Elegant gold bordered button with hover shimmer."""
    def __init__(self, master, text="", command=None, variant="primary", **kwargs):
        super().__init__(master, bg=C["bg"], **kwargs)
        colors = {
            "primary": (C["accent"],    C["bg"],       C["accent_dim"]),
            "danger":  (C["danger"],    C["bg"],       "#9A2E4A"),
            "ghost":   (C["border"],    C["text_muted"], C["hover"]),
            "violet":  (C["accent2"],   C["bg"],       "#5A44CC"),
        }
        border, fg, hover = colors.get(variant, colors["primary"])

        self._border   = border
        self._hover_bg = hover
        self._fg       = fg
        self._variant  = variant

        self.btn = tk.Label(
            self, text=text, fg=fg if variant != "primary" else C["accent"],
            bg=C["bg"], font=("Courier New", 10, "bold"),
            padx=22, pady=10, cursor="hand2",
            highlightbackground=border, highlightthickness=1,
        )
        self.btn.pack(fill="both", expand=True)

        self.btn.bind("<Enter>",   self._hover_on)
        self.btn.bind("<Leave>",   self._hover_off)
        self.btn.bind("<Button-1>", lambda e: command() if command else None)

    def _hover_on(self, e):
        if self._variant == "primary":
            self.btn.config(bg=C["accent"], fg=C["bg"])
        elif self._variant == "violet":
            self.btn.config(bg=C["accent2"], fg=C["text"])
        elif self._variant == "danger":
            self.btn.config(bg=C["danger"], fg=C["text"])
        else:
            self.btn.config(bg=C["hover"])

    def _hover_off(self, e):
        self.btn.config(
            bg=C["bg"],
            fg=C["accent"] if self._variant == "primary" else
               C["accent2"] if self._variant == "violet" else
               C["danger"]  if self._variant == "danger" else C["text_muted"]
        )


# ─── MAIN APPLICATION ─────────────────────────────────────────────────────────
class VaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VAULT — MD5 Password Manager")
        self.root.geometry("960x700")
        self.root.minsize(860, 620)
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)

        self.toast = Toast(self.root)
        self._build_ui()
        self._refresh_vault_list()

    # ── HEADER ────────────────────────────────────────────────────────────────
    def _build_header(self, parent):
        hdr = tk.Frame(parent, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, 2))

        # Logo area
        logo_frame = tk.Frame(hdr, bg=C["bg"])
        logo_frame.pack(side="left")

        tk.Label(logo_frame, text="◈", fg=C["accent"], bg=C["bg"],
                 font=("Courier New", 24)).pack(side="left", padx=(0,8))
        tk.Label(logo_frame, text="VAULT", fg=C["text"], bg=C["bg"],
                 font=("Courier New", 20, "bold")).pack(side="left")
        tk.Label(logo_frame, text=" MD5 SECURE STORE", fg=C["text_muted"], bg=C["bg"],
                 font=("Courier New", 9)).pack(side="left", padx=(6,0), pady=(8,0))

        # Live clock
        self.clock_lbl = tk.Label(hdr, fg=C["text_dim"], bg=C["bg"],
                                  font=("Courier New", 9))
        self.clock_lbl.pack(side="right", padx=4)
        self._tick_clock()

        # DB path badge
        short = os.path.basename(DB_FILE)
        tk.Label(hdr, text=f"  {short}  ", fg=C["text_muted"], bg=C["tag_bg"],
                 font=("Courier New", 8), padx=6, pady=2).pack(side="right", padx=8)

        # Separator
        tk.Frame(parent, bg=C["accent"], height=1).pack(fill="x")
        tk.Frame(parent, bg=C["bg"],     height=1).pack(fill="x")
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x")

    def _tick_clock(self):
        self.clock_lbl.config(text=datetime.now().strftime("⏱  %Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._tick_clock)

    # ── MAIN UI BUILD ─────────────────────────────────────────────────────────
    def _build_ui(self):
        outer = tk.Frame(self.root, bg=C["bg"], padx=24, pady=16)
        outer.pack(fill="both", expand=True)

        self._build_header(outer)

        # Tab row
        tab_row = tk.Frame(outer, bg=C["bg"])
        tab_row.pack(fill="x", pady=(14, 0))

        self.tabs = {}
        self.tab_frames = {}
        self.active_tab = tk.StringVar(value="add")

        for name, icon in [("add","⊕  ADD ENTRY"), ("lookup","⌕  LOOKUP"), ("vault","▤  VAULT")]:
            btn = tk.Label(
                tab_row, text=icon,
                fg=C["accent"] if name == "add" else C["text_muted"],
                bg=C["card"] if name == "add" else C["bg"],
                font=("Courier New", 9, "bold"),
                padx=18, pady=8, cursor="hand2",
                highlightbackground=C["accent"] if name == "add" else C["border"],
                highlightthickness=1,
            )
            btn.pack(side="left", padx=(0, 4))
            btn.bind("<Button-1>", lambda e, n=name: self._switch_tab(n))
            self.tabs[name] = btn

        # Content area
        content = tk.Frame(outer, bg=C["bg"])
        content.pack(fill="both", expand=True, pady=(0, 0))

        self.tab_frames["add"]    = self._build_add_tab(content)
        self.tab_frames["lookup"] = self._build_lookup_tab(content)
        self.tab_frames["vault"]  = self._build_vault_tab(content)

        self._switch_tab("add")

    def _switch_tab(self, name):
        for n, frame in self.tab_frames.items():
            frame.pack_forget()
        self.tab_frames[name].pack(fill="both", expand=True)
        self.active_tab.set(name)
        for n, btn in self.tabs.items():
            if n == name:
                btn.config(fg=C["accent"], bg=C["card"],
                           highlightbackground=C["accent"], highlightthickness=1)
            else:
                btn.config(fg=C["text_muted"], bg=C["bg"],
                           highlightbackground=C["border"], highlightthickness=1)
        if name == "vault":
            self._refresh_vault_list()

    # ── TAB: ADD ENTRY ────────────────────────────────────────────────────────
    def _build_add_tab(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])

        inner = tk.Frame(frame, bg=C["card"],
                         highlightbackground=C["border"], highlightthickness=1)
        inner.pack(fill="both", expand=True, pady=(12, 0))

        # Section title
        title_row = tk.Frame(inner, bg=C["card"], pady=16, padx=28)
        title_row.pack(fill="x")
        tk.Label(title_row, text="ADD NEW CREDENTIAL", fg=C["accent"],
                 bg=C["card"], font=("Courier New", 12, "bold")).pack(side="left")
        tk.Label(title_row, text="Passwords stored as MD5 hash", fg=C["text_muted"],
                 bg=C["card"], font=("Courier New", 8)).pack(side="right", pady=(4,0))

        tk.Frame(inner, bg=C["border"], height=1).pack(fill="x")

        form = tk.Frame(inner, bg=C["card"], padx=28, pady=20)
        form.pack(fill="both", expand=True)
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        # Row 1
        self.add_user = StyledEntry(form, label="Username", placeholder="Enter username")
        self.add_user.grid(row=0, column=0, sticky="ew", padx=(0,12), pady=(0,16))

        self.add_label = StyledEntry(form, label="Label / Site", placeholder="e.g. Gmail, GitHub")
        self.add_label.grid(row=0, column=1, sticky="ew", pady=(0,16))

        # Row 2
        self.add_pass = StyledEntry(form, label="Password", placeholder="Enter password", show="●")
        self.add_pass.grid(row=1, column=0, sticky="ew", padx=(0,12), pady=(0,16))

        self.add_pass2 = StyledEntry(form, label="Confirm Password", placeholder="Repeat password", show="●")
        self.add_pass2.grid(row=1, column=1, sticky="ew", pady=(0,16))

        # Hash preview
        preview_frame = tk.Frame(form, bg=C["input_bg"],
                                  highlightbackground=C["border"], highlightthickness=1)
        preview_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4,16))

        ph_inner = tk.Frame(preview_frame, bg=C["input_bg"], padx=14, pady=10)
        ph_inner.pack(fill="x")
        tk.Label(ph_inner, text="MD5 PREVIEW", fg=C["text_dim"], bg=C["input_bg"],
                 font=("Courier New", 7, "bold")).pack(anchor="w")
        self.hash_preview = tk.Label(ph_inner, text="Type password to preview hash...",
                                      fg=C["text_dim"], bg=C["input_bg"],
                                      font=("Courier New", 10), anchor="w")
        self.hash_preview.pack(fill="x")

        self.add_pass.entry.bind("<KeyRelease>", self._update_hash_preview)

        # Buttons
        btn_row = tk.Frame(form, bg=C["card"])
        btn_row.grid(row=3, column=0, columnspan=2, sticky="ew")
        btn_row.columnconfigure(0, weight=1)
        btn_row.columnconfigure(1, weight=0)
        btn_row.columnconfigure(2, weight=0)

        GoldButton(btn_row, "⊕  STORE CREDENTIAL", command=self._add_entry,
                   variant="primary").grid(row=0, column=1, padx=(0,10))
        GoldButton(btn_row, "↺  CLEAR", command=self._clear_add_form,
                   variant="ghost").grid(row=0, column=2)

        return frame

    def _update_hash_preview(self, e=None):
        pw = self.add_pass.get()
        if pw:
            h = md5_hash(pw)
            # Format with spaces for readability
            formatted = "  ".join([h[i:i+8] for i in range(0, 32, 8)])
            self.hash_preview.config(
                text=f"md5 → {formatted}",
                fg=C["accent2"]
            )
        else:
            self.hash_preview.config(text="Type password to preview hash...", fg=C["text_dim"])

    def _add_entry(self):
        user  = self.add_user.get().strip()
        pw    = self.add_pass.get().strip()
        pw2   = self.add_pass2.get().strip()
        label = self.add_label.get().strip()

        if not user:
            self.toast.show("Username cannot be empty", "error"); return
        if not pw:
            self.toast.show("Password cannot be empty", "error"); return
        if pw != pw2:
            self.toast.show("Passwords do not match", "warning"); return

        entry = add_entry(user, pw, label)
        self.toast.show(f"Credential stored for '{user}'", "success")
        self._clear_add_form()
        self._refresh_vault_list()

    def _clear_add_form(self):
        for w in [self.add_user, self.add_pass, self.add_pass2, self.add_label]:
            w.clear()
        self.hash_preview.config(text="Type password to preview hash...", fg=C["text_dim"])

    # ── TAB: LOOKUP ───────────────────────────────────────────────────────────
    def _build_lookup_tab(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])

        inner = tk.Frame(frame, bg=C["card"],
                         highlightbackground=C["border"], highlightthickness=1)
        inner.pack(fill="both", expand=True, pady=(12, 0))

        title_row = tk.Frame(inner, bg=C["card"], pady=16, padx=28)
        title_row.pack(fill="x")
        tk.Label(title_row, text="CREDENTIAL LOOKUP", fg=C["accent2"],
                 bg=C["card"], font=("Courier New", 12, "bold")).pack(side="left")
        tk.Label(title_row, text="Verify credentials & reveal stored entry",
                 fg=C["text_muted"], bg=C["card"], font=("Courier New", 8)).pack(side="right", pady=(4,0))

        tk.Frame(inner, bg=C["border"], height=1).pack(fill="x")

        form = tk.Frame(inner, bg=C["card"], padx=28, pady=20)
        form.pack(fill="x")
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        self.lkp_user = StyledEntry(form, label="Username", placeholder="Enter username to lookup")
        self.lkp_user.grid(row=0, column=0, sticky="ew", padx=(0,12), pady=(0,16))

        self.lkp_pass = StyledEntry(form, label="Password", placeholder="Enter password to verify", show="●")
        self.lkp_pass.grid(row=0, column=1, sticky="ew", pady=(0,16))

        btn_row = tk.Frame(form, bg=C["card"])
        btn_row.grid(row=1, column=0, columnspan=2, sticky="ew")
        btn_row.columnconfigure(0, weight=1)

        GoldButton(btn_row, "⌕  LOOKUP CREDENTIAL", command=self._lookup,
                   variant="violet").grid(row=0, column=1, padx=(0,10))
        GoldButton(btn_row, "↺  CLEAR", command=self._clear_lookup,
                   variant="ghost").grid(row=0, column=2)

        # Result panel
        result_outer = tk.Frame(inner, bg=C["card"], padx=28, pady=0)
        result_outer.pack(fill="both", expand=True)

        self.result_panel = tk.Frame(result_outer, bg=C["input_bg"],
                                      highlightbackground=C["border"], highlightthickness=1)
        self.result_panel.pack(fill="both", expand=True, pady=(0, 20))

        self.result_placeholder = tk.Label(
            self.result_panel,
            text="◈  Enter credentials above and click Lookup\n\nMatching entry will be revealed here",
            fg=C["text_dim"], bg=C["input_bg"],
            font=("Courier New", 11), justify="center"
        )
        self.result_placeholder.place(relx=0.5, rely=0.5, anchor="center")

        return frame

    def _lookup(self):
        user = self.lkp_user.get().strip()
        pw   = self.lkp_pass.get().strip()
        if not user or not pw:
            self.toast.show("Fill in both fields", "warning"); return

        entry = lookup_entry(user, pw)

        # Clear previous results
        for w in self.result_panel.winfo_children():
            w.destroy()

        if entry:
            self._show_result(entry)
            self.toast.show("Credentials matched! ✦", "success")
        else:
            self._show_no_match()
            self.toast.show("No matching credential found", "error")

    def _show_result(self, entry):
        pad = tk.Frame(self.result_panel, bg=C["input_bg"], padx=24, pady=20)
        pad.pack(fill="both", expand=True)

        tk.Label(pad, text="✦  CREDENTIAL FOUND", fg=C["success"], bg=C["input_bg"],
                 font=("Courier New", 11, "bold")).pack(anchor="w", pady=(0, 14))

        rows = [
            ("USERNAME",       entry["username"],       C["accent"]),
            ("USERNAME HASH",  entry["username_hash"],  C["text_muted"]),
            ("PASSWORD HASH",  entry["password_hash"],  C["text_muted"]),
            ("LABEL / SITE",   entry["label"],          C["accent2"]),
            ("STORED ON",      entry["created"],        C["text_muted"]),
        ]
        for label, value, color in rows:
            row = tk.Frame(pad, bg=C["input_bg"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text=f"{label:<18}", fg=C["text_dim"], bg=C["input_bg"],
                     font=("Courier New", 9, "bold"), width=18, anchor="w").pack(side="left")
            tk.Label(row, text="│", fg=C["border"], bg=C["input_bg"],
                     font=("Courier New", 9)).pack(side="left", padx=8)
            tk.Label(row, text=value, fg=color, bg=C["input_bg"],
                     font=("Courier New", 10)).pack(side="left")

        # Hash breakdown
        tk.Frame(pad, bg=C["border"], height=1).pack(fill="x", pady=12)
        tk.Label(pad, text="HASH SEGMENTS", fg=C["text_dim"], bg=C["input_bg"],
                 font=("Courier New", 8, "bold")).pack(anchor="w")
        seg_row = tk.Frame(pad, bg=C["input_bg"])
        seg_row.pack(anchor="w", pady=(4, 0))
        h = entry["password_hash"]
        for i, seg in enumerate([h[0:8], h[8:16], h[16:24], h[24:32]]):
            tk.Label(seg_row, text=seg, fg=C["accent2"], bg=C["tag_bg"],
                     font=("Courier New", 9), padx=8, pady=4,
                     highlightbackground=C["accent2"], highlightthickness=1
                     ).pack(side="left", padx=(0,4))

    def _show_no_match(self):
        pad = tk.Frame(self.result_panel, bg=C["input_bg"])
        pad.pack(fill="both", expand=True)
        tk.Label(pad, text="✖  NO MATCH FOUND",
                 fg=C["danger"], bg=C["input_bg"],
                 font=("Courier New", 14, "bold"), justify="center").place(relx=0.5, rely=0.4, anchor="center")
        tk.Label(pad, text="The username or password does not match any stored credential.",
                 fg=C["text_muted"], bg=C["input_bg"],
                 font=("Courier New", 9), justify="center").place(relx=0.5, rely=0.55, anchor="center")

    def _clear_lookup(self):
        self.lkp_user.clear()
        self.lkp_pass.clear()
        for w in self.result_panel.winfo_children():
            w.destroy()
        ph = tk.Label(
            self.result_panel,
            text="◈  Enter credentials above and click Lookup\n\nMatching entry will be revealed here",
            fg=C["text_dim"], bg=C["input_bg"],
            font=("Courier New", 11), justify="center"
        )
        ph.place(relx=0.5, rely=0.5, anchor="center")

    # ── TAB: VAULT ────────────────────────────────────────────────────────────
    def _build_vault_tab(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])

        inner = tk.Frame(frame, bg=C["card"],
                         highlightbackground=C["border"], highlightthickness=1)
        inner.pack(fill="both", expand=True, pady=(12, 0))

        title_row = tk.Frame(inner, bg=C["card"], pady=14, padx=24)
        title_row.pack(fill="x")
        tk.Label(title_row, text="VAULT CONTENTS", fg=C["accent"],
                 bg=C["card"], font=("Courier New", 12, "bold")).pack(side="left")
        self.entry_count_lbl = tk.Label(title_row, text="", fg=C["text_muted"],
                                         bg=C["card"], font=("Courier New", 8))
        self.entry_count_lbl.pack(side="left", padx=10, pady=(4,0))

        GoldButton(title_row, "⟳  REFRESH", command=self._refresh_vault_list,
                   variant="ghost").pack(side="right")
        GoldButton(title_row, "✖  DELETE SELECTED", command=self._delete_selected,
                   variant="danger").pack(side="right", padx=8)

        tk.Frame(inner, bg=C["border"], height=1).pack(fill="x")

        # Table header
        hdr = tk.Frame(inner, bg=C["tag_bg"], padx=24, pady=8)
        hdr.pack(fill="x")
        cols = [("#", 3), ("USERNAME", 12), ("LABEL", 10), ("USERNAME HASH", 20), ("PASSWORD HASH", 20), ("CREATED", 14)]
        for col, w in cols:
            tk.Label(hdr, text=col, fg=C["text_muted"], bg=C["tag_bg"],
                     font=("Courier New", 8, "bold"), width=w, anchor="w").pack(side="left", padx=4)

        # Scrollable list
        list_container = tk.Frame(inner, bg=C["card"])
        list_container.pack(fill="both", expand=True)

        canvas = tk.Canvas(list_container, bg=C["card"], highlightthickness=0)
        scrollbar = tk.Scrollbar(list_container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self.vault_frame = tk.Frame(canvas, bg=C["card"])
        self.vault_window = canvas.create_window((0, 0), window=self.vault_frame, anchor="nw")

        self.vault_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
            lambda e: canvas.itemconfig(self.vault_window, width=e.width))
        canvas.bind_all("<MouseWheel>",
            lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        self._canvas = canvas
        self._selected_idx = tk.IntVar(value=-1)

        # DB path bar
        db_bar = tk.Frame(inner, bg=C["input_bg"], padx=24, pady=6)
        db_bar.pack(fill="x")
        tk.Label(db_bar, text=f"◈  Database: {DB_FILE}", fg=C["text_dim"],
                 bg=C["input_bg"], font=("Courier New", 8)).pack(side="left")

        return frame

    def _refresh_vault_list(self):
        for w in self.vault_frame.winfo_children():
            w.destroy()

        entries = load_db()
        self.entry_count_lbl.config(text=f"  {len(entries)} credential{'s' if len(entries)!=1 else ''} stored")
        self._selected_idx.set(-1)
        self._vault_radios = []

        if not entries:
            tk.Label(self.vault_frame, text="\n\n◈  Vault is empty\nAdd credentials using the 'Add Entry' tab",
                     fg=C["text_dim"], bg=C["card"],
                     font=("Courier New", 11), justify="center").pack(expand=True, pady=40)
            return

        for i, e in enumerate(entries):
            row_bg = C["card"] if i % 2 == 0 else C["surface"]
            row = tk.Frame(self.vault_frame, bg=row_bg, padx=24, pady=9,
                           highlightbackground=C["border"], highlightthickness=0)
            row.pack(fill="x")

            # Highlight on hover
            def _enter(ev, r=row, bg=row_bg):
                r.config(bg=C["hover"])
                for child in r.winfo_children(): child.config(bg=C["hover"])
            def _leave(ev, r=row, bg=row_bg):
                r.config(bg=bg)
                for child in r.winfo_children(): child.config(bg=bg)
            row.bind("<Enter>", _enter)
            row.bind("<Leave>", _leave)

            def _select(ev, idx=i, r=row):
                self._selected_idx.set(idx)
                self.toast.show(f"Selected entry #{idx+1}", "info")

            row.bind("<Button-1>", _select)

            rb = tk.Radiobutton(row, variable=self._selected_idx, value=i,
                                 bg=row_bg, activebackground=C["hover"],
                                 selectcolor=C["accent"],
                                 highlightthickness=0, bd=0)
            rb.pack(side="left")
            rb.bind("<Button-1>", _select)
            self._vault_radios.append(rb)

            data = [
                (f"  {i+1}", 4, C["text_dim"]),
                (e["username"],      14, C["accent"]),
                (e["label"],         12, C["accent2"]),
                (e["username_hash"], 22, C["text_muted"]),
                (e["password_hash"], 22, C["text_muted"]),
                (e["created"],       16, C["text_dim"]),
            ]
            for text, w, color in data:
                tk.Label(row, text=text[:w*1], fg=color, bg=row_bg,
                          font=("Courier New", 9), width=w, anchor="w"
                          ).pack(side="left", padx=3)

    def _delete_selected(self):
        idx = self._selected_idx.get()
        if idx < 0:
            self.toast.show("Select an entry to delete", "warning"); return
        entries = load_db()
        if idx >= len(entries):
            self.toast.show("Invalid selection", "error"); return

        name = entries[idx]["username"]
        if messagebox.askyesno(
            "Confirm Delete",
            f"Delete credential for '{name}'?\nThis cannot be undone.",
            parent=self.root
        ):
            delete_entry(idx)
            self.toast.show(f"Deleted entry for '{name}'", "success")
            self._refresh_vault_list()

    # ── RUN ───────────────────────────────────────────────────────────────────
    def run(self):
        self.root.mainloop()


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = VaultApp()
    app.run()
