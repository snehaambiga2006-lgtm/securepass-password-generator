"""
gui.py
Tkinter/ttk desktop UI for SecurePass -- sidebar-navigation dashboard layout.

Everything here is local: no network calls, no persistence of generated
passwords, no logging of secrets. See README.md "Security Design" for
the full list of guarantees and limitations.

Layout: a fixed dark sidebar (nav) on the left + a swappable content area
on the right, styled like a typical admin/security dashboard. The GUI
holds zero business logic itself -- it only calls into generator.py,
strength.py, analyzer.py, clipboard.py, and history.py and renders state.
"""

import tkinter as tk
from tkinter import ttk

from . import clipboard, history
from .analyzer import analyze
from .generator import GeneratorError, PRESETS, generate_password, generate_passphrase
from .strength import classify_strength, estimate_entropy_bits

FONT = "Segoe UI"
MONO = "Consolas"

# Sidebar stays a dark, dashboard-style navy in BOTH themes; only the
# content area switches between light and dark. This is what gives it
# the "admin dashboard" look rather than a flat, uniformly-colored app.
LIGHT = {
    "bg": "#f3f5fa", "surface": "#ffffff", "surface_alt": "#eef1f8",
    "text": "#1b2233", "text_muted": "#6b7284", "border": "#e4e8f2",
    "accent": "#4457ee", "accent_text": "#ffffff",
    "sidebar_bg": "#161a2b", "sidebar_text": "#9096ad", "sidebar_text_active": "#ffffff",
    "sidebar_active": "#4457ee", "sidebar_border": "#232841",
    "weak": "#e5484d", "medium": "#f2a93c", "strong": "#2fb673",
}
DARK = {
    "bg": "#0e1017", "surface": "#171a26", "surface_alt": "#1f2333",
    "text": "#e9ebf3", "text_muted": "#8d94a8", "border": "#282d40",
    "accent": "#6478ff", "accent_text": "#ffffff",
    "sidebar_bg": "#0a0c14", "sidebar_text": "#7a8099", "sidebar_text_active": "#ffffff",
    "sidebar_active": "#6478ff", "sidebar_border": "#1c1f2e",
    "weak": "#ff6b6b", "medium": "#ffb84d", "strong": "#3ee08c",
}

NAV_ITEMS = [
    ("dashboard", "\u2302  Dashboard"),
    ("generator", "\U0001F510  Generator"),
    ("passphrase", "\U0001F4DD  Passphrase"),
    ("analyzer", "\U0001F50D  Analyzer"),
    ("lab", "\U0001F9EA  Security Lab"),
    ("history", "\U0001F553  History"),
]


class Toast(tk.Toplevel):
    """Small self-dismissing notification popup, bottom-right corner."""

    def __init__(self, parent, message, palette, duration_ms=1800):
        super().__init__(parent)
        self.overrideredirect(True)
        self.configure(bg=palette["accent"])
        tk.Label(self, text=message, bg=palette["accent"], fg=palette["accent_text"],
                  font=(FONT, 10, "bold"), padx=18, pady=11).pack()
        self.update_idletasks()

        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        w, h = self.winfo_width(), self.winfo_height()
        self.geometry(f"+{px + pw - w - 28}+{py + ph - h - 28}")
        self.after(duration_ms, self.destroy)


class Card(tk.Frame):
    """A bordered, padded 'card' surface -- the base building block of the dashboard."""

    def __init__(self, parent, palette, padx=18, pady=16, **kwargs):
        super().__init__(parent, bg=palette["surface"], highlightthickness=1,
                          highlightbackground=palette["border"], highlightcolor=palette["border"],
                          **kwargs)
        self._inner = tk.Frame(self, bg=palette["surface"])
        self._inner.pack(fill="both", expand=True, padx=padx, pady=pady)

    @property
    def body(self):
        return self._inner


class StatTile(Card):
    """One dashboard KPI tile: icon + big value + caption."""

    def __init__(self, parent, palette, icon, caption, value="—"):
        super().__init__(parent, palette, padx=16, pady=14)
        self.palette = palette
        top = tk.Frame(self.body, bg=palette["surface"])
        top.pack(fill="x")
        tk.Label(top, text=icon, bg=palette["surface"], font=(FONT, 16)).pack(side="left")
        self.value_var = tk.StringVar(value=value)
        tk.Label(self.body, textvariable=self.value_var, bg=palette["surface"],
                  fg=palette["text"], font=(FONT, 22, "bold")).pack(anchor="w", pady=(8, 0))
        tk.Label(self.body, text=caption, bg=palette["surface"],
                  fg=palette["text_muted"], font=(FONT, 9)).pack(anchor="w")

    def set_value(self, value):
        self.value_var.set(value)


class SecurePassApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecurePass — Local Password Security Dashboard")
        self.geometry("1120x720")
        self.minsize(980, 640)

        self.dark_mode = tk.BooleanVar(value=False)
        self.palette = LIGHT
        self.history = history.SessionHistory(max_items=5)
        self.nav_buttons = {}
        self.pages = {}
        self.active_page = "dashboard"

        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self._build_root_layout()
        self._build_sidebar()
        self._build_content_area()
        self._bind_shortcuts()
        self._apply_palette()
        self._show_page("dashboard")

    # ----------------------------------------------------------- layout --

    def _build_root_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

    def _build_sidebar(self):
        self.sidebar = tk.Frame(self, width=232)
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_propagate(False)

        brand = tk.Frame(self.sidebar)
        brand.pack(fill="x", padx=20, pady=(26, 30))
        self.brand_title = tk.Label(brand, text="\U0001F510 SecurePass", font=(FONT, 15, "bold"))
        self.brand_title.pack(anchor="w")
        self.brand_sub = tk.Label(brand, text="Local security toolkit", font=(FONT, 9))
        self.brand_sub.pack(anchor="w", pady=(2, 0))

        self.nav_frame = tk.Frame(self.sidebar)
        self.nav_frame.pack(fill="x")
        for key, label in NAV_ITEMS:
            btn = tk.Label(self.nav_frame, text=label, font=(FONT, 11), anchor="w",
                            padx=20, pady=11, cursor="hand2")
            btn.pack(fill="x")
            btn.bind("<Button-1>", lambda e, k=key: self._show_page(k))
            self.nav_buttons[key] = btn

        bottom = tk.Frame(self.sidebar)
        bottom.pack(fill="x", side="bottom", padx=20, pady=20)
        self.theme_btn = tk.Label(bottom, text="\U0001F313  Toggle theme", font=(FONT, 10),
                                    cursor="hand2", padx=6, pady=8)
        self.theme_btn.pack(fill="x")
        self.theme_btn.bind("<Button-1>", lambda e: self.toggle_theme())
        tk.Label(bottom, text="100% offline · v1.0", font=(FONT, 8)).pack(anchor="w", pady=(6, 0))

    def _build_content_area(self):
        self.content = tk.Frame(self)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        for key, _ in NAV_ITEMS:
            page = tk.Frame(self.content)
            page.grid(row=0, column=0, sticky="nsew")
            self.pages[key] = page

        self._build_dashboard_page(self.pages["dashboard"])
        self._build_generator_page(self.pages["generator"])
        self._build_passphrase_page(self.pages["passphrase"])
        self._build_analyzer_page(self.pages["analyzer"])
        self._build_lab_page(self.pages["lab"])
        self._build_history_page(self.pages["history"])

    def _show_page(self, key):
        self.active_page = key
        self.pages[key].tkraise()
        for k, btn in self.nav_buttons.items():
            active = (k == key)
            btn.configure(
                bg=self.palette["sidebar_active"] if active else self.palette["sidebar_bg"],
                fg=self.palette["sidebar_text_active"] if active else self.palette["sidebar_text"],
                font=(FONT, 11, "bold" if active else "normal"),
            )

    # ---------------------------------------------------------- theming --

    def _apply_palette(self):
        p = DARK if self.dark_mode.get() else LIGHT
        self.palette = p
        self.configure(bg=p["bg"])

        self.sidebar.configure(bg=p["sidebar_bg"])
        self.nav_frame.configure(bg=p["sidebar_bg"])
        for w in (self.brand_title, self.brand_sub, self.theme_btn):
            pass
        self.brand_title.configure(bg=p["sidebar_bg"], fg=p["sidebar_text_active"])
        self.brand_sub.configure(bg=p["sidebar_bg"], fg=p["sidebar_text"])
        self.theme_btn.configure(bg=p["sidebar_bg"], fg=p["sidebar_text"])
        for child in self.sidebar.winfo_children():
            child.configure(bg=p["sidebar_bg"]) if isinstance(child, tk.Frame) else None
        for f in self.sidebar.winfo_children():
            if isinstance(f, tk.Frame):
                f.configure(bg=p["sidebar_bg"])
                for gc in f.winfo_children():
                    if isinstance(gc, tk.Label) and gc not in self.nav_buttons.values():
                        gc.configure(bg=p["sidebar_bg"])

        self.content.configure(bg=p["bg"])
        for page in self.pages.values():
            page.configure(bg=p["bg"])

        self.style.configure("TFrame", background=p["bg"])
        self.style.configure("TLabel", background=p["bg"], foreground=p["text"], font=(FONT, 10))
        self.style.configure("TButton", font=(FONT, 10), padding=8)
        self.style.configure("Accent.TButton", font=(FONT, 10, "bold"), padding=9)
        self.style.map("Accent.TButton",
                        background=[("!disabled", p["accent"])],
                        foreground=[("!disabled", p["accent_text"])])
        self.style.configure("TCheckbutton", background=p["surface"], foreground=p["text"], font=(FONT, 10))
        self.style.configure("TEntry", font=(FONT, 10))
        self.style.configure("TSpinbox", font=(FONT, 10))
        self.style.configure("TCombobox", font=(FONT, 10))
        self.style.configure("Strength.Horizontal.TProgressbar", troughcolor=p["surface_alt"],
                              background=p["strong"], bordercolor=p["surface"],
                              lightcolor=p["strong"], darkcolor=p["strong"])

        self._repaint_deep(self.content, p)
        self._show_page(self.active_page)

    def _repaint_deep(self, widget, p):
        """Recolor plain tk widgets (Card/StatTile/Text/Listbox) that ttk.Style can't reach."""
        for child in widget.winfo_children():
            if isinstance(child, Card):
                child.configure(bg=p["surface"], highlightbackground=p["border"], highlightcolor=p["border"])
                child.body.configure(bg=p["surface"])
                self._repaint_surface_labels(child.body, p)
            elif isinstance(child, tk.Frame):
                child.configure(bg=p["bg"])
            elif isinstance(child, tk.Text):
                child.configure(bg=p["surface_alt"], fg=p["text"], insertbackground=p["text"], relief="flat")
            elif isinstance(child, tk.Listbox):
                child.configure(bg=p["surface_alt"], fg=p["text"], selectbackground=p["accent"], relief="flat")
            elif isinstance(child, tk.Label):
                child.configure(bg=p["bg"])
            self._repaint_deep(child, p)

    def _repaint_surface_labels(self, widget, p):
        for child in widget.winfo_children():
            if isinstance(child, tk.Label):
                child.configure(bg=p["surface"])
                if child.cget("fg") not in (p["weak"], p["medium"], p["strong"]):
                    pass
            elif isinstance(child, tk.Frame):
                child.configure(bg=p["surface"])
            self._repaint_surface_labels(child, p)

    def toggle_theme(self):
        self.dark_mode.set(not self.dark_mode.get())
        self._apply_palette()

    # --------------------------------------------------------- dashboard --

    def _build_dashboard_page(self, page):
        wrap = tk.Frame(page)
        wrap.pack(fill="both", expand=True, padx=28, pady=26)

        header = tk.Frame(wrap)
        header.pack(fill="x")
        tk.Label(header, text="Dashboard", font=(FONT, 20, "bold")).pack(anchor="w")
        tk.Label(header, text="Session overview — nothing here is ever written to disk.",
                  font=(FONT, 10)).pack(anchor="w", pady=(2, 18))

        tiles_row = tk.Frame(wrap)
        tiles_row.pack(fill="x")
        for i in range(4):
            tiles_row.grid_columnconfigure(i, weight=1, uniform="tile")

        self.tile_generated = StatTile(tiles_row, self.palette, "\u26A1", "Generated this session", "0")
        self.tile_last_strength = StatTile(tiles_row, self.palette, "\U0001F6E1", "Last strength", "—")
        self.tile_history = StatTile(tiles_row, self.palette, "\U0001F553", "In history", "0 / 5")
        self.tile_avg_len = StatTile(tiles_row, self.palette, "\U0001F4CF", "Avg length (history)", "—")
        for i, tile in enumerate([self.tile_generated, self.tile_last_strength,
                                    self.tile_history, self.tile_avg_len]):
            tile.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))

        body = tk.Frame(wrap)
        body.pack(fill="both", expand=True, pady=(22, 0))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        quick = Card(body, self.palette)
        quick.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        tk.Label(quick.body, text="Quick Generate", font=(FONT, 13, "bold"),
                  bg=self.palette["surface"]).pack(anchor="w")
        tk.Label(quick.body, text="One click, Strong preset, auto-copied to clipboard.",
                  font=(FONT, 9), bg=self.palette["surface"]).pack(anchor="w", pady=(2, 14))

        self.quick_pwd_var = tk.StringVar(value="Click Generate to create a password")
        quick_display = tk.Entry(quick.body, textvariable=self.quick_pwd_var, font=(MONO, 13, "bold"),
                                   state="readonly", relief="flat", readonlybackground=self.palette["surface_alt"])
        quick_display.pack(fill="x", ipady=8)

        self.quick_strength_var = tk.StringVar(value="")
        tk.Label(quick.body, textvariable=self.quick_strength_var, font=(FONT, 9),
                  bg=self.palette["surface"]).pack(anchor="w", pady=(8, 14))

        btn_row = tk.Frame(quick.body, bg=self.palette["surface"])
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="\u26A1 Generate", style="Accent.TButton",
                   command=self.on_quick_generate).pack(side="left")
        ttk.Button(btn_row, text="\U0001F4CB Copy", command=self.on_quick_copy).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Open full Generator \u2192",
                   command=lambda: self._show_page("generator")).pack(side="right")

        recent = Card(body, self.palette)
        recent.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        rec_header = tk.Frame(recent.body, bg=self.palette["surface"])
        rec_header.pack(fill="x")
        tk.Label(rec_header, text="Recent Activity", font=(FONT, 13, "bold"),
                  bg=self.palette["surface"]).pack(side="left")
        ttk.Button(rec_header, text="View all \u2192",
                   command=lambda: self._show_page("history")).pack(side="right")

        self.recent_list_frame = tk.Frame(recent.body, bg=self.palette["surface"])
        self.recent_list_frame.pack(fill="both", expand=True, pady=(12, 0))
        self._render_recent_activity()

    def _render_recent_activity(self):
        for child in self.recent_list_frame.winfo_children():
            child.destroy()
        items = self.history.all()[:5]
        if not items:
            tk.Label(self.recent_list_frame, text="Nothing generated yet this session.",
                      font=(FONT, 9), bg=self.palette["surface"],
                      fg=self.palette["text_muted"]).pack(anchor="w", pady=6)
            return
        color_map = {"Weak": self.palette["weak"], "Medium": self.palette["medium"], "Strong": self.palette["strong"]}
        for item in items:
            row = tk.Frame(self.recent_list_frame, bg=self.palette["surface"])
            row.pack(fill="x", pady=4)
            dot = tk.Label(row, text="\u25CF", fg=color_map.get(item["strength"], self.palette["text_muted"]),
                            bg=self.palette["surface"], font=(FONT, 10))
            dot.pack(side="left")
            masked = item["password"][:3] + "•" * max(0, item["length"] - 3)
            tk.Label(row, text=f"{masked}   ({item['strength']}, {item['length']} chars) — {item['timestamp']}",
                      font=(MONO, 9), bg=self.palette["surface"], fg=self.palette["text"]).pack(side="left", padx=6)

    def on_quick_generate(self):
        cfg = PRESETS["Strong"]
        try:
            pwd = generate_password(**cfg)
        except GeneratorError as e:
            self._toast(str(e))
            return
        self.quick_pwd_var.set(pwd)
        label, score = classify_strength(pwd)
        self.quick_strength_var.set(f"Strength: {label} ({score}/100)  ·  ~{estimate_entropy_bits(pwd):.1f} bits")
        self.history.add(pwd, label)
        self._refresh_dashboard()
        self._refresh_history_list()
        try:
            clipboard.copy_to_clipboard(pwd)
            self._toast("Generated & copied to clipboard")
        except RuntimeError:
            self._toast("Generated (clipboard unavailable)")

    def on_quick_copy(self):
        pwd = self.quick_pwd_var.get()
        if not pwd or pwd.startswith("Click Generate"):
            self._toast("Nothing to copy yet")
            return
        try:
            clipboard.copy_to_clipboard(pwd)
            self._toast("Copied to clipboard")
        except RuntimeError:
            self._toast("pyperclip not available")

    def _refresh_dashboard(self):
        s = self.history.stats()
        self.tile_generated.set_value(str(s["total_generated_this_session"]))
        self.tile_history.set_value(f"{s['retained_in_history']} / 5")
        self.tile_avg_len.set_value(str(s["average_length_in_history"]) if s["retained_in_history"] else "—")
        items = self.history.all()
        if items:
            self.tile_last_strength.set_value(items[0]["strength"])
        self._render_recent_activity()

    # --------------------------------------------------------- generator --

    def _build_generator_page(self, page):
        wrap = tk.Frame(page)
        wrap.pack(fill="both", expand=True, padx=28, pady=26)
        tk.Label(wrap, text="Password Generator", font=(FONT, 20, "bold")).pack(anchor="w")
        tk.Label(wrap, text="secrets-backed, type-guaranteed, locally generated.",
                  font=(FONT, 10)).pack(anchor="w", pady=(2, 18))

        body = tk.Frame(wrap)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        settings = Card(body, self.palette)
        settings.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        s = settings.body
        tk.Label(s, text="Settings", font=(FONT, 13, "bold"), bg=self.palette["surface"]).pack(anchor="w")

        preset_row = tk.Frame(s, bg=self.palette["surface"])
        preset_row.pack(fill="x", pady=(14, 8))
        tk.Label(preset_row, text="Preset", bg=self.palette["surface"]).pack(side="left")
        self.preset_var = tk.StringVar(value="Strong")
        preset_combo = ttk.Combobox(preset_row, textvariable=self.preset_var, state="readonly",
                                     values=["Custom", "Basic", "Strong", "Maximum"], width=12)
        preset_combo.pack(side="left", padx=8)
        preset_combo.bind("<<ComboboxSelected>>", self._apply_preset)

        len_row = tk.Frame(s, bg=self.palette["surface"])
        len_row.pack(fill="x", pady=8)
        tk.Label(len_row, text="Length", bg=self.palette["surface"]).pack(side="left")
        self.length_var = tk.IntVar(value=16)
        ttk.Spinbox(len_row, from_=8, to=128, textvariable=self.length_var, width=6,
                    command=self._mark_custom).pack(side="left", padx=8)
        self.length_scale = ttk.Scale(len_row, from_=8, to=128, orient="horizontal",
                                       command=lambda v: (self.length_var.set(int(float(v))), self._mark_custom()))
        self.length_scale.set(16)
        self.length_scale.pack(side="left", fill="x", expand=True, padx=8)

        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=True)

        for label, var in [("Uppercase (A-Z)", self.use_upper), ("Lowercase (a-z)", self.use_lower),
                            ("Numbers (0-9)", self.use_digits), ("Symbols (!@#...)", self.use_symbols)]:
            ttk.Checkbutton(s, text=label, variable=var, command=self._mark_custom).pack(anchor="w", pady=2)
        ttk.Checkbutton(s, text="Exclude ambiguous characters (0 O l 1 I)",
                         variable=self.exclude_ambiguous, command=self._mark_custom).pack(anchor="w", pady=(2, 12))

        tk.Label(s, text="Custom symbol set (optional)", bg=self.palette["surface"]).pack(anchor="w")
        self.custom_symbols_var = tk.StringVar(value="")
        symbols_entry = ttk.Entry(s, textvariable=self.custom_symbols_var)
        symbols_entry.pack(fill="x", pady=(4, 14))
        symbols_entry.bind("<KeyRelease>", lambda e: self._mark_custom())

        ttk.Button(s, text="Generate Password  (Ctrl+G)", style="Accent.TButton",
                   command=self.on_generate_password).pack(fill="x")

        output = Card(body, self.palette)
        output.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        o = output.body
        tk.Label(o, text="Result", font=(FONT, 13, "bold"), bg=self.palette["surface"]).pack(anchor="w")

        self.password_display_var = tk.StringVar(value="")
        self.password_entry = ttk.Entry(o, textvariable=self.password_display_var,
                                          font=(MONO, 15, "bold"), show="•")
        self.password_entry.pack(fill="x", pady=(14, 8), ipady=8)

        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(o, text="Show password", variable=self.show_password,
                         command=self._toggle_visibility).pack(anchor="w", pady=(2, 14))

        btn_row = tk.Frame(o, bg=self.palette["surface"])
        btn_row.pack(fill="x", pady=(0, 18))
        ttk.Button(btn_row, text="\U0001F4CB Copy  (Ctrl+Shift+C)", command=self.on_copy_password).pack(side="left")
        ttk.Button(btn_row, text="\U0001F9F9 Clear Clipboard", command=self.on_clear_clipboard).pack(side="left", padx=8)

        tk.Label(o, text="Strength", font=(FONT, 11, "bold"), bg=self.palette["surface"]).pack(anchor="w", pady=(4, 4))
        self.strength_label_var = tk.StringVar(value="—")
        tk.Label(o, textvariable=self.strength_label_var, bg=self.palette["surface"]).pack(anchor="w")
        self.strength_bar = ttk.Progressbar(o, style="Strength.Horizontal.TProgressbar", maximum=100, value=0)
        self.strength_bar.pack(fill="x", pady=(8, 4))
        self.entropy_label_var = tk.StringVar(value="Entropy: —")
        tk.Label(o, textvariable=self.entropy_label_var, font=(FONT, 9),
                  fg=self.palette["text_muted"], bg=self.palette["surface"]).pack(anchor="w")

    def _mark_custom(self):
        self.preset_var.set("Custom")

    def _apply_preset(self, event=None):
        name = self.preset_var.get()
        if name not in PRESETS:
            return
        cfg = PRESETS[name]
        self.length_var.set(cfg["length"])
        self.length_scale.set(cfg["length"])
        self.use_upper.set(cfg["use_upper"])
        self.use_lower.set(cfg["use_lower"])
        self.use_digits.set(cfg["use_digits"])
        self.use_symbols.set(cfg["use_symbols"])
        self.exclude_ambiguous.set(cfg["exclude_ambiguous"])

    def _toggle_visibility(self):
        self.password_entry.configure(show="" if self.show_password.get() else "•")

    def on_generate_password(self):
        try:
            pwd = generate_password(
                length=self.length_var.get(), use_upper=self.use_upper.get(),
                use_lower=self.use_lower.get(), use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(), exclude_ambiguous=self.exclude_ambiguous.get(),
                custom_symbols=self.custom_symbols_var.get() or None,
            )
        except GeneratorError as e:
            self._toast(str(e))
            return

        self.password_display_var.set(pwd)
        label, score = classify_strength(pwd)
        self.strength_label_var.set(f"{label}  ({score}/100)")
        self.strength_bar.configure(value=score)
        color = {"Weak": self.palette["weak"], "Medium": self.palette["medium"],
                 "Strong": self.palette["strong"]}.get(label, self.palette["strong"])
        self.style.configure("Strength.Horizontal.TProgressbar", background=color, lightcolor=color, darkcolor=color)
        self.entropy_label_var.set(f"Entropy: ~{estimate_entropy_bits(pwd):.1f} bits")

        self.history.add(pwd, label)
        self._refresh_dashboard()
        self._refresh_history_list()
        self._refresh_lab(pwd, label, score)

        try:
            clipboard.copy_to_clipboard(pwd)
            self._toast("Password generated & copied")
        except RuntimeError:
            self._toast("Generated (clipboard unavailable)")

    def on_copy_password(self):
        pwd = self.password_display_var.get()
        if not pwd:
            self._toast("Nothing to copy yet")
            return
        try:
            clipboard.copy_to_clipboard(pwd)
            self._toast("Copied to clipboard")
        except RuntimeError:
            self._toast("pyperclip not available")

    def on_clear_clipboard(self):
        clipboard.clear_clipboard()
        self._toast("Clipboard cleared (best effort)")

    # --------------------------------------------------------- passphrase --

    def _build_passphrase_page(self, page):
        wrap = tk.Frame(page)
        wrap.pack(fill="both", expand=True, padx=28, pady=26)
        tk.Label(wrap, text="Passphrase Generator", font=(FONT, 20, "bold")).pack(anchor="w")
        tk.Label(wrap, text="Diceware-style, word-based, easy to remember.",
                  font=(FONT, 10)).pack(anchor="w", pady=(2, 18))

        body = tk.Frame(wrap)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        settings = Card(body, self.palette)
        settings.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        s = settings.body
        tk.Label(s, text="Settings", font=(FONT, 13, "bold"), bg=self.palette["surface"]).pack(anchor="w")

        row = tk.Frame(s, bg=self.palette["surface"])
        row.pack(fill="x", pady=(14, 8))
        tk.Label(row, text="Word count", bg=self.palette["surface"]).pack(side="left")
        self.word_count_var = tk.IntVar(value=4)
        ttk.Spinbox(row, from_=2, to=12, textvariable=self.word_count_var, width=6).pack(side="left", padx=8)

        row2 = tk.Frame(s, bg=self.palette["surface"])
        row2.pack(fill="x", pady=8)
        tk.Label(row2, text="Separator", bg=self.palette["surface"]).pack(side="left")
        self.separator_var = tk.StringVar(value="-")
        ttk.Entry(row2, textvariable=self.separator_var, width=6).pack(side="left", padx=8)

        self.capitalize_var = tk.BooleanVar(value=True)
        self.include_number_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(s, text="Capitalize each word", variable=self.capitalize_var).pack(anchor="w", pady=2)
        ttk.Checkbutton(s, text="Include a random number", variable=self.include_number_var).pack(anchor="w", pady=2)

        ttk.Button(s, text="Generate Passphrase", style="Accent.TButton",
                   command=self.on_generate_passphrase).pack(fill="x", pady=(16, 0))

        output = Card(body, self.palette)
        output.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        o = output.body
        tk.Label(o, text="Result", font=(FONT, 13, "bold"), bg=self.palette["surface"]).pack(anchor="w")

        self.passphrase_var = tk.StringVar(value="")
        entry = ttk.Entry(o, textvariable=self.passphrase_var, font=(MONO, 14, "bold"))
        entry.pack(fill="x", pady=(14, 10), ipady=8)
        ttk.Button(o, text="\U0001F4CB Copy Passphrase", command=self.on_copy_passphrase).pack(anchor="w")

    def on_generate_passphrase(self):
        try:
            phrase = generate_passphrase(
                word_count=self.word_count_var.get(), separator=self.separator_var.get() or "-",
                capitalize=self.capitalize_var.get(), include_number=self.include_number_var.get(),
            )
        except GeneratorError as e:
            self._toast(str(e))
            return

        self.passphrase_var.set(phrase)
        label, score = classify_strength(phrase)
        self.history.add(phrase, label)
        self._refresh_dashboard()
        self._refresh_history_list()
        self._refresh_lab(phrase, label, score)
        self._toast("Passphrase generated")

    def on_copy_passphrase(self):
        phrase = self.passphrase_var.get()
        if not phrase:
            self._toast("Nothing to copy yet")
            return
        try:
            clipboard.copy_to_clipboard(phrase)
            self._toast("Copied to clipboard")
        except RuntimeError:
            self._toast("pyperclip not available")

    # ----------------------------------------------------------- analyzer --

    def _build_analyzer_page(self, page):
        wrap = tk.Frame(page)
        wrap.pack(fill="both", expand=True, padx=28, pady=26)
        tk.Label(wrap, text="Password Analyzer", font=(FONT, 20, "bold")).pack(anchor="w")
        tk.Label(wrap, text="100% local — nothing you type here ever leaves this app.",
                  font=(FONT, 10)).pack(anchor="w", pady=(2, 18))

        card = Card(wrap, self.palette)
        card.pack(fill="both", expand=True)
        c = card.body

        row = tk.Frame(c, bg=self.palette["surface"])
        row.pack(fill="x")
        self.analyze_input_var = tk.StringVar(value="")
        self.analyze_entry = ttk.Entry(row, textvariable=self.analyze_input_var, font=(MONO, 13), show="•")
        self.analyze_entry.pack(side="left", fill="x", expand=True, ipady=8)

        self.analyze_show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(c, text="Show characters", variable=self.analyze_show_var,
                         command=lambda: self.analyze_entry.configure(
                             show="" if self.analyze_show_var.get() else "•")).pack(anchor="w", pady=(8, 0))

        ttk.Button(c, text="Analyze", style="Accent.TButton", command=self.on_analyze).pack(anchor="w", pady=14)

        self.analysis_text = tk.Text(c, height=14, wrap="word", relief="flat", font=(MONO, 10), bd=0)
        self.analysis_text.pack(fill="both", expand=True)
        self.analysis_text.configure(state="disabled")

    def on_analyze(self):
        result = analyze(self.analyze_input_var.get())
        self.analysis_text.configure(state="normal")
        self.analysis_text.delete("1.0", "end")

        if "error" in result:
            self.analysis_text.insert("end", result["error"])
        else:
            lines = [
                f"Length:              {result['length']}",
                f"Has uppercase:       {result['has_upper']}",
                f"Has lowercase:       {result['has_lower']}",
                f"Has digit:           {result['has_digit']}",
                f"Has symbol:          {result['has_symbol']}",
                f"Unique characters:   {result['unique_chars']}",
                f"Estimated entropy:   {result['entropy_bits']} bits",
                f"Strength:            {result['strength_label']} ({result['score']}/100)",
                "",
                "Warnings:" if result["warnings"] else "No warnings.",
            ]
            lines += [f"  • {w}" for w in result["warnings"]]
            self.analysis_text.insert("end", "\n".join(lines))
            self._refresh_lab_from_dict(result)

        self.analysis_text.configure(state="disabled")

    # ---------------------------------------------------------------- lab --

    def _build_lab_page(self, page):
        wrap = tk.Frame(page)
        wrap.pack(fill="both", expand=True, padx=28, pady=26)
        tk.Label(wrap, text="Security Lab", font=(FONT, 20, "bold")).pack(anchor="w")
        tk.Label(wrap, text="Metrics for the most recently generated or analyzed value.",
                  font=(FONT, 10)).pack(anchor="w", pady=(2, 18))

        card = Card(wrap, self.palette)
        card.pack(fill="both", expand=True)
        c = card.body

        self.lab_vars = {
            "length": tk.StringVar(value="Length: —"),
            "entropy": tk.StringVar(value="Entropy: —"),
            "diversity": tk.StringVar(value="Character diversity: —"),
            "score": tk.StringVar(value="Security score: —"),
        }
        for key in ["length", "entropy", "diversity", "score"]:
            tk.Label(c, textvariable=self.lab_vars[key], bg=self.palette["surface"],
                      font=(FONT, 12)).pack(anchor="w", pady=5)

        tk.Label(c, text="Session Statistics", font=(FONT, 13, "bold"),
                  bg=self.palette["surface"]).pack(anchor="w", pady=(20, 8))
        self.stats_var = tk.StringVar(value="Generate a password to see session stats.")
        tk.Label(c, textvariable=self.stats_var, bg=self.palette["surface"], justify="left").pack(anchor="w")

        tk.Label(c, text="This score is a local heuristic, not a guarantee of real-world "
                          "uncrackability. It does not check breach databases.",
                  font=(FONT, 9), fg=self.palette["text_muted"], bg=self.palette["surface"],
                  wraplength=760, justify="left").pack(anchor="w", pady=(20, 0))

    def _refresh_lab(self, value, label, score):
        self.lab_vars["length"].set(f"Length: {len(value)}")
        self.lab_vars["entropy"].set(f"Entropy: ~{estimate_entropy_bits(value):.1f} bits")
        self.lab_vars["diversity"].set(f"Character diversity: {len(set(value))} unique / {len(value)} total")
        self.lab_vars["score"].set(f"Security score: {label} ({score}/100)")
        self._refresh_stats()

    def _refresh_lab_from_dict(self, result):
        self.lab_vars["length"].set(f"Length: {result['length']}")
        self.lab_vars["entropy"].set(f"Entropy: ~{result['entropy_bits']} bits")
        self.lab_vars["diversity"].set(f"Character diversity: {result['unique_chars']} unique / {result['length']} total")
        self.lab_vars["score"].set(f"Security score: {result['strength_label']} ({result['score']}/100)")

    def _refresh_stats(self):
        s = self.history.stats()
        text = (f"Generated this session: {s['total_generated_this_session']}\n"
                f"Retained in history:    {s['retained_in_history']} / 5\n"
                f"Avg length (history):   {s['average_length_in_history']}\n"
                f"Strength breakdown:     {s['strength_breakdown']}")
        self.stats_var.set(text)

    # ------------------------------------------------------------ history --

    def _build_history_page(self, page):
        wrap = tk.Frame(page)
        wrap.pack(fill="both", expand=True, padx=28, pady=26)

        header = tk.Frame(wrap)
        header.pack(fill="x")
        tk.Label(header, text="History", font=(FONT, 20, "bold")).pack(side="left")
        ttk.Button(header, text="Clear History", command=self.on_clear_history).pack(side="right")

        tk.Label(wrap, text="Last 5 generated values, session memory only — never written to disk.",
                  font=(FONT, 10)).pack(anchor="w", pady=(2, 18))

        card = Card(wrap, self.palette)
        card.pack(fill="both", expand=True)
        self.history_list = tk.Listbox(card.body, font=(MONO, 11), relief="flat", height=12,
                                         bg=self.palette["surface_alt"])
        self.history_list.pack(fill="both", expand=True)

    def _refresh_history_list(self):
        self.history_list.delete(0, "end")
        for item in self.history.all():
            self.history_list.insert("end", f"[{item['timestamp']}]  {item['password']}   —  {item['strength']}")

    def on_clear_history(self):
        self.history.clear()
        self._refresh_history_list()
        self._refresh_dashboard()
        self._toast("History cleared")

    # ------------------------------------------------------------- misc --

    def _bind_shortcuts(self):
        self.bind_all("<Control-g>", lambda e: self.on_generate_password())
        self.bind_all("<Control-G>", lambda e: self.on_generate_password())
        self.bind_all("<Control-Shift-C>", lambda e: self.on_copy_password())
        self.bind_all("<Control-Shift-c>", lambda e: self.on_copy_password())
        self.bind_all("<Control-Key-1>", lambda e: self._show_page("dashboard"))
        self.bind_all("<Control-Key-2>", lambda e: self._show_page("generator"))
        self.bind_all("<Control-Key-3>", lambda e: self._show_page("passphrase"))

    def _toast(self, message):
        Toast(self, message, self.palette)

    def on_close(self):
        clipboard.clear_clipboard()
        self.destroy()


def run():
    app = SecurePassApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
