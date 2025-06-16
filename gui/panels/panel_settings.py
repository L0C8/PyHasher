"""Settings panel with theme selection."""

import tkinter as tk
from tkinter import ttk

from core import utils


class SettingsPanel(ttk.Frame):
    def __init__(self, parent, apply_theme_callback):
        super().__init__(parent)
        self.apply_theme_callback = apply_theme_callback
        self.themes = utils.load_themes()
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Theme:").grid(row=0, column=0, pady=10, padx=10)

        self.theme_var = tk.StringVar(value=list(self.themes.keys())[0])

        # derive combobox colors from current ttk style
        style = ttk.Style()
        dd_bg = style.lookup("TCombobox", "fieldbackground")
        dd_fg = style.lookup("TCombobox", "foreground")

        style.configure(
            "Settings.TCombobox",
            fieldbackground=dd_bg,
            background=dd_bg,
            foreground=dd_fg,
        )
        style.map(
            "Settings.TCombobox",
            fieldbackground=[("readonly", dd_bg)],
            background=[("readonly", dd_bg)],
            foreground=[("readonly", dd_fg)],
        )

        self.theme_combo = ttk.Combobox(
            self,
            textvariable=self.theme_var,
            values=list(self.themes.keys()),
            state="readonly",
            style="Settings.TCombobox",
        )
        self.theme_combo.grid(row=0, column=1, padx=10)

        ttk.Button(self, text="Apply", command=self.change_theme).grid(row=0, column=2, padx=10)

        self.columnconfigure(1, weight=1)

    def change_theme(self):
        theme = self.theme_var.get()
        if theme in self.themes:
            self.apply_theme_callback(self.themes[theme])

