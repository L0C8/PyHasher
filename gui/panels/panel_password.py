"""Password generator panel."""

import tkinter as tk
from tkinter import ttk

from core.utils import get_password


class PasswordPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Length:").grid(row=0, column=0, padx=10, pady=10)
        self.length_var = tk.IntVar(value=12)
        ttk.Entry(self, textvariable=self.length_var, width=5).grid(row=0, column=1, pady=10)

        ttk.Button(self, text="Generate", command=self.make_password).grid(row=0, column=2, padx=10)

        self.result = ttk.Entry(self, width=30)
        self.result.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.columnconfigure(2, weight=1)

    def make_password(self):
        length = self.length_var.get()
        pw = get_password(length=length)
        self.result.delete(0, tk.END)
        self.result.insert(0, pw)

