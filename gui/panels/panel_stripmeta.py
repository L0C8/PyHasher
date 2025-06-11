"""Panel to strip metadata from files by copying contents to a new file."""

import os
import tkinter as tk
from tkinter import ttk, filedialog

from core import utils


class StripMetaPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Input File:").grid(row=0, column=0, padx=5, pady=5)
        self.in_entry = ttk.Entry(self, width=40)
        self.in_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(self, text="Select File", command=self.browse_input).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(self, text="Output File:").grid(row=1, column=0, padx=5, pady=5)
        self.out_entry = ttk.Entry(self, width=40)
        self.out_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(self, text="Save As", command=self.browse_output).grid(row=1, column=2, padx=5, pady=5)

        ttk.Button(self, text="Strip Metadata", command=self.strip_metadata).grid(row=2, column=1, pady=10)
        self.status = ttk.Label(self, text="")
        self.status.grid(row=3, column=0, columnspan=3)

        self.columnconfigure(1, weight=1)

    def browse_input(self):
        path = filedialog.askopenfilename()
        if path:
            self.in_entry.delete(0, tk.END)
            self.in_entry.insert(0, path)
            if not self.out_entry.get():
                self.out_entry.insert(0, self.default_output(path))

    def browse_output(self):
        path = filedialog.asksaveasfilename(initialfile="clean_" + os.path.basename(self.in_entry.get()))
        if path:
            self.out_entry.delete(0, tk.END)
            self.out_entry.insert(0, path)

    def default_output(self, src):
        directory = os.path.dirname(src)
        filename = "clean_" + os.path.basename(src)
        return os.path.join(directory, filename)

    def strip_metadata(self):
        src = self.in_entry.get()
        dst = self.out_entry.get()
        if not src or not dst:
            self.status.config(text="Select input and output files")
            return
        try:
            utils.strip_metadata(src, dst)
        except Exception as exc:
            self.status.config(text=f"Error: {exc}")
        else:
            self.status.config(text=f"Saved to {dst}")

