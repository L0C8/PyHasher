# panels/panel_hasher.py
import tkinter as tk
from tkinter import ttk
import hashlib

class HasherPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Enter text to hash:").pack(pady=5)

        self.input_entry = ttk.Entry(self, width=40)
        self.input_entry.pack(pady=5)

        self.result_label = ttk.Label(self, text="Hash will appear here.")
        self.result_label.pack(pady=10)

        ttk.Button(self, text="Hash", command=self.hash_text).pack(pady=5)

    def hash_text(self):
        text = self.input_entry.get()
        if text:
            result = hashlib.sha256(text.encode()).hexdigest()
            self.result_label.config(text=result)
        else:
            self.result_label.config(text="No input provided.")
