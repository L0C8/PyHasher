# panels/panel_hasher.py
import tkinter as tk
from tkinter import ttk, filedialog
import hashlib

from core.utils import hash_text, hash_file

class HasherPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Hash Method:").pack(pady=5)

        methods = sorted(hashlib.algorithms_guaranteed)
        self.method_var = tk.StringVar(value="sha256")
        ttk.Combobox(
            self, textvariable=self.method_var, values=methods, state="readonly"
        ).pack(pady=5)

        ttk.Label(self, text="Enter text to hash:").pack(pady=5)

        self.input_entry = ttk.Entry(self, width=40)
        self.input_entry.pack(pady=5)

        ttk.Button(self, text="Hash Text", command=self.hash_text).pack(pady=5)

        ttk.Button(self, text="Hash File", command=self.hash_file_dialog).pack(pady=5)

        self.result_box = ttk.Entry(self, width=64)
        self.result_box.pack(pady=10, fill="x", padx=5)

        ttk.Button(self, text="Copy", command=self.copy_hash).pack(pady=5)

    def hash_text(self):
        text = self.input_entry.get()
        method = self.method_var.get()
        if text:
            result = hash_text(text, method)
            self.display_result(result)
        else:
            self.display_result("No input provided.")

    def hash_file_dialog(self):
        path = filedialog.askopenfilename()
        if path:
            method = self.method_var.get()
            try:
                result = hash_file(path, method)
            except Exception as exc:
                result = str(exc)
            self.display_result(result)

    def display_result(self, text):
        self.result_box.delete(0, tk.END)
        self.result_box.insert(0, text)

    def copy_hash(self):
        result = self.result_box.get()
        if result:
            self.clipboard_clear()
            self.clipboard_append(result)
