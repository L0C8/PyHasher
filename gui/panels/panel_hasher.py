import tkinter as tk
from tkinter import ttk, filedialog
import hashlib

from core.utils import hash_text, hash_file

class HasherPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):

        ttk.Label(self, text="Hash Method:").grid(row=0, column=0, sticky="w", padx=5, pady=2)

        methods = sorted(hashlib.algorithms_guaranteed)
        self.method_var = tk.StringVar(value="sha256")
        ttk.Combobox(
            self, textvariable=self.method_var, values=methods, state="readonly"
        ).grid(row=0, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(self, text="Enter text to hash:").grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        self.input_entry = ttk.Entry(self, width=54)
        self.input_entry.grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        ttk.Button(self, text="Hash Text", command=self.hash_text).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        ttk.Button(self, text="Hash File", command=self.hash_file_dialog).grid(row=3, column=1, columnspan=2, sticky="w", padx=5, pady=2)

        self.result_box = ttk.Entry(self, width=54)
        self.result_box.grid(row=5, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        ttk.Button(self, text="Copy", command=self.copy_hash).grid(row=6, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        ttk.Button(self, text="Clear", command=self.clear_hash).grid(row=6, column=1, columnspan=2, sticky="w", padx=5, pady=2)


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
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, path)

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

    def clear_hash(self):
        self.display_result("")
