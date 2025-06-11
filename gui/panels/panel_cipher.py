"""Symmetric cipher panel using AES with password."""

import tkinter as tk
from tkinter import ttk

from core.cipher import AESCipherPass


class CipherPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Password:").grid(row=0, column=0, padx=10, pady=10)
        self.pass_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.pass_var, show="*").grid(row=0, column=1, columnspan=2, sticky="ew")

        ttk.Label(self, text="Input:").grid(row=1, column=0, padx=10, pady=5)
        self.input_text = tk.Text(self, height=4, width=40)
        self.input_text.grid(row=1, column=1, columnspan=2, pady=5, sticky="ew")

        ttk.Label(self, text="Output:").grid(row=2, column=0, padx=10, pady=5)
        self.output_text = tk.Text(self, height=4, width=40)
        self.output_text.grid(row=2, column=1, columnspan=2, pady=5, sticky="ew")

        ttk.Button(self, text="Encrypt", command=self.encrypt).grid(row=3, column=1, pady=5)
        ttk.Button(self, text="Decrypt", command=self.decrypt).grid(row=3, column=2, pady=5)
        self.columnconfigure(2, weight=1)

    def encrypt(self):
        password = self.pass_var.get()
        plaintext = self.input_text.get("1.0", tk.END).strip()
        if password and plaintext:
            result = AESCipherPass.encrypt(plaintext, password)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)

    def decrypt(self):
        password = self.pass_var.get()
        ciphertext = self.input_text.get("1.0", tk.END).strip()
        if password and ciphertext:
            result = AESCipherPass.decrypt(ciphertext, password)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)

