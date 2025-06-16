"""Symmetric cipher panel using AES with password."""

import tkinter as tk
from tkinter import ttk

from core.cipher import (
    AESCipher,
    AESCipherPass,
    DESCipher,
    DESCipherPass,
)


class CipherPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Cipher:").grid(row=0, column=0, padx=10, pady=5)
        self.alg_var = tk.StringVar(value="AESPassword")
        ttk.Combobox(
            self,
            textvariable=self.alg_var,
            values=["DES", "DESPassword", "AES", "AESPassword"],
            state="readonly",
        ).grid(row=0, column=1, columnspan=2, padx=10, sticky="ew")

        ttk.Label(self, text="Password/Key:").grid(row=1, column=0, padx=10, pady=10)
        self.pass_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.pass_var, show="*").grid(row=1, column=1, columnspan=2, sticky="ew")

        ttk.Label(self, text="Input:").grid(row=2, column=0, padx=10, pady=5)

        style = ttk.Style()
        text_bg = style.lookup("TEntry", "fieldbackground")
        text_fg = style.lookup("TEntry", "foreground")

        self.input_text = tk.Text(
            self,
            height=4,
            width=40,
            bg=text_bg,
            fg=text_fg,
            insertbackground=text_fg,
        )
        self.input_text.grid(row=2, column=1, columnspan=2, pady=5, sticky="ew")

        ttk.Label(self, text="Output:").grid(row=3, column=0, padx=10, pady=5)
        self.output_text = tk.Text(
            self,
            height=4,
            width=40,
            bg=text_bg,
            fg=text_fg,
            insertbackground=text_fg,
        )
        self.output_text.grid(row=3, column=1, columnspan=2, pady=5, sticky="ew")

        ttk.Button(self, text="Encrypt", command=self.encrypt).grid(row=4, column=1, pady=5)
        ttk.Button(self, text="Decrypt", command=self.decrypt).grid(row=4, column=2, pady=5)
        self.columnconfigure(2, weight=1)

    def encrypt(self):
        password = self.pass_var.get()
        plaintext = self.input_text.get("1.0", tk.END).strip()
        if password and plaintext:
            cipher_cls = self.get_cipher()
            if cipher_cls in (AESCipher, DESCipher):
                result = cipher_cls.encrypt(plaintext, password.encode())
            else:
                result = cipher_cls.encrypt(plaintext, password)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)

    def decrypt(self):
        password = self.pass_var.get()
        ciphertext = self.input_text.get("1.0", tk.END).strip()
        if password and ciphertext:
            cipher_cls = self.get_cipher()
            if cipher_cls in (AESCipher, DESCipher):
                result = cipher_cls.decrypt(ciphertext, password.encode())
            else:
                result = cipher_cls.decrypt(ciphertext, password)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)

    def get_cipher(self):
        alg = self.alg_var.get()
        if alg == "AES":
            return AESCipher
        if alg == "AESPassword":
            return AESCipherPass
        if alg == "DES":
            return DESCipher
        return DESCipherPass

