import tkinter as tk
import os
import random
from cipher import AESCipher, AESCipherPass, DESCipher, DESCipherPass
from utils import PasswordBuilder

cipher_instance = None
cipher_pass_instance = None


def create_cipher_tab(parent, theme):
    frame = tk.Frame(parent, bg=theme['bg'])

    cipher_mode = tk.StringVar(value="AES")

    def update_mode_label():
        selected = cipher_mode.get()
        if selected in ("AES", "DES"):
            label_key.configure(text="Key:")
        else:
            label_key.configure(text="Pass:")

    def set_cipher():
        global cipher_instance, cipher_pass_instance
        key = entry_key.get().strip()
        if not key:
            return
        mode = cipher_mode.get()
        if mode == "AES":
            if len(key.encode()) not in (16, 24, 32):
                return
            cipher_instance = AESCipher(key.encode())
        elif mode == "AES (Pass)":
            cipher_pass_instance = AESCipherPass(key)
        elif mode == "DES":
            cipher_instance = DESCipher(key.encode())
        elif mode == "DES (Pass)":
            cipher_pass_instance = DESCipherPass(key)

    def randomize_key():
        global cipher_instance, cipher_pass_instance
        mode = cipher_mode.get()
        if mode == "AES":
            random_key = os.urandom(random.choice([16, 24, 32]))
            entry_key.delete(0, tk.END)
            entry_key.insert(0, random_key.hex())
            cipher_instance = AESCipher(random_key)
        elif mode == "DES":
            random_key = os.urandom(8)
            entry_key.delete(0, tk.END)
            entry_key.insert(0, random_key.hex())
            cipher_instance = DESCipher(random_key)
        else:
            builder = PasswordBuilder(use_chars=True, use_numbers=True, use_special=True, length=16)
            random_pass = builder.build()
            entry_key.delete(0, tk.END)
            entry_key.insert(0, random_pass)
            if mode == "AES (Pass)":
                cipher_pass_instance = AESCipherPass(random_pass)
            elif mode == "DES (Pass)":
                cipher_pass_instance = DESCipherPass(random_pass)

    def encrypt_text():
        text = input_text.get("1.0", "end-1c").strip()
        if not text:
            return
        mode = cipher_mode.get()
        if mode in ("AES", "DES") and cipher_instance:
            result = cipher_instance.encrypt(text)
        elif mode in ("AES (Pass)", "DES (Pass)") and cipher_pass_instance:
            result = cipher_pass_instance.encrypt(text)
        else:
            result = "Error"
        output_text.delete("1.0", "end")
        output_text.insert("1.0", result)

    def decrypt_text():
        text = input_text.get("1.0", "end-1c").strip()
        if not text:
            return
        mode = cipher_mode.get()
        if mode in ("AES", "DES") and cipher_instance:
            result = cipher_instance.decrypt(text)
        elif mode in ("AES (Pass)", "DES (Pass)") and cipher_pass_instance:
            result = cipher_pass_instance.decrypt(text)
        else:
            result = "Error"
        output_text.delete("1.0", "end")
        output_text.insert("1.0", result)

    def copy_output():
        result = output_text.get("1.0", "end-1c")
        frame.clipboard_clear()
        frame.clipboard_append(result)
        frame.update()

    label_mode = tk.Label(frame, text="Mode:", bg=theme['bg'], fg=theme['fg'])
    label_mode.place(x=10, y=10)

    mode_menu = tk.OptionMenu(frame, cipher_mode, "AES", "AES (Pass)", "DES", "DES (Pass)", command=lambda _: update_mode_label())
    mode_menu.configure(bg=theme['button_bg'], fg=theme['button_fg'])
    mode_menu.place(x=60, y=5)

    label_key = tk.Label(frame, text="Key:", bg=theme['bg'], fg=theme['fg'])
    label_key.place(x=10, y=35)

    entry_key = tk.Entry(frame, width=30, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    entry_key.place(x=60, y=35)

    button_set = tk.Button(frame, text="Set", command=set_cipher, bg=theme['button_bg'], fg=theme['button_fg'], width=7)
    button_set.place(x=290, y=32)

    button_random = tk.Button(frame, text="Random", command=randomize_key, bg=theme['button_bg'], fg=theme['button_fg'], width=7)
    button_random.place(x=360, y=32)

    input_text = tk.Text(frame, width=50, height=3, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    input_text.place(x=10, y=70)

    output_text = tk.Text(frame, width=50, height=3, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    output_text.place(x=10, y=135)

    button_encrypt = tk.Button(frame, text="Encrypt", command=encrypt_text, bg=theme['button_bg'], fg=theme['button_fg'], width=8)
    button_encrypt.place(x=10, y=200)

    button_decrypt = tk.Button(frame, text="Decrypt", command=decrypt_text, bg=theme['button_bg'], fg=theme['button_fg'], width=8)
    button_decrypt.place(x=95, y=200)

    button_copy = tk.Button(frame, text="Copy", command=copy_output, bg=theme['button_bg'], fg=theme['button_fg'], width=8)
    button_copy.place(x=180, y=200)

    return frame