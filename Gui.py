import os
import tkinter as tk
from tkinter import ttk, filedialog
import customtkinter

from Cipher import (
    str_2_md5,
    str_2_sha1,
    str_2_sha256,
    file_2_md5,
    file_2_sha1,
    file_2_sha256,
    AESCipher,
)


customtkinter.set_appearance_mode("System")


# ---------------------- Hashing functions ----------------------

def hash_text(event=None):
    """Hash the contents of the input box."""
    text = input_box.get()

    if file_mode.get():
        if not os.path.isfile(text):
            output_box.delete(0, tk.END)
            output_box.insert(0, "Error: File not found.")
            return

        if selected_hash.get() == "MD5":
            hashed = file_2_md5(text)
        elif selected_hash.get() == "SHA-1":
            hashed = file_2_sha1(text)
        elif selected_hash.get() == "SHA-256":
            hashed = file_2_sha256(text)
        else:
            hashed = "Error: Select a hash type"
    else:
        if selected_hash.get() == "MD5":
            hashed = str_2_md5(text)
        elif selected_hash.get() == "SHA-1":
            hashed = str_2_sha1(text)
        elif selected_hash.get() == "SHA-256":
            hashed = str_2_sha256(text)
        else:
            hashed = "Error: Select a hash type"

    output_box.delete(0, tk.END)
    output_box.insert(0, hashed)


# ---------------------- AES functions ----------------------

def encrypt_text():
    """Encrypt the text from cipher_input using the provided key."""
    key = key_entry.get().encode()
    plaintext = cipher_input.get()

    if len(key) not in (16, 24, 32):
        cipher_output.delete(0, tk.END)
        cipher_output.insert(0, "Key must be 16/24/32 bytes")
        return

    cipher = AESCipher(key)
    encrypted = cipher.encrypt(plaintext)
    cipher_output.delete(0, tk.END)
    cipher_output.insert(0, encrypted)


def decrypt_text():
    """Decrypt the text from cipher_input using the provided key."""
    key = key_entry.get().encode()
    ciphertext = cipher_input.get()

    if len(key) not in (16, 24, 32):
        cipher_output.delete(0, tk.END)
        cipher_output.insert(0, "Key must be 16/24/32 bytes")
        return

    cipher = AESCipher(key)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except Exception as exc:  # Broad except to show user errors
        decrypted = f"Error: {exc}"
    cipher_output.delete(0, tk.END)
    cipher_output.insert(0, decrypted)


# ---------------------- GUI setup ----------------------
root = tk.Tk()
root.title("PyHasher")
root.geometry("500x300")
root.resizable(False, False)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

hash_tab = ttk.Frame(notebook)
cipher_tab = ttk.Frame(notebook)

notebook.add(hash_tab, text="Hasher")
notebook.add(cipher_tab, text="Cipher")


# ---------------------- Hasher tab ----------------------
selected_hash = tk.StringVar(value="MD5")
file_mode = tk.BooleanVar(value=False)

hash_options = customtkinter.CTkFrame(hash_tab, fg_color="transparent")
hash_options.pack(pady=10)

for text, val in ("MD5", "MD5"), ("SHA-1", "SHA-1"), ("SHA-256", "SHA-256"):
    customtkinter.CTkRadioButton(
        hash_options,
        text=text,
        variable=selected_hash,
        value=val,
        text_color="#000000",
    ).pack(side="left", padx=5)

file_frame = customtkinter.CTkFrame(hash_tab, fg_color="transparent")
file_frame.pack(pady=5)

file_checkbox = customtkinter.CTkCheckBox(
    file_frame,
    text="File",
    text_color="#000000",
    variable=file_mode,
)
file_checkbox.pack(side="left")

file_button = customtkinter.CTkButton(
    file_frame,
    text="Browse",
    width=80,
    command=lambda: browse_file(),
)
file_button.pack(side="left", padx=5)

input_frame = customtkinter.CTkFrame(hash_tab, fg_color="transparent")
input_frame.pack(pady=5)

input_box = customtkinter.CTkEntry(input_frame, width=280, text_color="#000000")
input_box.pack(side="left", padx=5)
input_box.bind("<Return>", hash_text)

hash_button = customtkinter.CTkButton(
    input_frame,
    text="Hash",
    width=80,
    command=hash_text,
)
hash_button.pack(side="left")

output_frame = customtkinter.CTkFrame(hash_tab, fg_color="transparent")
output_frame.pack(pady=5)

output_box = customtkinter.CTkEntry(output_frame, width=280, text_color="#000000")
output_box.pack(side="left", padx=5)

copy_button = customtkinter.CTkButton(
    output_frame,
    text="Copy",
    width=80,
    command=lambda: copy_to_clipboard(),
)
copy_button.pack(side="left")


# ---------------------- Cipher tab ----------------------
key_label = customtkinter.CTkLabel(cipher_tab, text="Key", text_color="#000000")
key_label.pack(pady=(10, 0))

key_entry = customtkinter.CTkEntry(cipher_tab, width=360, text_color="#000000")
key_entry.pack(pady=5)

cipher_input = customtkinter.CTkEntry(cipher_tab, width=360, text_color="#000000")
cipher_input.pack(pady=5)

cipher_buttons = customtkinter.CTkFrame(cipher_tab, fg_color="transparent")
cipher_buttons.pack(pady=5)

customtkinter.CTkButton(
    cipher_buttons,
    text="Encrypt",
    width=80,
    command=encrypt_text,
).pack(side="left", padx=5)
customtkinter.CTkButton(
    cipher_buttons,
    text="Decrypt",
    width=80,
    command=decrypt_text,
).pack(side="left", padx=5)

cipher_output = customtkinter.CTkEntry(cipher_tab, width=360, text_color="#000000")
cipher_output.pack(pady=5)


# ---------------------- Helper functions ----------------------
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(output_box.get())
    root.update()


def browse_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        input_box.delete(0, tk.END)
        input_box.insert(0, file_path)


root.mainloop()

