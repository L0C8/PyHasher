import os, customtkinter, random
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from Cipher import str_2_md5, str_2_sha1, str_2_sha256, file_2_md5, file_2_sha1, file_2_sha256, AESCipher, AESCipherPass
import string, random

# ----- Cipher Functions -----
aes_cipher = None
aes_cipher_pass = None
is_plaintext = True

def set_cipher_key():
    global aes_cipher, aes_cipher_pass
    key_text = cipher_key_box.get().strip()

    if not key_text:
        print("Error: Key cannot be empty.")
        return

    selected_mode = cipher_mode.get()

    if selected_mode == "AES":
        key = key_text.encode()
        if len(key) not in (16, 24, 32):
            print("Error: Key must be 16, 24, or 32 bytes long.\n")
            return
        aes_cipher = AESCipher(key)
        print("AES Cipher Instance Created Successfully!")

    elif selected_mode == "AES (PKCS7)":
        aes_cipher_pass = AESCipherPass(key_text)
        print("AES (PKCS7) CipherPass Instance Created Successfully!")

def update_cipher_mode():
    selected_mode = cipher_mode.get()

    if selected_mode == "AES":
        cipher_label_keyinput.configure(text="Key:")
    elif selected_mode == "AES (PKCS7)":
        cipher_label_keyinput.configure(text="Pass:")

    cipher_key_box.delete(0, "end")

def encrypt_text():
    global aes_cipher, aes_cipher_pass
    text = cipher_input_text.get("1.0", "end-1c").strip()

    if not text:
        print("Error: No text to encrypt.")
        return

    selected_mode = cipher_mode.get()

    try:
        if selected_mode == "AES" and aes_cipher:
            processed_text = aes_cipher.encrypt(text)
        elif selected_mode == "AES (PKCS7)" and aes_cipher_pass:
            processed_text = aes_cipher_pass.encrypt(text)
        else:
            processed_text = "Error: No valid cipher instance set."

        cipher_output_text.delete("1.0", "end")
        cipher_output_text.insert("1.0", processed_text)
        print(f"Processed text using mode: {selected_mode}")
    except Exception as e:
        print(f"Encryption failed: {e}")

def decrypt_text():
    global aes_cipher, aes_cipher_pass
    text = cipher_input_text.get("1.0", "end-1c").strip()

    if not text:
        print("Error: No text to decrypt.")
        return

    selected_mode = cipher_mode.get()

    try:
        if selected_mode == "AES" and aes_cipher:
            processed_text = aes_cipher.decrypt(text)
        elif selected_mode == "AES (PKCS7)" and aes_cipher_pass:
            processed_text = aes_cipher_pass.decrypt(text)
        else:
            processed_text = "Error: No valid cipher instance set."

        cipher_output_text.delete("1.0", "end")
        cipher_output_text.insert("1.0", processed_text)
        print(f"Processed text using mode: {selected_mode}")
    except Exception as e:
        print(f"Decryption failed: {e}")
    
def swap_text_mode():
    global is_plaintext
    is_plaintext = not is_plaintext  

    if is_plaintext:
        cipher_input_label.configure(text="Input (Plaintext):")
        cipher_output_label.configure(text="Output (Ciphertext):")
    else:
        cipher_input_label.configure(text="Input (Ciphertext):")
        cipher_output_label.configure(text="Output (Plaintext):")

    print(f"Mode switched: {'Plaintext -> Ciphertext' if is_plaintext else 'Ciphertext -> Plaintext'}")

def set_random_cipher_key():
    global aes_cipher
    key_length = random.choice([8, 12, 16]) 
    random_key = os.urandom(key_length)

    cipher_key_box.delete(0, "end")
    cipher_key_box.insert(0, random_key.hex())

    aes_cipher = AESCipher(random_key)
    print(f"Random AES Key Set: {random_key.hex()}")


def clear_textfield():
    cipher_input_text.delete("1.0", "end")
    cipher_output_text.delete("1.0", "end")

def copy_textfield():
    text = cipher_output_text.get("1.0", "end-1c") 
    if text.strip(): 
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

# ----- Hash Functions ----- 
def hash_text(event=None):  
    
    text = hash_input_box.get()
    
    if hash_file_mode.get():
        if not os.path.isfile(text):
            hash_output_box.delete(0, tk.END)
            hash_output_box.insert(0, "Error: File not found.")
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

    hash_output_box.delete(0, tk.END)
    hash_output_box.insert(0, hashed)

def copy_hash_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(hash_output_box.get())
    root.update()

def browse_hash_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        hash_input_box.delete(0, "end")  
        hash_input_box.insert(0, file_path) 

# ----- Password Generator Function -----
def generate_password():
    length = int(password_length_spinbox.get()) 

    char_sets = []
    if use_chars.get():
        char_sets.append(string.ascii_letters) 
    if use_numbers.get():
        char_sets.append(string.digits)  
    if use_special.get():
        char_sets.append(string.punctuation) 

    if not char_sets:
        password_output_box.delete(0, "end")
        password_output_box.insert(0, "Error: Select at least one option!")
        return

    all_chars = "".join(char_sets)
    password = "".join(random.choice(all_chars) for _ in range(length))

    password_output_box.delete(0, "end")
    password_output_box.insert(0, password)

# ----- Gui -----
root = tk.Tk()
root.title("PyHasher")
root.geometry("480x300")
root.resizable(0, 0)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)
tab3 = ttk.Frame(notebook)

notebook.add(tab1, text="Hasher")
notebook.add(tab2, text="Cipher")
notebook.add(tab3, text="Password")

# ----- Tab 1 -----

selected_hash = tk.StringVar(value="MD5")  

hash_radio_frame = customtkinter.CTkFrame(
    master=tab1,
    fg_color="transparent"
    )
hash_radio_frame.place(x=128, y=8)

hash_label_keyinput = customtkinter.CTkLabel(
    master=tab1,
    text="Hash",
    font=("Arial", 14),
    text_color="#000000",
    height=30,
    width=95,
    corner_radius=0
    )

hash_label_keyinput.place(x=10, y=10)

hash_radio_frame = customtkinter.CTkFrame(
    master=tab1, 
    fg_color="transparent")
hash_radio_frame.place(x=10, y=40)

customtkinter.CTkRadioButton(
    hash_radio_frame, 
    text="MD5", 
    variable=selected_hash, 
    value="MD5",
    text_color="#000000"
    ).pack(side="left", padx=5)
customtkinter.CTkRadioButton(
    hash_radio_frame, 
    text="SHA-1", 
    variable=selected_hash, 
    value="SHA-1",
    text_color="#000000"
    ).pack(side="left", padx=5)
customtkinter.CTkRadioButton(
    hash_radio_frame, 
    text="SHA-256",     
    variable=selected_hash, 
    value="SHA-256",
    text_color="#000000"
    ).pack(side="left", padx=5)

hash_file_mode = tk.BooleanVar(value=False)

hash_file_checkbox = customtkinter.CTkCheckBox(
    master=tab1, 
    text="File", 
    text_color="#000000",
    variable=hash_file_mode
    )

hash_file_checkbox.place(x=11, y=80)

hash_file_button = customtkinter.CTkButton(
    master=tab1, 
    text="Browse", 
    command=browse_hash_file, 
    width=80
)
hash_file_button.place(x=80, y=80)

hash_input_frame = customtkinter.CTkFrame(
    master=tab1, 
    fg_color="transparent"
    )
hash_input_frame.place(x=10, y=110)

hash_input_box = customtkinter.CTkEntry(
    master=hash_input_frame, 
    width=240, 
    text_color="#000000"
    )
hash_input_box.pack(side="left", padx=5)
hash_input_box.bind("<Return>", hash_text)

hash_output_button = customtkinter.CTkButton(
    master=hash_input_frame, 
    text="Hash", 
    command=hash_text, 
    width=80
    )
hash_output_button.pack(side="left")

hash_output_frame = customtkinter.CTkFrame(
    master=tab1, 
    fg_color="transparent"
    )
hash_output_frame.place(x=10, y=150)

hash_output_box = customtkinter.CTkEntry(
    master=hash_output_frame, 
    width=240, 
    text_color="#000000"
    )

hash_output_box.pack(side="left", padx=5)

hash_button_copy = customtkinter.CTkButton(
    master=hash_output_frame, 
    text="Copy", 
    command=copy_hash_to_clipboard, 
    width=80
    )

hash_button_copy.pack(side="left")

# ----- Tab 2 -----

cipher_label_keyinput = customtkinter.CTkLabel(
    master=tab2,
    text="Key:",
    font=("Arial", 14),
    text_color="#000000",
    corner_radius=0
    )

cipher_label_keyinput.place(x=10, y=50)

cipher_button_keyinput = customtkinter.CTkButton(
    master=tab2, 
    text="Set", 
    command=set_cipher_key,
    width=40
)
cipher_button_keyinput.place(x=320, y=50)

cipher_button_keyinput = customtkinter.CTkButton(
    master=tab2, 
    text="Random", 
    command=set_random_cipher_key,
    width=80
)
cipher_button_keyinput.place(x=370, y=50)

cipher_key_box = customtkinter.CTkEntry(
    master=tab2, 
    width=256, 
    text_color="#000000"
)
cipher_key_box.place(x=50, y=50)

cipher_input_label = customtkinter.CTkLabel(
    master=tab2,
    text="Input (Plaintext):",
    font=("Arial", 12),
    text_color="#000000"
)
cipher_input_label.place(x=10, y=90)

cipher_input_text = scrolledtext.ScrolledText(
    master=tab2, 
    width=50, 
    height=2, 
    wrap="word"
)
cipher_input_text.place(x=10, y=110)

cipher_output_label = customtkinter.CTkLabel(
    master=tab2,
    text="Output (Ciphertext):",
    font=("Arial", 12),
    text_color="#000000"
)
cipher_output_label.place(x=10, y=170)

cipher_output_text = scrolledtext.ScrolledText(
    master=tab2, 
    width=50, 
    height=2, 
    wrap="word"
)
cipher_output_text.place(x=10, y=190)

cipher_mode = tk.StringVar(value="AES")  

cipher_mode_label = customtkinter.CTkLabel(
    master=tab2,
    text="Type:",
    font=("Arial", 14),
    text_color="#000000"
)
cipher_mode_label.place(x=10, y=10)

cipher_mode_dropdown = customtkinter.CTkComboBox(
    master=tab2,
    values=["AES", "AES (PKCS7)"],
    variable=cipher_mode,
    state="readonly",
    command=lambda _: update_cipher_mode()
)
cipher_mode_dropdown.place(x=60, y=10)

cipher_encrypt_button = customtkinter.CTkButton(
    master=tab2, 
    text="Encrypt", 
    command=encrypt_text,
    width=80
)
cipher_encrypt_button.place(x=10, y=240)

cipher_decrypt_button = customtkinter.CTkButton(
    master=tab2, 
    text="Decrypt", 
    command=decrypt_text,
    width=80
)
cipher_decrypt_button.place(x=100, y=240)

cipher_copy_button = customtkinter.CTkButton(
    master=tab2, 
    text="Copy", 
    command=copy_textfield,
    width=80
)
cipher_copy_button.place(x=190, y=240)

cipher_clear_button = customtkinter.CTkButton(
    master=tab2, 
    text="Clear", 
    command=clear_textfield,
    width=80
)
cipher_clear_button.place(x=280, y=240)

hash_input_box.bind("<Return>", hash_text)  

# ----- Tab 3 (Password) -----

password_length_label = customtkinter.CTkLabel(
    master=tab3,
    text="Length:",
    font=("Arial", 12),
    text_color="#000000"
)
password_length_label.place(x=10, y=20)

password_length_spinbox = customtkinter.CTkEntry(
    master=tab3,
    width=50,
    text_color="#000000"
)
password_length_spinbox.place(x=70, y=20)
password_length_spinbox.insert(0, "8") 

def increase_length():
    current = int(password_length_spinbox.get())
    if current < 100:
        password_length_spinbox.delete(0, "end")
        password_length_spinbox.insert(0, str(current + 1))

def decrease_length():
    current = int(password_length_spinbox.get())
    if current > 8:
        password_length_spinbox.delete(0, "end")
        password_length_spinbox.insert(0, str(current - 1))

up_button = customtkinter.CTkButton(
    master=tab3,
    text="▲",
    command=increase_length,
    width=20
)
up_button.place(x=130, y=8)

down_button = customtkinter.CTkButton(
    master=tab3,
    text="▼",
    command=decrease_length,
    width=20
)
down_button.place(x=130, y=40)

use_chars = tk.BooleanVar(value=True)
use_numbers = tk.BooleanVar(value=True)
use_special = tk.BooleanVar(value=True)

chars_checkbox = customtkinter.CTkCheckBox(
    master=tab3,
    text="Characters (A-Z, a-z)",
    variable=use_chars,
    text_color="#000000"
)
chars_checkbox.place(x=10, y=80)

numbers_checkbox = customtkinter.CTkCheckBox(
    master=tab3,
    text="Numeric (0-9)",
    variable=use_numbers,
    text_color="#000000"
)
numbers_checkbox.place(x=10, y=110)

special_checkbox = customtkinter.CTkCheckBox(
    master=tab3,
    text="Special (!@#$%^&*)",
    variable=use_special,
    text_color="#000000"
)
special_checkbox.place(x=10, y=140)

password_frame = customtkinter.CTkFrame(master=tab3, fg_color="transparent")
password_frame.place(x=10, y=180)

password_output_box = customtkinter.CTkEntry(
    master=password_frame,
    width=240,
    text_color="#000000"
)
password_output_box.pack(side="left", padx=5)

generate_button = customtkinter.CTkButton(
    master=password_frame,
    text="Generate",
    command=generate_password,
    width=80
)
generate_button.pack(side="left")

if __name__ == "__main__":
    root.mainloop()