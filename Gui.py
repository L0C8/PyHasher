import os, customtkinter, random
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from Cipher import str_2_md5, str_2_sha1, str_2_sha256, file_2_md5, file_2_sha1, file_2_sha256, AESCipher

# ----- Cipher Functions -----
aes_cipher = None
is_plaintext = True

def set_cipher_key():
    global aes_cipher
    key = cipher_key_box.get().encode() 

    if not key:
        print("Error: Key cannot be empty.")
        return

    if len(key) not in (16, 24, 32):
        print("Error: Key must be 16, 24, or 32 bytes long.\n")
        print(len(key))
        return
    
    aes_cipher = AESCipher(key) 
    print("AES Cipher Instance Created Successfully!")

def set_random_cipher_key():
    global aes_cipher
    key_length = random.choice([8, 12, 16]) 
    random_key = os.urandom(key_length)

    cipher_key_box.delete(0, "end")
    cipher_key_box.insert(0, random_key.hex())

    aes_cipher = AESCipher(random_key)
    print(f"Random AES Key Set: {random_key.hex()}")

def encrypt_text():
    global aes_cipher
    if aes_cipher is None:
        print("Error: No AES key set. Please set a key first.")
        return

    text = cipher_input_text.get("1.0", "end-1c")
    if not text.strip():
        print("Error: No text to encrypt.")
        return

    try:
        if(is_plaintext):
            encrypted_text = aes_cipher.encrypt(text)
            cipher_output_text.delete("1.0", "end")
            cipher_output_text.insert("1.0", encrypted_text) 
            print("Text encrypted successfully.")
        else:
            decrypted_text = aes_cipher.decrypt(text)
            cipher_output_text.delete("1.0", "end")
            cipher_output_text.insert("1.0", decrypted_text) 
            print("Text encrypted successfully.")
    except Exception as e:
        print(f"Encryption failed: {e}")

def decrypt_text():
    global aes_cipher
    if aes_cipher is None:
        print("Error: No AES key set. Please set a key first.")
        return
    text = cipher_input_text.get("1.0", "end-1c")
    
    if not text.strip():
        print("Error: No text to encrypt.")
        return

    try:
        encrypted_text = aes_cipher.encrypt(text)
        cipher_output_text.delete("1.0", "end")
        cipher_output_text.insert("1.0", encrypted_text) 
        print("Text encrypted successfully.")
    except Exception as e:
        print(f"Encryption failed: {e}")
    
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

# ----- Gui -----
root = tk.Tk()
root.title("PyHasher")
root.geometry("480x300")
root.resizable(0, 0)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)

notebook.add(tab1, text="Hasher")
notebook.add(tab2, text="Cipher")

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

cipher_translate_button = customtkinter.CTkButton(
    master=tab2, 
    text="Translate", 
    command=encrypt_text,
    width=80
)
cipher_translate_button.place(x=10, y=240)

cipher_swap_button = customtkinter.CTkButton(
    master=tab2, 
    text="Swap", 
    command=swap_text_mode,
    width=80
)
cipher_swap_button.place(x=100, y=240)

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

cipher_mode = tk.StringVar(value="AES") 

cipher_mode_label = customtkinter.CTkLabel(
    master=tab2,
    text="Type:",
    font=("Arial", 14),
    text_color="#000000",
    corner_radius=0
    )

cipher_mode_label.place(x=10, y=10) 

cipher_mode_dropdown = customtkinter.CTkComboBox(
    master=tab2,
    values=["AES", "AES (PKCS7)"],
    variable=cipher_mode
)
cipher_mode_dropdown.place(x=60, y=10) 

hash_input_box.bind("<Return>", hash_text)  

root.mainloop()