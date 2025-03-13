import tkinter as tk
import os, customtkinter
from tkinter import ttk, filedialog, scrolledtext
from Cipher import str_2_md5, str_2_sha1, str_2_sha256, file_2_md5, file_2_sha1, file_2_sha256 


# ----- Cipher Functions -----

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

# ----- Gui -----
root = tk.Tk()
root.title("PyHasher")
root.geometry("480x256")
root.resizable(0, 0)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)

notebook.add(tab1, text="Hasher")
notebook.add(tab2, text="Cipher")

# ----- functions -----

def copy_hash_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(hash_output_box.get())
    root.update()

def browse_hash_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        hash_input_box.delete(0, "end")  # Clear previous input
        hash_input_box.insert(0, file_path)  # Insert selected file path

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

cipher_label_keyinput.place(x=10, y=10)

cipher_button_keyinput = customtkinter.CTkButton(
    master=tab2, 
    text="Set", 
    width=80
)
cipher_button_keyinput.place(x=320, y=10)

cipher_key_box = customtkinter.CTkEntry(
    master=tab2, 
    width=256, 
    text_color="#000000"
)
cipher_key_box.place(x=50, y=10)

cipher_input_label = customtkinter.CTkLabel(
    master=tab2,
    text="Input:",
    font=("Arial", 12),
    text_color="#000000"
)
cipher_input_label.place(x=10, y=50)

cipher_input_text = scrolledtext.ScrolledText(
    master=tab2, 
    width=50, 
    height=2, 
    wrap="word"
)
cipher_input_text.place(x=10, y=70)

cipher_output_label = customtkinter.CTkLabel(
    master=tab2,
    text="Output:",
    font=("Arial", 12),
    text_color="#000000"
)
cipher_output_label.place(x=10, y=110)

cipher_output_text = scrolledtext.ScrolledText(
    master=tab2, 
    width=50, 
    height=2, 
    wrap="word"
)
cipher_output_text.place(x=10, y=130)

cipher_translate_button = customtkinter.CTkButton(
    master=tab2, 
    text="Translate", 
    width=80
)
cipher_translate_button.place(x=10, y=180)

cipher_swap_button = customtkinter.CTkButton(
    master=tab2, 
    text="Swap", 
    width=80
)
cipher_swap_button.place(x=100, y=180)

cipher_copy_button = customtkinter.CTkButton(
    master=tab2, 
    text="Copy", 
    width=80
)
cipher_copy_button.place(x=190, y=180)

cipher_clear_button = customtkinter.CTkButton(
    master=tab2, 
    text="Clear", 
    width=80
)
cipher_clear_button.place(x=280, y=180)

hash_input_box.bind("<Return>", hash_text)  

root.mainloop()