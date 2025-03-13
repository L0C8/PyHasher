import tkinter as tk
import os, customtkinter
from tkinter import ttk
from Cipher import str_2_md5, str_2_sha1, str_2_sha256, file_2_md5, file_2_sha1, file_2_sha256 


# ----- Cipher Functions -----

# ----- Hash Functions ----- 
def hash_text(event=None):  
    
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

# ----- Tab 1 -----

selected_hash = tk.StringVar(value="MD5")  

radio_frame = customtkinter.CTkFrame(master=tab1)
radio_frame.place(x=128, y=8)

Hash_Label_KeyInput = customtkinter.CTkLabel(
    master=tab1,
    text="Hash",
    font=("Arial", 14),
    text_color="#000000",
    height=30,
    width=95,
    corner_radius=0
    )

Hash_Label_KeyInput.place(x=0, y=0)

customtkinter.CTkRadioButton(
    radio_frame, 
    text="MD5", 
    variable=selected_hash, 
    value="MD5",
    text_color="#000000"
    ).pack(side="left", padx=5)
customtkinter.CTkRadioButton(
    radio_frame, 
    text="SHA-1", 
    variable=selected_hash, 
    value="SHA-1",
    text_color="#000000"
    ).pack(side="left", padx=5)
customtkinter.CTkRadioButton(
    radio_frame, 
    text="SHA-256", 
    variable=selected_hash, 
    value="SHA-256",
    text_color="#000000"
    ).pack(side="left", padx=5)

file_mode = tk.BooleanVar(value=False)
file_checkbox = customtkinter.CTkCheckBox(
    master=tab1, 
    text="File", 
    text_color="#000000",
    variable=file_mode
    )

file_checkbox.place(x=48, y=48)

input_box = customtkinter.CTkEntry(
    master=tab1, 
    width=300,
    text_color="#000000"
    )
input_box.pack(pady=5)
input_box.bind("<Return>", hash_text)

hash_button = customtkinter.CTkButton(
    master=tab1, 
    text="Hash", 
    command=hash_text
    )
hash_button.pack(pady=5)

output_box = customtkinter.CTkEntry(
    master=tab1, 
    width=300, 
    state="normal"
    )
output_box.pack(pady=5)

# ----- Tab 2 -----

Cipher_Label_KeyInput = customtkinter.CTkLabel(
    master=tab2,
    text="Key",
    font=("Arial", 14),
    text_color="#000000",
    height=30,
    width=95,
    corner_radius=0
    )
Cipher_Label_KeyInput.place(x=0, y=0)
# input_box = ttk.Entry(tab2, width=50)
# input_box.pack(pady=5)
input_box.bind("<Return>", hash_text)  

root.mainloop()