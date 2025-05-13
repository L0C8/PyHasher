import tkinter as tk
from tkinter import filedialog
from PIL import Image
import os
from cipher import caesarpaint_generate_key, caesarpaint_draw_text, caesarpaint_read_image, caesarpaint_draw_ciphered, caesarpaint_read_ciphered

loaded_keys = {}

def create_caesarpaint_tab(parent, theme):
    frame = tk.Frame(parent, bg=theme['bg'])

    key_var = tk.StringVar()
    key_dropdown = tk.OptionMenu(frame, key_var, "None")
    key_dropdown.configure(bg=theme['button_bg'], fg=theme['button_fg'])
    key_dropdown.place(x=10, y=10)

    mode_var = tk.StringVar(value="Standard")
    mode_dropdown = tk.OptionMenu(frame, mode_var, "Standard" )
    mode_dropdown.configure(bg=theme['button_bg'], fg=theme['button_fg'])
    mode_dropdown.place(x=10, y=50)

    def refresh_key_list():
        key_menu = key_dropdown["menu"]
        key_menu.delete(0, "end")
        for name in loaded_keys:
            key_menu.add_command(label=name, command=lambda n=name: key_var.set(n))

    def load_key():
        file_path = filedialog.askopenfilename(title="Select Key Image")
        if file_path:
            try:
                name = os.path.basename(file_path)
                img = Image.open(file_path).convert("RGB")
                loaded_keys[name] = img
                refresh_key_list()
                key_var.set(name)
            except Exception as e:
                print("Error loading image:", e)

    def generate_key():
        img = caesarpaint_generate_key()
        save_path = filedialog.asksaveasfilename(defaultextension=".png")
        if save_path:
            img.save(save_path)

    def encode_text():
        key = loaded_keys.get(key_var.get())
        text = text_input.get("1.0", "end-1c")
        if key and text:
            if mode_var.get() == "DES Cipher":
                img = caesarpaint_draw_ciphered(text, key)
            else:
                img = caesarpaint_draw_text(text, key)
            path = filedialog.asksaveasfilename(defaultextension=".png")
            if path:
                img.save(path)

    def decode_image():
        key = loaded_keys.get(key_var.get())
        file_path = filedialog.askopenfilename()
        if key and file_path:
            img = Image.open(file_path).convert("RGB")
            if mode_var.get() == "DES Cipher":
                result = caesarpaint_read_ciphered(img, key)
            else:
                result = caesarpaint_read_image(img, key)
            text_input.delete("1.0", "end")
            text_input.insert("1.0", result)

    tk.Button(frame, text="Load Key", command=load_key, bg=theme['button_bg'], fg=theme['button_fg'], width=8).place(x=150, y=10)
    tk.Button(frame, text="New Key", command=generate_key, bg=theme['button_bg'], fg=theme['button_fg'], width=8).place(x=250, y=10)

    tk.Button(frame, text="Encode", command=encode_text, bg=theme['button_bg'], fg=theme['button_fg'], width=8).place(x=150, y=50)
    tk.Button(frame, text="Decode", command=decode_image, bg=theme['button_bg'], fg=theme['button_fg'], width=8).place(x=250, y=50)

    text_input = tk.Text(frame, width=50, height=8, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    text_input.place(x=10, y=130)

    return frame