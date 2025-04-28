import tkinter as tk
from tkinter import ttk, filedialog
from cipher import str_2_md5, str_2_sha1, str_2_sha256, file_2_md5, file_2_sha1, file_2_sha256

def create_hash_tab(parent, theme):
    frame = tk.Frame(parent, bg=theme['bg'])

    selected_hash = tk.StringVar(value="MD5")
    hash_file_mode = tk.BooleanVar(value=False)

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
        text = hash_output_box.get()
        frame.clipboard_clear()
        frame.clipboard_append(text)
        frame.update()

    def browse_hash_file():
        file_path = filedialog.askopenfilename(title="Select a File")
        if file_path:
            hash_input_box.delete(0, "end")
            hash_input_box.insert(0, file_path)

    # UI Elements
    hash_label = tk.Label(frame, text="Hash", bg=theme['bg'], fg=theme['headline'], font=("Arial", 14))
    hash_label.place(x=10, y=10)

    hash_radio_frame = tk.Frame(frame, bg=theme['bg'])
    hash_radio_frame.place(x=128, y=8)

    tk.Radiobutton(hash_radio_frame, text="MD5", variable=selected_hash, value="MD5", bg=theme['bg'], fg=theme['fg']).pack(side="left", padx=5)
    tk.Radiobutton(hash_radio_frame, text="SHA-1", variable=selected_hash, value="SHA-1", bg=theme['bg'], fg=theme['fg']).pack(side="left", padx=5)
    tk.Radiobutton(hash_radio_frame, text="SHA-256", variable=selected_hash, value="SHA-256", bg=theme['bg'], fg=theme['fg']).pack(side="left", padx=5)

    hash_file_checkbox = tk.Checkbutton(frame, text="File", variable=hash_file_mode, bg=theme['bg'], fg=theme['fg'])
    hash_file_checkbox.place(x=11, y=80)

    hash_file_button = tk.Button(frame, text="Browse", command=browse_hash_file, bg=theme['button_bg'], fg=theme['button_fg'])
    hash_file_button.place(x=80, y=80)

    hash_input_box = tk.Entry(frame, width=30, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    hash_input_box.place(x=10, y=130)
    hash_input_box.bind("<Return>", hash_text)

    hash_output_button = tk.Button(frame, text="Hash", command=hash_text, bg=theme['button_bg'], fg=theme['button_fg'])
    hash_output_button.place(x=320, y=125)

    hash_output_box = tk.Entry(frame, width=30, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    hash_output_box.place(x=10, y=170)

    hash_button_copy = tk.Button(frame, text="Copy", command=copy_hash_to_clipboard, bg=theme['button_bg'], fg=theme['button_fg'])
    hash_button_copy.place(x=320, y=165)

    return frame