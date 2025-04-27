import tkinter as tk

def create_cipher_tab(parent, theme):
    frame = tk.Frame(parent, bg=theme['bg'])
    label = tk.Label(frame, text="Cipher Panel", bg=theme['bg'], fg=theme['fg'])
    label.pack(pady=20)
    return frame
