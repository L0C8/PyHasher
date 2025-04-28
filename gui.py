import tkinter as tk
from tkinter import ttk
import configparser

from panels.gui_hash import create_hash_tab
from panels.gui_cipher import create_cipher_tab
from panels.gui_password import create_password_tab
from panels.gui_settings import create_settings_tab

# === Load Themes ===
def load_themes():
    config = configparser.ConfigParser()
    config.read("data/themes.ini")
    return config

# === Apply Theme ===
def apply_theme(widget, theme_dict):
    widget.configure(bg=theme_dict['bg'])
    style = ttk.Style()
    style.theme_use('default')
    style.configure("TNotebook", background=theme_dict['bg'])
    style.configure("TNotebook.Tab", background=theme_dict['button_bg'], foreground=theme_dict['button_fg'])
    style.map("TNotebook.Tab", background=[("selected", theme_dict['accent'])])

# === Run Application ===
def run_app():
    root = tk.Tk()
    root.title("PyHasher")
    root.geometry("480x300")
    root.resizable(False, False)

    themes = load_themes()
    selected_theme = themes['MidnightPurple'] 

    apply_theme(root, selected_theme)

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill='both')

    # Add tabs
    notebook.add(create_hash_tab(notebook, selected_theme), text="Hasher")
    notebook.add(create_cipher_tab(notebook, selected_theme), text="Cipher")
    notebook.add(create_password_tab(notebook, selected_theme), text="Password")
    notebook.add(create_settings_tab(notebook, selected_theme), text="Settings")
    
    root.mainloop()