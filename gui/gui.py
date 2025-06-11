import tkinter as tk
from tkinter import ttk

from gui.panels.panel_hasher import HasherPanel
from gui.panels.panel_password import PasswordPanel
from gui.panels.panel_cipher import CipherPanel
from gui.panels.panel_settings import SettingsPanel
from core import utils

class PyHashGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyHash v3")
        self.root.geometry("480x320")
        self.root.resizable(False, False)

        # load themes
        self.themes = utils.load_themes()
        self.apply_theme(self.themes.get('light'))

        self.setup_tabs()

    def apply_theme(self, theme):
        if not theme:
            return
        bg = theme.get('background', '#FFFFFF')
        fg = theme.get('foreground', '#000000')
        style = ttk.Style()
        style.configure('.', background=bg, foreground=fg)
        self.root.configure(bg=bg)
        
    def setup_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')

        # Create tabs using panel classes
        hasher_tab = HasherPanel(self.notebook)
        self.notebook.add(hasher_tab, text="Hasher")

        pass_tab = PasswordPanel(self.notebook)
        self.notebook.add(pass_tab, text="Password")

        cipher_tab = CipherPanel(self.notebook)
        self.notebook.add(cipher_tab, text="Cipher")

        settings_tab = SettingsPanel(self.notebook, self.apply_theme)
        self.notebook.add(settings_tab, text="Settings")

if __name__ == '__main__':
    root = tk.Tk()
    app = PyHashGUI(root)
    root.mainloop()
