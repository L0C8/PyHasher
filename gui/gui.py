import tkinter as tk
from tkinter import ttk

from gui.panels.panel_hasher import HasherPanel
from gui.panels.panel_password import PasswordPanel
from gui.panels.panel_cipher import CipherPanel
from gui.panels.panel_stripmeta import StripMetaPanel
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
        tab_bg = theme.get('tab_background', bg)
        tab_fg = theme.get('tab_foreground', fg)
        entry_bg = theme.get('entry_background', '#FFFFFF')
        entry_fg = theme.get('entry_foreground', '#000000')
        text_bg = theme.get('text_background', entry_bg)
        text_fg = theme.get('text_foreground', entry_fg)
        dd_bg = theme.get('dropdown_background', entry_bg)
        dd_fg = theme.get('dropdown_foreground', entry_fg)

        style = ttk.Style()
        style.configure('.', background=bg, foreground=fg)
        style.configure('TNotebook', background=tab_bg)
        style.configure('TNotebook.Tab', background=tab_bg, foreground=tab_fg)
        style.map('TNotebook.Tab', background=[('selected', tab_bg)], foreground=[('selected', tab_fg)])
        style.configure('TEntry', fieldbackground=entry_bg, foreground=entry_fg)
        style.configure('TCombobox', fieldbackground=dd_bg, background=dd_bg,
                        foreground=dd_fg)

        self.root.configure(bg=bg)
        self.root.option_add('*Text.background', text_bg)
        self.root.option_add('*Text.foreground', text_fg)
        self.root.option_add('*Entry.background', entry_bg)
        self.root.option_add('*Entry.foreground', entry_fg)
        self.root.option_add('*TCombobox*Listbox.background', dd_bg)
        self.root.option_add('*TCombobox*Listbox.foreground', dd_fg)
        
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

        # on hold
        # strip_tab = StripMetaPanel(self.notebook)
        # self.notebook.add(strip_tab, text="Metadata")

        settings_tab = SettingsPanel(self.notebook, self.apply_theme)
        self.notebook.add(settings_tab, text="Settings")

if __name__ == '__main__':
    root = tk.Tk()
    app = PyHashGUI(root)
    root.mainloop()
