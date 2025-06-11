import tkinter as tk
from tkinter import ttk
from gui.panels.panel_hasher import HasherPanel

class PyHashGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyHash v3")
        self.root.geometry("480x320")
        self.root.resizable(False, False)

        self.setup_tabs()

    def setup_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')

        # Create tabs using panel classes
        hasher_tab = HasherPanel(self.notebook)
        self.notebook.add(hasher_tab, text="Hasher")

if __name__ == '__main__':
    root = tk.Tk()
    app = PyHashGUI(root)
    root.mainloop()
