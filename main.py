from gui.gui import PyHashGUI
import tkinter as tk

if __name__ == '__main__':
    root = tk.Tk()
    app = PyHashGUI(root)
    root.mainloop()

from gui import run_app

if __name__ == "__main__":
    run_app()
