import tkinter as tk

def show_ok_popup(message):
    popup = tk.Toplevel()
    popup.title("PyHasher")
    popup.geometry("300x100")
    popup.resizable(False, False)

    label = tk.Label(popup, text=message)
    label.pack(pady=10)

    button = tk.Button(popup, text="OK", command=popup.destroy)
    button.pack(pady=5)
