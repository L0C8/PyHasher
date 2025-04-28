import tkinter as tk

def create_settings_tab(parent, theme):
    frame = tk.Frame(parent, bg=theme['bg'])
    label = tk.Label(frame, text="Settings Panel", bg=theme['bg'], fg=theme['fg'])
    label.pack(pady=20)
    return frame
