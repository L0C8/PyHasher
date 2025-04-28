import tkinter as tk
from utils import save_selected_theme, load_selected_theme

def create_settings_tab(parent, theme, themes):
    frame = tk.Frame(parent, bg=theme['bg'])

    label = tk.Label(frame, text="Select Theme", bg=theme['bg'], fg=theme['fg'], font=("Arial", 14))
    label.pack(pady=10)

    theme_listbox = tk.Listbox(frame, bg=theme['bg'], fg=theme['fg'], selectbackground=theme['accent'], height=5)
    for theme_name in themes.sections():
        theme_listbox.insert(tk.END, theme_name)
    theme_listbox.pack(padx=10, pady=10, fill='both', expand=True)

    def apply_selected_theme():
        selection = theme_listbox.curselection()
        if selection:
            selected_theme = theme_listbox.get(selection[0])
            save_selected_theme(selected_theme)

    apply_button = tk.Button(frame, text="Apply Theme", command=apply_selected_theme, bg=theme['button_bg'], fg=theme['button_fg'])
    apply_button.pack(pady=10)

    return frame