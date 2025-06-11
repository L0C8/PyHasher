import tkinter as tk
from utils import save_selected_theme, load_selected_theme, save_special_characters, load_special_characters
from panels.popup_okay import show_ok_popup

def create_settings_tab(parent, theme, themes):
    frame = tk.Frame(parent, bg=theme['bg'])

    label = tk.Label(frame, text="Select Theme", bg=theme['bg'], fg=theme['fg'], font=("Arial", 14))
    label.grid(row=0, column=0, sticky='w', padx=10, pady=(10, 0))

    theme_var = tk.StringVar(value=load_selected_theme())
    theme_menu = tk.OptionMenu(frame, theme_var, *themes.sections())
    theme_menu.configure(bg=theme['button_bg'], fg=theme['button_fg'])
    theme_menu.grid(row=1, column=0, padx=10, pady=5, sticky='we')

    def apply_selected_theme():
        selected_theme = theme_var.get()
        if selected_theme:
            save_selected_theme(selected_theme)
            show_ok_popup("Please restart the app!")

    apply_button = tk.Button(frame, text="Apply Theme", command=apply_selected_theme, bg=theme['button_bg'], fg=theme['button_fg'])
    apply_button.grid(row=2, column=0, padx=10, pady=5, sticky='w')

    # Special Characters
    special_label = tk.Label(frame, text="Special Characters:", bg=theme['bg'], fg=theme['fg'], font=("Arial", 12))
    special_label.grid(row=3, column=0, sticky='w', padx=10, pady=(10, 0))

    special_var = tk.StringVar(value=load_special_characters())
    special_entry = tk.Entry(frame, textvariable=special_var, width=30, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    special_entry.grid(row=4, column=0, padx=10, pady=5, sticky='w')

    def save_special():
        save_special_characters(special_var.get())

    save_special_button = tk.Button(frame, text="Save Special Chars", command=save_special, bg=theme['button_bg'], fg=theme['button_fg'])
    save_special_button.grid(row=5, column=0, padx=10, pady=5, sticky='w')

    return frame