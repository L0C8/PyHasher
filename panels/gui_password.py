import tkinter as tk
from utils import PasswordBuilder

def create_password_tab(parent, theme):
    frame = tk.Frame(parent, bg=theme['bg'])

    password_length_var = tk.IntVar(value=8)
    use_chars = tk.BooleanVar(value=True)
    use_numbers = tk.BooleanVar(value=True)
    use_special = tk.BooleanVar(value=True)

    def generate_password():
        builder = PasswordBuilder(
            use_chars=use_chars.get(),
            use_numbers=use_numbers.get(),
            use_special=use_special.get(),
            length=password_length_var.get()
        )
        password = builder.build()
        password_output_box.delete(0, tk.END)
        password_output_box.insert(0, password)

    # gui 
    
    label = tk.Label(frame, text="Generate Password", bg=theme['bg'], fg=theme['headline'], font=("Arial", 14))
    label.pack(pady=10)

    options_frame = tk.Frame(frame, bg=theme['bg'])
    options_frame.pack(pady=5)

    tk.Label(options_frame, text="Length:", bg=theme['bg'], fg=theme['fg']).grid(row=0, column=0, sticky="w")
    length_entry = tk.Entry(options_frame, textvariable=password_length_var, width=5, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    length_entry.grid(row=0, column=1, padx=5)

    tk.Checkbutton(options_frame, text="Letters (A-Z, a-z)", variable=use_chars, bg=theme['bg'], fg=theme['fg']).grid(row=1, column=0, columnspan=2, sticky="w")
    tk.Checkbutton(options_frame, text="Numbers (0-9)", variable=use_numbers, bg=theme['bg'], fg=theme['fg']).grid(row=2, column=0, columnspan=2, sticky="w")
    tk.Checkbutton(options_frame, text="Special Characters", variable=use_special, bg=theme['bg'], fg=theme['fg']).grid(row=3, column=0, columnspan=2, sticky="w")

    password_output_box = tk.Entry(frame, width=30, bg=theme['bg'], fg=theme['fg'], insertbackground=theme['fg'])
    password_output_box.pack(pady=10)

    generate_button = tk.Button(frame, text="Generate", command=generate_password, bg=theme['button_bg'], fg=theme['button_fg'])
    generate_button.pack(pady=5)

    return frame