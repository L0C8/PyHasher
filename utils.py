import configparser
import os
import random
import string

SETTINGS_FILE = 'data/settings.ini'

# --- Theme Management ---
def save_selected_theme(theme_name):
    config = configparser.ConfigParser()
    if os.path.exists(SETTINGS_FILE):
        config.read(SETTINGS_FILE)
    if 'Settings' not in config:
        config['Settings'] = {}
    config['Settings']['theme'] = theme_name
    with open(SETTINGS_FILE, 'w') as configfile:
        config.write(configfile)

def load_selected_theme():
    config = configparser.ConfigParser()
    if os.path.exists(SETTINGS_FILE):
        config.read(SETTINGS_FILE)
        return config.get('Settings', 'theme', fallback='Dark')
    return 'Dark'

# --- Special Characters Management ---
def save_special_characters(special_chars):
    config = configparser.ConfigParser()
    if os.path.exists(SETTINGS_FILE):
        config.read(SETTINGS_FILE)
    if 'Settings' not in config:
        config['Settings'] = {}
    config['Settings']['special_chars'] = special_chars
    with open(SETTINGS_FILE, 'w') as configfile:
        config.write(configfile)

def load_special_characters():
    config = configparser.ConfigParser()
    if os.path.exists(SETTINGS_FILE):
        config.read(SETTINGS_FILE)
        return config.get('Settings', 'special_chars', fallback='!@#$%^&*()')
    return '!@#$%^&*()'

# --- Password Builder ---
class PasswordBuilder:
    def __init__(self, use_chars=True, use_numbers=True, use_special=True, length=8):
        self.use_chars = use_chars
        self.use_numbers = use_numbers
        self.use_special = use_special
        self.length = length
        self.special_chars = load_special_characters()

    def build(self):
        char_sets = []
        if self.use_chars:
            char_sets.append(string.ascii_letters)
        if self.use_numbers:
            char_sets.append(string.digits)
        if self.use_special:
            char_sets.append(self.special_chars)

        if not char_sets:
            return "Error: No character sets selected."

        all_chars = ''.join(char_sets)
        return ''.join(random.choice(all_chars) for _ in range(self.length))
