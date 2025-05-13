import configparser
import os
import random
import string

SETTINGS_FILE = 'data/settings.ini'
THEMES_FILE = 'data/themes.ini'

# --- Boot Commands ---

def startup():
    os.makedirs('data', exist_ok=True)
    ensure_themes_exist()
    ensure_settings_exist()

def ensure_settings_exist():
    if not os.path.exists(SETTINGS_FILE):
        config = configparser.ConfigParser(interpolation=None)
        config['Settings'] = {
            'theme': 'Dark',
            'special_chars': '!@#$^&*()'
        }
        with open(SETTINGS_FILE, 'w') as configfile:
            config.write(configfile)

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

def ensure_themes_exist():
    if not os.path.exists(THEMES_FILE):
        os.makedirs('data', exist_ok=True)
        config = configparser.ConfigParser()
        config['Dark'] = {
            'bg': '#1e1e1e',
            'fg': '#d4d4d4',
            'headline': '#ffffff',
            'button_bg': '#333333',
            'button_fg': '#ffffff',
            'accent': '#007acc'
        }
        config['Light'] = {
            'bg': '#ffffff',
            'fg': '#000000',
            'headline': '#222222',
            'button_bg': '#dddddd',
            'button_fg': '#000000',
            'accent': '#007acc'
        }
        with open(THEMES_FILE, 'w') as configfile:
            config.write(configfile)

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
