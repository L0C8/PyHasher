import hashlib
import random
import string
import os
from configparser import ConfigParser


# hash defs 
def hash_text(text, method='sha256'):
    h = getattr(hashlib, method)()
    h.update(text.encode('utf-8'))
    return h.hexdigest()

def hash_file(file_path, method='sha256'):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    h = getattr(hashlib, method)()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

# password defs 
def get_password(length=12, use_chars=True, use_nums=True, use_specials=True):
    chars = ''
    if use_chars:
        chars += string.ascii_letters
    if use_nums:
        chars += string.digits
    if use_specials:
        chars += string.punctuation
    if not chars:
        raise ValueError("At least one character type must be selected.")

    return ''.join(random.choice(chars) for _ in range(length))

# theme defs
THEME_PATH = os.path.join('data', 'themes.ini')


def ensure_themes():
    """Ensure the default themes file exists."""
    os.makedirs(os.path.dirname(THEME_PATH), exist_ok=True)
    if not os.path.exists(THEME_PATH):
        config = ConfigParser()
        config['dark'] = {'background': '#333333', 'foreground': '#FFFFFF'}
        config['light'] = {'background': '#FFFFFF', 'foreground': '#000000'}
        with open(THEME_PATH, 'w') as f:
            config.write(f)


def load_themes():
    """Load all available themes from the config file."""
    ensure_themes()
    config = ConfigParser()
    config.read(THEME_PATH)
    return {section: dict(config[section]) for section in config.sections()}
