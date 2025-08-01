import hashlib
import os
import random
import string
from configparser import ConfigParser
import struct
import base64

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

# cipher
def randomize_key(alg_name: str) -> str:
    if "Password" in alg_name:
        # Return 8-char random password
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    elif alg_name == "AES":
        return base64.b64encode(os.urandom(16)).decode() 
    elif alg_name == "DES":
        return base64.b64encode(os.urandom(8)).decode()
    else:
        return ""
    
# metadata utils
def strip_metadata(src_path, dest_path):
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"File not found: {src_path}")

    os.makedirs(os.path.dirname(dest_path) or '.', exist_ok=True)

    ext = os.path.splitext(src_path)[1].lower()

    if ext == '.png':
        try:
            _strip_png(src_path, dest_path)
            return
        except Exception:
            pass

    try:
        from PIL import Image
    except Exception:
        Image = None

    if Image and ext in {'.jpg', '.jpeg', '.bmp', '.gif', '.tiff', '.png'}:
        with Image.open(src_path) as img:
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(list(img.getdata()))
            save_kwargs = {}
            if ext in {'.jpg', '.jpeg', '.tiff'}:
                save_kwargs['exif'] = None
            if ext == '.png':
                save_kwargs['pnginfo'] = None
            new_img.save(dest_path, **save_kwargs)
            return

    # Fallback: just copy bytes
    with open(src_path, 'rb') as src, open(dest_path, 'wb') as dst:
        for chunk in iter(lambda: src.read(8192), b''):
            dst.write(chunk)


def _strip_png(src_path, dest_path):
    keep = {
        b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS', b'gAMA',
        b'cHRM', b'sBIT', b'bKGD', b'pHYs', b'sRGB', b'hIST',
        b'acTL', b'fcTL', b'fdAT'
    }

    with open(src_path, 'rb') as src:
        data = src.read()

    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('Not a PNG file')

    out = bytearray()
    out.extend(b'\x89PNG\r\n\x1a\n')
    idx = 8
    length = len(data)
    while idx + 8 <= length:
        size = int.from_bytes(data[idx:idx+4], 'big')
        ctype = data[idx+4:idx+8]
        end = idx + 8 + size + 4
        if end > length:
            break
        chunk = data[idx:end]
        if ctype in keep:
            out.extend(chunk)
        idx = end
        if ctype == b'IEND':
            break

    with open(dest_path, 'wb') as dst:
        dst.write(out)


def save_metadata(src_path, dest_path):
    """Extract metadata from a file and save it to a text file.

    For common image formats, this attempts to read available metadata using
    Pillow if installed. If no metadata can be found, the output file will
    contain a short message indicating such.
    """
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"File not found: {src_path}")

    lines = []
    ext = os.path.splitext(src_path)[1].lower()
    if ext in {'.png', '.jpg', '.jpeg', '.bmp', '.gif'}:
        try:
            from PIL import Image
        except Exception:
            pass
        else:
            with Image.open(src_path) as img:
                if img.info:
                    for k, v in img.info.items():
                        lines.append(f"{k}: {v}")
                try:
                    exif = img.getexif()
                except Exception:
                    exif = None
                if exif:
                    for k, v in exif.items():
                        lines.append(f"{k}: {v}")

    if not lines:
        lines.append("No metadata found.")

    os.makedirs(os.path.dirname(dest_path) or '.', exist_ok=True)
    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

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

# Default themes used when creating a new theme file or filling in missing keys
DEFAULT_THEMES = {
    'dark': {
        'background': '#222222',
        'foreground': '#ffffff',
        'tab_background': '#333333',
        'tab_foreground': '#ffffff',
        'entry_background': '#444444',
        'entry_foreground': '#ffffff',
        'text_background': '#444444',
        'text_foreground': '#ffffff',
        'dropdown_background': '#444444',
        'dropdown_foreground': '#ffffff',
    },
    'light': {
        'background': '#f0f0f0',
        'foreground': '#000000',
        'tab_background': '#e0e0e0',
        'tab_foreground': '#000000',
        'entry_background': '#ffffff',
        'entry_foreground': '#000000',
        'text_background': '#ffffff',
        'text_foreground': '#000000',
        'dropdown_background': '#ffffff',
        'dropdown_foreground': '#000000',
    },
    'dark_blue': {
        'background': '#1a237e',
        'foreground': '#e8eaf6',
        'tab_background': '#283593',
        'tab_foreground': '#e8eaf6',
        'entry_background': '#3949ab',
        'entry_foreground': '#e8eaf6',
        'text_background': '#3949ab',
        'text_foreground': '#e8eaf6',
        'dropdown_background': '#3949ab',
        'dropdown_foreground': '#e8eaf6',
    },
    'matrix': {
        'background': '#000000',
        'foreground': '#00ff00',
        'tab_background': '#002b00',
        'tab_foreground': '#00ff00',
        'entry_background': '#003300',
        'entry_foreground': '#00ff00',
        'text_background': '#001a00',
        'text_foreground': '#00ff00',
        'dropdown_background': '#003300',
        'dropdown_foreground': '#00ff00',
    },
    'sunset': {
        'background': '#ff7043',
        'foreground': '#fff8e1',
        'tab_background': '#ffab91',
        'tab_foreground': '#4e342e',
        'entry_background': '#ffccbc',
        'entry_foreground': '#4e342e',
        'text_background': '#ffe0b2',
        'text_foreground': '#4e342e',
        'dropdown_background': '#ffccbc',
        'dropdown_foreground': '#4e342e',
    },
    'ocean': {
        'background': '#01579b',
        'foreground': '#e1f5fe',
        'tab_background': '#0277bd',
        'tab_foreground': '#e1f5fe',
        'entry_background': '#0288d1',
        'entry_foreground': '#e1f5fe',
        'text_background': '#0288d1',
        'text_foreground': '#e1f5fe',
        'dropdown_background': '#0288d1',
        'dropdown_foreground': '#e1f5fe',
    },
    'pastel': {
        'background': '#f8bbd0',
        'foreground': '#4e342e',
        'tab_background': '#f48fb1',
        'tab_foreground': '#4e342e',
        'entry_background': '#fce4ec',
        'entry_foreground': '#4e342e',
        'text_background': '#fce4ec',
        'text_foreground': '#4e342e',
        'dropdown_background': '#fce4ec',
        'dropdown_foreground': '#4e342e',
    },
}


def ensure_themes():
    """Ensure the default themes file exists and contains required keys."""
    os.makedirs(os.path.dirname(THEME_PATH), exist_ok=True)
    config = ConfigParser()
    if os.path.exists(THEME_PATH):
        config.read(THEME_PATH)
    changed = False
    for name, values in DEFAULT_THEMES.items():
        if name not in config:
            config[name] = values
            changed = True
            continue
        for key, val in values.items():
            if key not in config[name]:
                config[name][key] = val
                changed = True
    if changed or not os.path.exists(THEME_PATH):
        with open(THEME_PATH, 'w') as f:
            config.write(f)


def load_themes():
    """Load all available themes from the config file."""
    ensure_themes()
    config = ConfigParser()
    config.read(THEME_PATH)
    return {section: dict(config[section]) for section in config.sections()}
