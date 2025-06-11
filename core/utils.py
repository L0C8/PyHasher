import hashlib
import random
import string


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