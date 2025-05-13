from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib, base64, os
from PIL import Image
import random
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import unpad

# Hash 

def str_2_md5(text):
    md5_hash = hashlib.md5()
    md5_hash.update(text.encode('utf-8'))  
    return md5_hash.hexdigest()

def file_2_md5(file_path):
    md5_hash = hashlib.md5()
    try:
        with open(file_path, "rb") as f: 
            for chunk in iter(lambda: f.read(4096), b""): 
                md5_hash.update(chunk)  
        
        return md5_hash.hexdigest()  
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"Error: {e}"
    
def str_2_sha256(text):
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    return sha256_hash

def str_2_sha1(text):
    sha1_hash = hashlib.sha1(text.encode()).hexdigest()
    return sha1_hash

def file_2_sha256(file_path):
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):  # Read in 4KB chunks
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    except FileNotFoundError:
        return "Error: File not found.", "Error: File not found."
    except Exception as e:
        return f"Error: {e}", f"Error: {e}"

def file_2_sha1(file_path):
    sha1_hash = hashlib.sha1()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):  # Read in 4KB chunks
                sha1_hash.update(chunk)
        
        return sha1_hash.hexdigest()
    
    except FileNotFoundError:
        return "Error: File not found.", "Error: File not found."
    except Exception as e:
        return f"Error: {e}", f"Error: {e}"
    
# Ciphers

class DESCipher:
    def __init__(self, password):
        if isinstance(password, str):
            password = hashlib.md5(password.encode()).digest()
        self.key = password[:8]


    def encrypt(self, plaintext):
        iv = os.urandom(8)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        padded = pad(plaintext.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded)
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, encrypted_text):
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            cipher = DES.new(self.key, DES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
            return decrypted.decode()
        except Exception as e:
            return f"Error decrypting: {e}"
        
class DESCipherPass:
    def __init__(self, password):
        self.key = self.set_key(password)

    def set_key(self, password):
        return hashlib.sha1(password.encode()).digest()[:8]  # SHA-1 derived 8-byte key

    def encrypt(self, plaintext):
        iv = os.urandom(8)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        padded = pad(plaintext.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded)
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, encrypted_text):
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            cipher = DES.new(self.key, DES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
            return decrypted.decode()
        except Exception as e:
            return f"Error decrypting: {e}"

class AESCipher:
    def __init__(self, key):
        self.key = key  
        self.backend = default_backend()

    def encrypt(self, plaintext):
        iv = os.urandom(16) 
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, encrypted_text):
        encrypted_data = base64.b64decode(encrypted_text)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_data.decode()

class AESCipherPass:
    def __init__(self, password):
        self.key = self.set_key(password)
        self.backend = default_backend()

    def set_key(self, password):
        sha1 = hashlib.sha1(password.encode())
        key = sha1.digest()[:16]
        return key

    def encrypt(self, plaintext):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode() 

    def decrypt(self, ciphertext):
        try:
            encrypted_data = base64.b64decode(ciphertext)
            cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
            decryptor = cipher.decryptor()

            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

            return decrypted_data.decode()
        except Exception as e:
            return f"Error decrypting: {e}"
        
# Caesar Paint

def caesarpaint_generate_key(width=16, height=16):
    used = set()
    img = Image.new("RGB", (width, height))
    for y in range(height):
        for x in range(width):
            while True:
                r, g, b = random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
                if (r, g, b) not in used:
                    used.add((r, g, b))
                    img.putpixel((x, y), (r, g, b))
                    break
    return img

def caesarpaint_draw_text(text, key_img):
    width = height = 2
    while width * height < len(text) * 2:  
        width *= 2
        height *= 2

    output = Image.new("RGB", (width, height))
    key = [key_img.getpixel((x, y)) for y in range(16) for x in range(16)]

    used_positions = set()

    for idx, char in enumerate(text):
        while True:
            x = random.randint(0, width - 1)
            y = random.randint(0, height - 1)
            if (x, y) not in used_positions:
                output.putpixel((x, y), key[ord(char) % 256])
                used_positions.add((x, y))
                break

    for y in range(height):
        for x in range(width):
            if (x, y) not in used_positions:
                while True:
                    r, g, b = random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
                    if (r, g, b) not in key: 
                        output.putpixel((x, y), (r, g, b))
                        break

    return output

def caesarpaint_read_image(image, key_img):
    key = [key_img.getpixel((x, y)) for y in range(16) for x in range(16)]
    reverse = {tuple(rgb): idx for idx, rgb in enumerate(key)}
    text = ""
    for y in range(image.height):
        for x in range(image.width):
            rgb = image.getpixel((x, y))
            if tuple(rgb) in reverse:
                text += chr(reverse[tuple(rgb)])
    return text
