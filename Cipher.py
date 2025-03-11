from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib, cryptography, base64, os

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