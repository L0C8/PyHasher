from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib, base64, os

class AESCipher:
    backend = default_backend()

    @staticmethod
    def encrypt(plaintext, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=AESCipher.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt(encrypted_text, key):
        encrypted_data = base64.b64decode(encrypted_text)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=AESCipher.backend)
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_data.decode()

class AESCipherPass:
    backend = default_backend()

    @staticmethod
    def set_key(password):
        sha1 = hashlib.sha1(password.encode())
        return sha1.digest()[:16]

    @staticmethod
    def encrypt(plaintext, password):
        key = AESCipherPass.set_key(password)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=AESCipherPass.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode()

    @staticmethod
    def decrypt(ciphertext, password):
        try:
            key = AESCipherPass.set_key(password)
            encrypted_data = base64.b64decode(ciphertext)
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=AESCipherPass.backend)
            decryptor = cipher.decryptor()

            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

            return decrypted_data.decode()
        except Exception as e:
            return f"Error decrypting: {e}"

class DESCipher:
    @staticmethod
    def encrypt(plaintext, key):
        if isinstance(key, str):
            key = key.encode()

        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes long.")

        cipher = DES.new(key, DES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
        return base64.b64encode(cipher.iv + ct_bytes).decode()

    @staticmethod
    def decrypt(encrypted_text, key):
        if isinstance(key, str):
            key = key.encode()

        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes long.")

        raw = base64.b64decode(encrypted_text)
        iv = raw[:8]
        ct = raw[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), DES.block_size)
        return pt.decode()

class DESCipherPass:
    backend = default_backend()

    @staticmethod
    def set_key(password):
        sha1 = hashlib.sha1(password.encode()).digest()
        return (sha1 + sha1)[:24]

    @staticmethod
    def encrypt(plaintext, password):
        key = DESCipherPass.set_key(password)
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=DESCipherPass.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode()

    @staticmethod
    def decrypt(ciphertext, password):
        try:
            key = DESCipherPass.set_key(password)
            encrypted_data = base64.b64decode(ciphertext)
            cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=DESCipherPass.backend)
            decryptor = cipher.decryptor()

            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
            decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

            return decrypted_data.decode()
        except Exception as e:
            return f"Error decrypting: {e}"
