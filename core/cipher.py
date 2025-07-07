from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
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
    backend = default_backend()

    @staticmethod
    def encrypt(plaintext, key):
        if len(key) != 24:
            raise ValueError("Triple DES key must be 24 bytes long.")

        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=DESCipher.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt(encrypted_text, key):
        if len(key) != 24:
            raise ValueError("Triple DES key must be 24 bytes long.")

        encrypted_data = base64.b64decode(encrypted_text)
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=DESCipher.backend)
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_data.decode()

class DESCipherPass:
    backend = default_backend()

    @staticmethod
    def set_key(password):
        sha1 = hashlib.sha1(password.encode()).digest()
        return (sha1 + sha1)[:24]  # Make 24-byte key for TripleDES

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
