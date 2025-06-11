import pytest

try:
    from core.cipher import AESCipherPass
except ModuleNotFoundError:
    pytest.skip("cryptography not installed", allow_module_level=True)


def test_aes_cipher_roundtrip():
    plain = "hello world"
    pw = "secret"
    encrypted = AESCipherPass.encrypt(plain, pw)
    decrypted = AESCipherPass.decrypt(encrypted, pw)
    assert decrypted == plain
