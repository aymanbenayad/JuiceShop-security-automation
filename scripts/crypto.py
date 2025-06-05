import pytest
from cryptography.fernet import Fernet

class TestEncryption:
    @classmethod
    def setup_class(cls):
        cls.key = Fernet.generate_key()
        cls.fernet = Fernet(cls.key)
        cls.test_strings = [
            "",
            "simple string",
            "special chars !@#$%^&*()",
            "1234567890",
            "a" * 1000  
        ]
        print(f"Generated Key: {cls.key.decode()}")

    @staticmethod
    def encryption(plain_text: str, key: bytes) -> bytes:
        f = Fernet(key)
        return f.encrypt(plain_text.encode())

    @staticmethod
    def decryption(cipher_text: bytes, key: bytes) -> str:
        f = Fernet(key)
        return f.decrypt(cipher_text).decode()

    def test_encryption_decryption_cycle(self):
        for test_str in self.test_strings:
            encrypted = TestEncryption.encryption(test_str, self.key)
            decrypted = TestEncryption.decryption(encrypted, self.key)
            print(f"\nOriginal: {test_str}")
            print(f"Encrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")
            assert decrypted == test_str

    def test_different_keys_fail(self):
        wrong_key = Fernet.generate_key()
        test_str = "test string"
        encrypted = TestEncryption.encryption(test_str, self.key)
        print(f"\nEncrypted with correct key: {encrypted}")
        print(f"Trying to decrypt with wrong key: {wrong_key.decode()}")
        with pytest.raises(Exception):
            TestEncryption.decryption(encrypted, wrong_key)

    def test_tampered_data_fails(self):
        test_str = "important data"
        encrypted = TestEncryption.encryption(test_str, self.key)
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF])
        print(f"\nOriginal encrypted: {encrypted}")
        print(f"Tampered encrypted: {tampered}")
        with pytest.raises(Exception):
            TestEncryption.decryption(tampered, self.key)

    def test_consistency(self):
        test_str = "repeated string"
        encrypted1 = TestEncryption.encryption(test_str, self.key)
        encrypted2 = TestEncryption.encryption(test_str, self.key)
        print(f"\nFirst encryption: {encrypted1}")
        print(f"Second encryption: {encrypted2}")
        assert encrypted1 != encrypted2
