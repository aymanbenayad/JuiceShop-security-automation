import pytest
from cryptography.fernet import Fernet
from testCrypto import encryption, decryption  

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

    def test_encryption_decryption_cycle(self):
        """Test that encryption + decryption returns original data"""
        for test_str in self.test_strings:
            encrypted = encryption(test_str, self.key)
            assert encrypted != test_str  
            decrypted = decryption(encrypted, self.key)
            assert decrypted == test_str

    def test_different_keys_fail(self):
        """Test that wrong key fails decryption"""
        wrong_key = Fernet.generate_key()
        test_str = "test string"
        encrypted = encryption(test_str, self.key)
        with pytest.raises(Exception):  
            decryption(encrypted, wrong_key)

    def test_tampered_data_fails(self):
        """Test that modified ciphertext fails decryption"""
        test_str = "important data"
        encrypted = encryption(test_str, self.key)
        # Tamper with the encrypted data
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF])
        with pytest.raises(Exception):
            decryption(tampered, self.key)

    def test_consistency(self):
        """Test that same input produces different ciphertexts (IV should change)"""
        test_str = "repeated string"
        encrypted1 = encryption(test_str, self.key)
        encrypted2 = encryption(test_str, self.key)
        assert encrypted1 != encrypted2  # Different IVs should produce different ciphertexts

