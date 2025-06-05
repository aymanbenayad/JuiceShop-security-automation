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
            encrypted = self.encryption(test_str, self.key)
            decrypted = self.decryption(encrypted, self.key)
            print(f"\nOriginal: {test_str}")
            print(f"Encrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")
            assert decrypted == test_str

    def test_different_keys_fail(self):
        wrong_key = Fernet.generate_key()
        test_str = "test string"
        encrypted = self.encryption(test_str, self.key)
        print(f"\nEncrypted with correct key: {encrypted}")
        print(f"Trying to decrypt with wrong key: {wrong_key.decode()}")
        try:
            self.decryption(encrypted, wrong_key)
            print("ERROR: Decryption with wrong key unexpectedly succeeded")
        except Exception as e:
            print("Correctly failed to decrypt with wrong key.")

    def test_tampered_data_fails(self):
        test_str = "important data"
        encrypted = self.encryption(test_str, self.key)
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF])
        print(f"\nOriginal encrypted: {encrypted}")
        print(f"Tampered encrypted: {tampered}")
        try:
            self.decryption(tampered, self.key)
            print("ERROR: Decryption of tampered data unexpectedly succeeded")
        except Exception:
            print("Correctly failed to decrypt tampered data.")

    def test_consistency(self):
        test_str = "repeated string"
        encrypted1 = self.encryption(test_str, self.key)
        encrypted2 = self.encryption(test_str, self.key)
        print(f"\nFirst encryption: {encrypted1}")
        print(f"Second encryption: {encrypted2}")
        assert encrypted1 != encrypted2


def main():
    test = TestEncryption()
    test.setup_class()

    test.test_encryption_decryption_cycle()
    test.test_different_keys_fail()
    test.test_tampered_data_fails()
    test.test_consistency()

if __name__ == "__main__":
    main()
