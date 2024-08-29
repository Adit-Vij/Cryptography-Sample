from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

class AESKeyGen:
    def __init__(self):
        self.KEY_LENGTH = 16  # 128-bit AES key length

    def generate_key(self):
        return os.urandom(self.KEY_LENGTH)
    
class RSAKeyGen:
    def __init__(self):
        self.KEY_LENGTH = 4096
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.KEY_LENGTH,
            backend=default_backend())
        public_key = private_key.public_key()
        self.private_key = private_key
        self.public_key = public_key

    def private_key_to_pem(self, file_path):
        try:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(file_path, 'wb') as pem_out:
                pem_out.write(pem)
                print(f"Private key written to {file_path}")
        except (OSError, IOError) as e:
            print(f"Failed to write to {file_path}: {e}")

    def public_key_to_pem(self, file_path):
        try:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(file_path, 'wb') as pem_out:
                pem_out.write(pem)
                print(f"Public key written to {file_path}")
        except (OSError, IOError) as e:
            print(f"Failed to write to {file_path}: {e}")