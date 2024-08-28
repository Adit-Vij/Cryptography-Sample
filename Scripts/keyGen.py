from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

class AESKeyGen:
    def __init__(self):
        self.KEY_LENGTH = 32

    def generate_key(self):
        return os.urandom(self.KEY_LENGTH)
    
class RSAKeyGen:
    def __init__(self):
        self.KEY_LENGTH = 4096
    
    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.KEY_LENGTH,
            backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def private_key_to_pem(self, private_key):
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption)
        return pem

    def public_key_to_pem(self, public_key):
        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem
