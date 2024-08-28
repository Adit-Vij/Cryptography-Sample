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
            key_size=self.key_size,
            backend=default_backend()
        )