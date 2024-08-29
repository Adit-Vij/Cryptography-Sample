import base64
from keyGen import AESKeyGen
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

class Encryptor:
    def __init__(self):
        self.aes_key = None
        self.cipher_text = None
        self.cipher_key = None
        self.enc_file = None
        self.kg = AESKeyGen()
        self.aes_key = self.kg.generate_key()

    def pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def encrypt_file(self, file_path):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f:
            plain_text = f.read()

        # Apply padding
        padded_plain_text = self.pad(plain_text)

        # Encrypt the file
        self.cipher_text = iv + encryptor.update(padded_plain_text) + encryptor.finalize()

    def encrypt_aes_key(self, src_private_key_path, dest_public_key_path):
        try:
            # Load the source's RSA private key
            with open(src_private_key_path, 'rb') as pem_in:
                src_private_key = serialization.load_pem_private_key(
                    pem_in.read(),
                    password=None,
                    backend=default_backend()
                )

            # Load the destination's RSA public key
            with open(dest_public_key_path, 'rb') as pem_in:
                dest_public_key = serialization.load_pem_public_key(
                    pem_in.read(),
                    backend=default_backend()
                )

            # Encrypt the AES key with the destination's public key
            encrypted_aes_key = dest_public_key.encrypt(
                self.aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # Sign the encrypted AES key with the source's private key
            signature = src_private_key.sign(
                encrypted_aes_key,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Combine the encrypted AES key and the signature
            self.cipher_key = encrypted_aes_key + signature

        except Exception as e:
            print(f"Encryption failed: {e}")
            return None

    def write_encrypted_file(self, encrypted_file_path):
        try:
            with open(encrypted_file_path, 'wb') as f_out:
                # Write the length of the cipher_key followed by the cipher_key and cipher_text
                f_out.write(len(self.cipher_key).to_bytes(4, byteorder='big'))
                f_out.write(self.cipher_key)
                f_out.write(self.cipher_text)

            print(f"Encrypted file successfully written to: {encrypted_file_path}")

        except (OSError, IOError) as e:
            print(f"Failed to write the encrypted file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")