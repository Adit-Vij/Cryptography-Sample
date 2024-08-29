import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class Decryptor:
    def __init__(self, sender_public_key_path):
        self.aes_key = None
        self.cipher_text = None
        self.cipher_key = None
        self.sender_public_key_path = sender_public_key_path

    def unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

    def decrypt_file(self, encrypted_file_path, dest_file_path, private_key_path):
        try:
            # Load the recipient's RSA private key
            with open(private_key_path, 'rb') as pem_in:
                private_key = serialization.load_pem_private_key(
                    pem_in.read(),
                    password=None,
                    backend=default_backend()
                )

            # Load the sender's RSA public key
            with open(self.sender_public_key_path, 'rb') as pem_in:
                sender_public_key = serialization.load_pem_public_key(
                    pem_in.read(),
                    backend=default_backend()
                )

            # Read the encrypted file
            with open(encrypted_file_path, 'rb') as f_in:
                key_length = int.from_bytes(f_in.read(4), byteorder='big')
                self.cipher_key = f_in.read(key_length)
                self.cipher_text = f_in.read()

            # Verify the signature using the sender's public key
            encrypted_aes_key, signature = self.cipher_key[:-256], self.cipher_key[-256:]
            sender_public_key.verify(
                signature,
                encrypted_aes_key,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Decrypt the AES key using the recipient's private key
            self.aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # Decrypt the file content
            iv = self.cipher_text[:16]
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(self.cipher_text[16:]) + decryptor.finalize()

            # Remove padding
            plain_text = self.unpad(decrypted_data)

            # Write the decrypted content to the destination file
            with open(dest_file_path, 'wb') as f_out:
                f_out.write(plain_text)

            print(f"Decrypted file successfully written to: {dest_file_path}")

        except Exception as e:
            print(f"Decryption failed: {e}")