class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift
        self.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def encrypt(self, plaintext):
        plaintext = plaintext.upper()
        ciphertext = ''
        
        for char in plaintext:
            if char in self.alphabet:
                index = (self.alphabet.index(char) + self.shift) % 26
                ciphertext += self.alphabet[index]
            else:
                ciphertext += char
        
        return ciphertext

    def decrypt(self, ciphertext):
        ciphertext = ciphertext.upper()
        plaintext = ''
        
        for char in ciphertext:
            if char in self.alphabet:
                index = (self.alphabet.index(char) - self.shift) % 26
                plaintext += self.alphabet[index]
            else:
                plaintext += char
        
        return plaintext

if __name__ == "__main__":
    shift = int(input("Enter the shift value: "))
    cipher = CaesarCipher(shift)
    
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().upper()
    if choice == 'E':
        plaintext = input("Enter the plaintext: ")
        encrypted = cipher.encrypt(plaintext)
        print(f"Encrypted text: {encrypted}")
    elif choice == 'D':
        ciphertext = input("Enter the ciphertext: ")
        decrypted = cipher.decrypt(ciphertext)
        print(f"Decrypted text: {decrypted}")
    else:
        print("Invalid choice!")
