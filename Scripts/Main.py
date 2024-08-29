from keyGen import RSAKeyGen
from Encryptor import Encryptor
from Decryptor import Decryptor


print("=============MAIN MENU=============")
print("Select an option to continue...")
print("\n")
print("1) Generate RSA keys")
print("2) Encrypt a file")
print("3) Decrypt a file")
print("===================================")
choice = input("Type in the number to select the option (Default option = 2): ")
print("\n")

if choice == "1":
    rsaKeyGen = RSAKeyGen()
    print("============RSA KEY-GEN============")
    pvt_key_path = input("Enter the path where you want to save your RSA private key (with key file name): ")
    pvt_key_path += ".pem"
    pub_key_path = input("Enter the path where you want to save your RSA public key (with key file name): ")
    pub_key_path += ".pem"
    rsaKeyGen.generate_keys()
    rsaKeyGen.private_key_to_pem(pvt_key_path)
    rsaKeyGen.public_key_to_pem(pub_key_path)

elif choice == "2":
    file_enc = Encryptor()
    print("==========File Encryptor==========")
    in_file = input("Enter the path to file which you want to encypt: ")
    out_file = input("Enter the path where you want to save the file (with file name): ")
    src_pvt_key = input("Enter the path to your private key: ")
    des_pub_key = input("Enter the path to reciever's public key: ")
    out_file += ".AVEC"
    print("Encrypting file...")
    file_enc.encrypt_file(in_file)
    file_enc.encrypt_aes_key(src_pvt_key, des_pub_key)
    file_enc.write_encrypted_file(out_file)

elif choice == "3":
    
    print("==========File Decryptor==========")
    in_file = input("Enter the path to file which you want to decypt: ")
    out_file = input("Enter the path where you want to save the file (with file name and extension): ")
    des_pvt_key = input("Enter the path to your private key: ")
    src_pub_key = input("Enter the path to senders public key: ")
    file_dec =Decryptor(src_pub_key)
    file_dec.decrypt_file(in_file, out_file,des_pvt_key)