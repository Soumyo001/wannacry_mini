from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import os

password = "hello"
salt = get_random_bytes(16)
key = password.encode().ljust(32, b'\0')[:32]

def encrypt_file(file_path, key):
    try:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        open(file_path+'.encrypted', 'wb').write(salt + iv + encrypted_data)
        os.remove(file_path)
        print(f"Successfully encrypted: {file_path}")
    except Exception as e:
        print(f"Error encrypting: {file_path}\n{e}")

if __name__ == "__main__":
    file_path = "/home/defalt/Downloads/check.cpp"
    if os.path.exists(file_path):
        encrypt_file(file_path, key)
    else: print(f"File not found error: {file_path}")
