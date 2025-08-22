import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

password = "hello"
key = password.encode().ljust(32, b'\0')[:32]

def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            encrypted_data = f.read()
    
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrpted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        original_file_path = file_path.replace('.encrypted', '')

        open(original_file_path, 'wb').write(decrpted_data)
        os.remove(file_path)
        print(f"Successfully decrypted: {file_path}")
    except Exception as e:
        print(f"Failed to decrypt file: {e}")

if __name__ == "__main__":
    file_path = "/home/defalt/Downloads/check.cpp.encrypted"
    if os.path.exists(file_path):
        decrypt_file(file_path, key)
    else:
        print(f"Decryption error, file: {file_path} does not exist")
