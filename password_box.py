import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import getpass

#to generate salt run os.urandom(16)
#salt = b'\xd2\xb5\x12\xbd\xf3\x87\xa2\x1b\xac\xd7\xa5\xbe'

def get_password():
    user_input = getpass.getpass("Please enter your password:")
    password = user_input.encode()
    return password

def get_key(password, salt):
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def get_salt():
    if os.path.isfile("salt_file") == False:
        salt = os.urandom(16)
        with open("salt_file", "wb") as f:
            f.write(salt)
    else:
        with open("salt_file", "rb")as f:
            salt = f.read()
    return salt

def encrypt(key, input_file):
    fernet = Fernet(key)
    with open(input_file, "rb") as f:
        original_data = f.read()
    encrypted = fernet.encrypt(original_data)
    with open("encrypted_file", "wb") as f:
        f.write(encrypted)

def decrypt(key, encrypted_file):
    fernet = Fernet(key)
    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()
    decrypted = fernet.decrypt(encrypted_data)
    with open("decrypted_file", 'wb') as f:
        f.write(decrypted)

password = get_password()
print(password)
salt = get_salt()
print(salt)
key = get_key(password, salt)
print(key)
input_file = "input.txt"
encrypt(key, input_file)
print("File Encrypted")
encrypted_file = "encrypted_file"
decrypt(key, encrypted_file)
print("File Decrypted")
