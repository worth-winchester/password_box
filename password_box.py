import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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
    if os.path.isfile("salt.txt") == False:
        salt = os.urandom(16)
        with open("salt.txt", "w") as f:
            f.write(str(salt))
    else:
        with open("salt.txt", "r")as f:
            salt = f.read().encode()
    return salt

password = get_password()
salt = get_salt()
key = get_key(password, salt)

print(password)
print(salt)
print(key)