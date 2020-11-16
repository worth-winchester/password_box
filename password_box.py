import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import getpass
import bcrypt
import sqlite3

#to generate salt run os.urandom(16)
#or run bcrypt.gensalt()
#salt = b'\xd2\xb5\x12\xbd\xf3\x87\xa2\x1b\xac\xd7\xa5\xbe'

### Getting User Input ###
def get_password():
    user_input = getpass.getpass("Please enter your password:")
    password = user_input.encode()
    return password

def get_username():
    user_input = input("Please enter your username:")
    username = user_input.encode()
    return username

### Symmetrical Encryption Functions ###
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

#def get_encryption_salt():
#    if os.path.isfile("encryption_salt") == False:
#        salt = os.urandom(16)
#        with open("encryption_salt", "wb") as f:
#            f.write(salt)
#    else:
#        with open("encryption_salt", "rb")as f:
#            salt = f.read()
#    return salt

def get_encryption_salt():
    salt = os.urandom(16)
    return salt

def encrypt_file(key, input_file):
    fernet = Fernet(key)
    with open(input_file, "rb") as f:
        original_data = f.read()
    encrypted = fernet.encrypt(original_data)
    with open("encrypted_file", "wb") as f:
        f.write(encrypted)

def decrypt_file(key, encrypted_file):
    fernet = Fernet(key)
    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()
    decrypted = fernet.decrypt(encrypted_data)
    with open("decrypted_file", 'wb') as f:
        f.write(decrypted)

### Hashing Functions ###
def get_hash(item_to_hash, salt):
    hashed = bcrypt.hashpw(item_to_hash, salt)
    return hashed

def get_static_hash_salt():
    if os.path.isfile("static_hash_salt") == False:
        salt = bcrypt.gensalt()
        with open("static_hash_salt", "wb") as f:
            f.write(salt)
    else:
        with open("static_hash_salt", "rb")as f:
            salt = f.read()
    return salt

def get_hash_salt():
    salt = bcrypt.gensalt()
    return salt

def check_hash(input_hash, saved_hash):
    if input_hash == saved_hash:
        return True
    else:
        return False

### SQL Database Management ###

### Reusable DB Functions ###
def connect_to_db(database_name):
    connection = sqlite3.connect(database_name)
    return connection

def close_db_connection(connection):
    connection.close()

def insert_service_pwd(service, pwd):
    connection0.execute("INSERT INTO PASSWORDS (SERVICE,PASSWORD) \
        VALUES (" + str(service) + ", " + str(pwd) + ");")

### START: Create DBs and Tables Initially ###
#   Run the following lines to create the initial databases
#   and tables for these databases
#   one database to hold the services and associated passwords
#   and a second database to hold hashes and salts
#   also create static_salt

connection0 = connect_to_db("pwd.db") #Create database for passwords; will be encrypted
connection1 = connect_to_db("hash.db") #Create database for hashes and salts; will not be encrypted

#create a table that holds services and passwords for password db
connection0.execute("""CREATE TABLE PASSWORDS
                (SERVICE    TEXT    NOT NULL,
                PASSWORD    TEXT    NOT NULL);""")

#create a table that holds hashes and salts used for authentication
connection1.execute("""CREATE TABLE HASHES-AND-SALTS
                (USERNAME-HASH  TEXT    NOT NULL,
                USER-SALT0      TEXT    NOT NULL,
                PWD-HASH        TEXT    NOT NULL,
                USER-SALT1      TEXT    NOT NULL);""")

connection0.close()
connection1.close()

static_salt = get_static_hash_salt()
### END: Create DBs and Tables Initially ###

### Add New User ###
username = get_username()
username_hash = get_hash(username, get_static_hash_salt())
user_salt0 = get_hash_salt()
pwd_hash = get_hash(get_password(), user_salt0)
user_salt1 = get_encryption_salt()
