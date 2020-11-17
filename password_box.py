import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import getpass
import sqlite3

#to generate salt run os.urandom(16)
#or run bcrypt.gensalt()

#def get_encryption_salt():
#    if os.path.isfile("encryption_salt") == False:
#        salt = os.urandom(16)
#        with open("encryption_salt", "wb") as f:
#            f.write(salt)
#    else:
#        with open("encryption_salt", "rb")as f:
#            salt = f.read()
#    return salt

#CryptoEngine
class CryptoEngine:
    def get_key(self, password, salt):
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def generate_salt_file(self):
        salt = os.urandom(16)
        with open("salt", "wb") as f:
            f.write(salt)

    def get_salt(self):
        with open("salt", "rb") as f:
            salt = f.read()
            return salt

    def encrypt_file(self, key, input_file):
        fernet = Fernet(key)
        with open(input_file, "rb") as f:
            original_data = f.read()
        encrypted = fernet.encrypt(original_data)
        with open("encrypted_file", "wb") as f:
            f.write(encrypted)

    def decrypt_file(self, key, encrypted_file):
        fernet = Fernet(key)
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        decrypted = fernet.decrypt(encrypted_data)
        with open("decrypted_file", 'wb') as f:
            f.write(decrypted)

#DBManager
class DBManager:
    def connect_to_db(self, database_name):
        connection = sqlite3.connect(database_name)
        return connection

    def close_db_connection(self, connection):
        connection.close()

    def insert_service_pwd(self, connection, service, pwd):
        connection.execute("INSERT INTO PASSWORDS (SERVICE,PASSWORD) \
            VALUES (" + str(service) + ", " + str(pwd) + ");")

#UIHandler
class UIHandler:
    def get_password(self, output_string):
        user_input = getpass.getpass(output_string)
        password = user_input.encode()
        return password

#Initialize
def initialize(connection, cryptoengine, uihandler):
    connection.execute("""CREATE TABLE PASSWORDS
                    (SERVICE    TEXT    NOT NULL,
                    PASSWORD    TEXT    NOT NULL);""")

    cryptoengine.generate_salt_file()

    salt = cryptoengine.get_salt()
    password = uihandler.get_password("Please enter a password to setup password_box:")

    key = cryptoengine.get_key(password, salt)

    cryptoengine.encrypt_file(key, "pwd.db") 

    print("Database has been initialized and encrypted. Please restart password_box.")

#Main
def main():
    database_manager = DBManager()
    crypto_engine = CryptoEngine()
    ui_handler = UIHandler()

    connection = database_manager.connect_to_db("pwd.db")

    if os.path.isfile("salt") == False:
        initialize(connection, crypto_engine, ui_handler)
    else:
        pass

    connection.close()

main()
