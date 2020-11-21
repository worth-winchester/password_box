import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import getpass
import sqlite3

#CryptoEngine
class CryptoEngine:
    def get_key(self, pwd, salt):
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(pwd))
        return key

    def generate_salt_file(self):
        salt = os.urandom(16)
        with open("salt", "wb") as f:
            f.write(salt)

    def get_salt(self):
        with open("salt", "rb") as f:
            salt = f.read()
            return salt

    def encrypt_db(self, key, db_name):
        fernet = Fernet(key)
        with open(db_name, "rb") as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(db_name, "wb") as f:
            f.write(encrypted)

    def decrypt_file(self, key, db_name):
        fernet = Fernet(key)
        with open(db_name, "rb") as f:
            data = f.read()
        decrypted = fernet.decrypt(data)
        with open(db_name, "wb") as f:
            f.write(decrypted)

    def encode_pwd_string(self, pwd):
        encoded = pwd.encode()
        return encoded

#DBManager
class DBManager:
    def get_db_connection(self, db_name):
        connection = sqlite3.connect(db_name)
        return connection

    def close_db_connection(self, connection):
        connection.close()

    def get_db_cursor(self, connection):
        cursor = connection.cursor()
        return cursor
    
    def make_pwd_table(self, cursor):
        cursor.execute('''CREATE TABLE passwords (service text, pwd text)''')
    
    def insert_pwd(self, cursor, service, pwd):
        temp_tuple = (service, pwd)
        cursor.execute("INSERT INTO passwords VALUES (?, ?)", temp_tuple)

    def commit_changes(self, connection):
        connection.commit()

    def get_pwd_from_table(self, cursor, service):
        temp_tuple = (service,)
        cursor.execute("SELECT pwd FROM passwords WHERE service=?", temp_tuple)
        pwd_tuple = cursor.fetchone()
        pwd, = pwd_tuple
        return pwd

#UIHandler
class UIHandler:
    def get_pwd_from_user(self, output_string):
        pwd = getpass.getpass(output_string)
        return pwd

    def get_input_from_user(self, output_string):
        user_input = input(output_string)
        return user_input

def initialize():
    pass

def main():
    dbmanager = DBManager()
    uihandler = UIHandler()
    cryptoengine = CryptoEngine()

    if (os.path.isfile("pwd.db")) and (os.path.isfile("salt")):
        pass
    else:
        initialize()

#Start of Test
#dbmanager = DBManager()
#uihandler = UIHandler()
#connection = dbmanager.get_db_connection("pwd.db")
#c = dbmanager.get_db_cursor(connection)
#dbmanager.make_pwd_table(c)
#service = uihandler.get_input_from_user("Please provide the service you would like to add: ")
#pwd = uihandler.get_pwd_from_user("Please provide the password you would like to add: ")
#dbmanager.insert_pwd(c, service, pwd)
#dbmanager.commit_changes(connection)
#print(dbmanager.get_pwd_from_table(c, "github"))
#dbmanager.close_db_connection(c)
#End of Test
