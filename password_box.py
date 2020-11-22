import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import getpass
import sqlite3
import random

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

    def decrypt_db(self, key, db_name):
        fernet = Fernet(key)
        with open(db_name, "rb") as f:
            data = f.read()
        decrypted = fernet.decrypt(data)
        with open(db_name, "wb") as f:
            f.write(decrypted)

    def encode_pwd_string(self, pwd):
        encoded = pwd.encode()
        return encoded

#PWDGenerator
class PWDGenerator:
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "0123456789"
    symbols = "!@#$%&*"

    def generate(self, lowerbool, upperbool, numsbool, symsbool, length):
        pool = ""
        if lowerbool:
            pool += self.lowercase
        if upperbool:
            pool += self.uppercase
        if numsbool:
            pool += self.numbers
        if symsbool:
            pool += self.symbols
        length_int = int(length)
        pwd = "".join(random.sample(pool, length_int))
        return pwd

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

    ### New Additions for Tonight 11/21/20 ###
    def delete_from_table(self, cursor, service):
        temp_tuple = (service,)
        cursor.execute("DELETE FROM passwords WHERE service=?", temp_tuple)

#UIHandler
class UIHandler:
    def get_pwd_from_user(self, output_string):
        pwd = getpass.getpass(output_string)
        return pwd

    def get_input_from_user(self, output_string):
        user_input = input(output_string)
        return user_input

def main():
    dbmanager = DBManager()
    uihandler = UIHandler()
    cryptoengine = CryptoEngine()

    if (os.path.isfile("pwd.db")) and (os.path.isfile("salt")):
        pwd = uihandler.get_pwd_from_user("Please enter your master password to decrypt your password database:")
        encoded_pwd = cryptoengine.encode_pwd_string(pwd)
        key = cryptoengine.get_key(encoded_pwd, cryptoengine.get_salt())
        cryptoengine.decrypt_db(key, "pwd.db")
        connection = dbmanager.get_db_connection("pwd.db")
        cursor = dbmanager.get_db_cursor(connection)
        loop_token = 1
        while loop_token == 1:
            print(" _____Main Menu_______________________________________")
            print("|                                                     |")
            print("| 1 - Get a saved password from the password database |")
            print("| 2 - Add a password to the password database         |")
            print("| 3 - Delete a password from the password database    |")
            print("| 0 - Encrypt password database and exit              |")
            print("|                                                     |")
            print(" -----------------------------------------------------")
            selection = uihandler.get_input_from_user("Please enter the number of the action you would like to take: ")
            if selection == "0":
                dbmanager.commit_changes(connection)
                dbmanager.close_db_connection(connection)
                cryptoengine.encrypt_db(key, "pwd.db")
                loop_token = 0
            if selection == "1":
                service = uihandler.get_input_from_user("Please enter the name of the service you would like the password for: ")
                result_pwd = dbmanager.get_pwd_from_table(cursor, service)
                print("The password for " + service + " is " + result_pwd)
            if selection == "2":
                new_service = uihandler.get_input_from_user("Please enter the name of the service you would like to add: ")
                pwd_option = uihandler.get_pwd_from_user("Please enter 0 if you would like password_box to generate a strong password.\nAlternatively, enter 1 if you would like to manually supply the password.")
                if pwd_option == "0":
                    pwdgenerator = PWDGenerator()
                    length = uihandler.get_input_from_user("Please enter the desired length of the password: ")
                    use_upper = uihandler.get_input_from_user("Should the password include uppercase in addition to lowercase letters (y or n)? ")
                    use_nums = uihandler.get_input_from_user("Should the password also include numbers (y or n)? ")
                    use_syms = uihandler.get_input_from_user("Should the password also include special symbols (y or n)? ")
                    upperbool, numsbool, symsbool = False, False, False
                    if use_upper == "y":
                        upperbool = True
                    if use_nums == "y":
                        numsbool = True
                    if use_syms == "y":
                        symsbool = True
                    new_pwd = pwdgenerator.generate(True, upperbool, numsbool, symsbool, length)
                if pwd_option == "1":
                    new_pwd = uihandler.get_pwd_from_user("Please enter the password to be used for " + new_service + ":")
                dbmanager.insert_pwd(cursor, new_service, new_pwd)
            if selection == "3":
                service_to_del = uihandler.get_input_from_user("Please enter the service to delete: ")
                dbmanager.delete_from_table(cursor, service_to_del)
    else:
        connection = dbmanager.get_db_connection("pwd.db") #Get connection and create pwd.db database file
        cursor = dbmanager.get_db_cursor(connection) #Get cursor object
        dbmanager.make_pwd_table(cursor) #Create passwords table in pwd.db
        dbmanager.commit_changes(connection) #Commit changes to pwd.db
        dbmanager.close_db_connection(connection) #Close connection to pwd.db

        cryptoengine.generate_salt_file() #Create salt file

        #Get user to input a master password for their password database 
        pwd = uihandler.get_pwd_from_user("Please enter a master password to encrypt your password database:")

        encoded_pwd = cryptoengine.encode_pwd_string(pwd) #Encode the string pwd to bytes

        key = cryptoengine.get_key(encoded_pwd, cryptoengine.get_salt()) #Generate master key

        cryptoengine.encrypt_db(key, "pwd.db") #Encrypt pwd.db

        print(" _________________________________________________________")
        print("|                                                         |")
        print("| Password_box has been initialized.                      |")
        print("| Please remember your master password.                   |")
        print("| It will be required to decrypt your password database.  |")
        print("| Please restart the program to start using password_box. |")
        print("|                                                         |")
        print(" ---------------------------------------------------------")

main()
