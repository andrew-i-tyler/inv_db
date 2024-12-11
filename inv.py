import psycopg2
import getpass
from cryptography.fernet import Fernet

# Generate a key for encryption and decryption
# You should store this key securely
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password).decode()

def connect_to_db():
    try:
        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")
        
        encrypted_password = encrypt_password(password)
        
        connection = psycopg2.connect(
            dbname="sql_inv_db",
            user=username,
            password=decrypt_password(encrypted_password),
            host="localhost",
            port="5432"
        )
        print("Connection to database established successfully.")
        return connection
    except Exception as error:
        print(f"Error connecting to database: {error}")
        return None

if __name__ == "__main__":
    conn = connect_to_db()
    if conn:
        conn.close()