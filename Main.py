import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def Encrypt_key(key):
    password = key.encode()
    salt = b'\x16\x00\xe2\xf6\xd1\xf0c%3\xed\xe0\x87\xba\x11\x17\xed'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,)
    E_key = base64.urlsafe_b64encode(kdf.derive(password))
    print(E_key)
    return E_key


if __name__ == "__main__":
    key = input("Enter Key : ")
    E_key = Encrypt_key(key)
    f = Fernet(E_key)
    message = "Secrete Meaasge".encode()
    token = f.encrypt(message)
    print("Encripted Message : ",token)
    d_m  = f.decrypt(token).decode()
    print("Decrepted Message : ",d_m)
    print("Finished")
