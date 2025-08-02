import os
import sys
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

#i want to later make it show both encrypt and decrypt and list of encrypted files
#decrypt will decrypt using password when you pick from the list, encrypt will encrypt 
#figure out a way to make it so you can encrypt multiple files at once
#and decrypt multiple files at once, and also make it so you can choose to encrypt or
#figure out a way for the key to make it safer as right now it is in the source code

magic = b"QsLockerFootprint"
salt = b"QsSecureSalt123!"

def getKeyFromPassword(password: str, salt: bytes) -> bytes:
    passwordBytes = password.encode()  # convert string to bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwordBytes))
    return key

def encryptFile(fernet, filePath, username: str):
    if not os.path.isfile(filePath):
        print("❌ File not found.")
        return False
    with open(filePath, "rb") as file:
        originalData = file.read()
    if originalData.startswith(magic):
        print("❌ File already encrypted!")
        return False
    encryptedData = magic + fernet.encrypt(f"{username}::".encode() +originalData)

    os.remove(filePath)
    with open(filePath, "wb") as file:
        file.write(encryptedData)
    print(f"🔐 Encrypted: {filePath}")
    return filePath

def decryptFile(fernet, filePath, username: str):
    if not os.path.isfile(filePath):
        print("❌ Encrypted file not found.")
        return
    with open(filePath, "rb") as file:
        encryptedData = file.read()
    if not encryptedData.startswith(magic):
        print("❌ The file has not been encrypted using Q's Security Panel.")
        return False
    try:
        decryptedData = fernet.decrypt(encryptedData[len(magic):])
        owner, _, fileContent = decryptedData.partition(b"::")
        if owner.decode() != username:
            print("❌ You are not the owner of this file.")
            return False
    except Exception:
        print("❌ Invalid decryption key or corrupted file.")
        return False
    os.remove(filePath)
    with open(filePath, "wb") as file:
        file.write(fileContent)
    print(f"✅ Decrypted and restored: {filePath}")
    return filePath


def signUp(users):
    while True:
        username = input("SIGNING UP\nEnter your username:\n-- >    ").strip()
        if username in users:
            print("❌ Username already exists. Please choose a different username.")
            continue
        break
    password = input("Enter your password:\n-- >    ").strip()
    key = getKeyFromPassword(password, salt)
    users[username] = key.decode()  # Store key as a string
    with open("users.json", "w") as file:
        json.dump(users, file)
    return key, username

def login(users):
    while True:
        username = input("LOGGING IN\nEnter your username:\n-- >    ").strip()
        if username not in users:
            print("❌ Username not found. Please try again.")
            continue
        break
    
    while True:
        password = input("Enter your password:\n-- >    ").strip()
        key = getKeyFromPassword(password, salt)
        if key.decode() != users[username]:
            print("❌ Incorrect password. Please try again.")
            continue
        break
    return key, username
    

def main():
    
    if not os.path.exists("users.json"):
        with open("users.json","w") as file:
            json.dump({}, file) 
    
    with open("users.json", "r") as f:
        users = json.load(f)

    while True:
        initialAction = input("Would you like to login(1) or sign up(2)?\n-- >   ").strip().lower()
        if initialAction == "1" or initialAction == 1:
            key, username = login(users)
            break
        elif initialAction == "2" or initialAction == 2:
            key, username = signUp(users)
            break
        else:
            print("❌ Invalid option. Please choose '1' for login or '2' for sign up.")
            continue
    if not key:
        print("🔒 Access denied.")
        sys.exit()
    fernet = Fernet(key)
    while True:
        decision = input("""\n\nWelcome James // Would you like to decrypt or encrypt a file?
\n- e for Encryption\n- d for decryption\n- x for exit\n\n-- >     """).strip().lower()
        
        if decision=="e":
            filePath = input("Enter the file name you'd like to encrypt:\n-- >     ").strip()
            encryptedPath = encryptFile(fernet, filePath, username)
            if not encryptedPath:
                continue
        elif decision=="d":
            filePath = input("Enter the file name you'd like to decrypt:\n-- >     ").strip()
            decryptedPath = decryptFile(fernet, filePath, username)
            if not decryptedPath:
                continue
        elif decision=="x":
            print("Goodbye!")
            sys.exit()
        else:
            print("❌ Invalid option. Please choose 'e', 'd', or 'x'.")

if __name__ == "__main__":
    main()