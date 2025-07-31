import os
import sys
import base64
import hashlib
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
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwordBytes))
    return key

def encryptFile(fernet, filePath):
    if not os.path.isfile(filePath):
        print("❌ File not found.")
        return False
    with open(filePath, "rb") as file:
        originalData = file.read()
    if originalData.startswith(magic):
        print("❌ File already encrypted!")
        return False
    encryptedData = magic + fernet.encrypt(originalData)

    os.remove(filePath)
    with open(filePath, "wb") as file:
        file.write(encryptedData)
    print(f"🔐 Encrypted: {filePath}")
    return filePath

def decryptFile(fernet, filePath):
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
    except Exception:
        print("❌ Invalid decryption key or corrupted file.")
        return False
    os.remove(filePath)
    with open(filePath, "wb") as file:
        file.write(decryptedData)
    print(f"✅ Decrypted and restored: {filePath}")
    return filePath

def main():
    password = input("Enter your password: ")
    key = getKeyFromPassword(password, salt)   
    fernet = Fernet(key)
    while True:
        decision = input("""\n\nWelcome James // Would you like to decrypt or encrypt a file?
\n- e for Encryption\n- d for decryption\n- x for exit\n\n-- >     """).strip().lower()
        
        if decision=="e":
            filePath = input("Enter the file name you'd like to encrypt:\n-- >     ").strip()
            encryptedPath = encryptFile(fernet, filePath)
            if not encryptedPath:
                continue
        elif decision=="d":
            filePath = input("Enter the file name you'd like to decrypt:\n-- >     ").strip()
            decryptedPath = decryptFile(fernet, filePath)
            if not decryptedPath:
                continue
        elif decision=="x":
            print("Goodbye!")
            sys.exit()
        else:
            print("❌ Invalid option. Please choose 'e', 'd', or 'x'.")


if __name__ == "__main__":
    main()
