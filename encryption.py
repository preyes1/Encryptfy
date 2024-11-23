from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode

class Encryptor:
    def __init__(self, key):
        self.key=key

    # padding method to ensure input data is 16 bytes in length
    # AES.block_size = 16 since AES uses block sizes of 16 bytes
    def pad(self,s):
        return s+b"\0" * (AES.block_size - len(s) % AES.block_size)
    
    # IV is used so that even if a person encrypts the same plaintext with the same key 
    # multiple times, it will still produce different ciphertexts
    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        # Creates the cipher text using AES CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Data is encrypted and iv is prepended to easily extract both
        return iv + cipher.encrypt(message)
    
    def decrypt(self, cipherText, key):
        iv = cipherText[:AES.block_size]
        print("aaaa")
        print(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(cipherText[AES.block_size:])
        print(plaintext.hex())
        # removes the padding added
        return plaintext.rstrip(b"\0")
