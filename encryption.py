from Cryptodome import Random
from Cryptodome.Cipher import AES
from base64 import b64encode
import os


class Encryptor:
    def __init__(self, key):
        self.key = key

    # padding method to ensure input data is 16 bytes in length
    # AES.block_size = 16 since AES uses block sizes of 16 bytes
    def pad(self,s):
        return s+b"\0" * (AES.block_size - len(s) % AES.block_size)
    
    # IV is used so that even if a person encrypts the same plaintext with the same key 
    # multiple times, it will still produce different ciphertexts
    def encrypt(self, message, key, key_size=256):

        # Pads the message and generates a random 16 byte IV
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)

        # Creates the cipher text using AES CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Data is encrypted and iv is prepended to easily extract both
        return iv + cipher.encrypt(message)
    
    def decrypt(self, cipherText, key):

        # Retreives the IV from the cipher text (first 16 bytes)
        iv = cipherText[:AES.block_size]
        
        # Removes the key salt from the cipherText
        cipherText = cipherText[:-16]

        # Generates the cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Have to skip the first 16 bytes because the first 16 bytes
        # is the initialization vector
        # This caused a super headache lol
        plaintext = cipher.decrypt(cipherText[AES.block_size:])
        print("PLAINTEXT: ", plaintext)

        # removes the padding added
        return plaintext.rstrip(b"\0")
        
