from flask import Flask, render_template, request, send_file, after_this_request
from encryption import *
from methods import derive_key
import os
import tempfile

app = Flask(__name__)

# Global variables to make code easier to read
MAX_INPUT_LENGTH = 1000
KEY_LENGTH = 16

# Default home page, gives info as to what AES is
@app.route('/', methods=["POST", "GET"])
def home():
    return render_template('index.html', active_page="home") 

# Encrypt message page
@app.route('/encrypt', methods=["POST", "GET"])
def encrypt():
    cipherTextHex=""
    if request.method == "POST":
        # Gets user input
        plaintext = request.form["plaintext"]
        key = request.form["key"]

        # Returns error message if an input box is empty
        if not plaintext or not key:
            return render_template('encrypt.html', cipherText="Please enter message and key", active_page="encrypt")
        
        # Limit plaintext to 1000 characters
        if len(plaintext) > MAX_INPUT_LENGTH:  
            return render_template('encrypt.html', cipherText="Plaintext is too large!", active_page="encrypt")

        # Ensure the key is 16 characters after processing
        if len(key) != KEY_LENGTH:  
            return render_template('encrypt.html', cipherText="Key must be 16 characters!", active_page="encrypt")

        # Generates random salt
        salt = os.urandom(16)

        # Gets derived key from key and salt (KDF)
        key=derive_key(key, salt)
        enc = Encryptor(key)

        # have to encode plaintext 
        cipherText = enc.encrypt(plaintext.encode(), key)

        # Appends salt to the ciphertext so we're able to decrypt
        cipherTextHex = cipherText.hex() + salt.hex()
        """
                cipherTextHex[-32:] gets the salt since the salt is 16 bytes
                and each byte is TWO characters
        """
    return render_template('encrypt.html', cipherText=cipherTextHex, active_page="encrypt")

# Decrypt message page
@app.route('/decrypt', methods=["POST", "GET"])
def decrypt():
    plainText=""
    if request.method == "POST":
        # Gets user input
        cipherText = request.form["ciphertext"]
        key = request.form["key"]

        # If statement ensures there is input in both boxes
        if not cipherText or not key:
            return render_template('decrypt.html', plainText="Please enter ciphertext and key", active_page="decrypt")
        
        # Retreives salt from the ciphertext
        salt = bytes.fromhex(cipherText[-32:])
        key=derive_key(key, salt)
    
        enc = Encryptor(key)

        # Ensures length of cipherText is valid
        if not len(cipherText) % 16 == 0:
            return render_template('decrypt.html', plainText="Invalid ciphertext length, must be a multiple of 16", active_page="decrypt")
        
        # Gives error message if wrong key is put
        try:
            # Have to convert cipherText back into a bytes object
            plainText = enc.decrypt(bytes.fromhex(cipherText), key)
            # Reverts plainText back from a bytes object to a String object
            return render_template('decrypt.html', plainText=plainText.decode(), active_page="decrypt")
               
        except:
            return render_template('decrypt.html', plainText="Invalid input", active_page="decrypt")
    
    return render_template('decrypt.html', active_page="decrypt")

# Encrypt File Page
@app.route('/encrypt-file', methods=["POST", "GET"])
def encrypt_file():
    if request.method == "POST": 
        try:
            # Gets file and key from HTML Form
            file = request.files.get("file")
            key = request.form["key"]

            # Returns if file or key is empty
            if not file or not key:
                return render_template('encrypt_file.html', active_page = "encrypt_file")

            # Ensures key is 16 bytes long
            if len(key) != KEY_LENGTH:  
                return render_template('encrypt_file.html', active_page="encrypt_file")

            # Generates random salt
            salt = os.urandom(16)

            # Gets derived key from key and salt (KDF)
            key=derive_key(key, salt)
            enc = Encryptor(key)

            # Reads file content and gets file name
            file_content = file.read()
            file_name = file.filename

            # Encrypts file content and appends salt to it
            enc_content = enc.encrypt(file_content, key)
            enc_content = enc_content + salt
        
            # Creating temp file so no information is stored
            # mode = wb means it will write bytes
            temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')  
            temp_file.write(enc_content)
            temp_file.flush()
            temp_file.close()

            # Return the encrypted file for download
            response = send_file(temp_file.name, as_attachment=True, download_name=file_name + ".enc")
            return response
        
        except:
            return render_template('encrypt_file.html', active_page = "encrypt_file")
        
    return render_template('encrypt_file.html', active_page = "encrypt_file")

# Decrypt File Page
@app.route('/decrypt-file', methods=["POST", "GET"])
def decrypt_file():
    if request.method == "POST": 
        try:
            # Gets file and key from HTML Form
            file = request.files.get("file")
            key = request.form["key"]

            # Returns if file or key is empty
            if not file or not key:
                return render_template('encrypt_file.html', active_page = "encrypt_file")

            # Ensures key is 16 bytes long
            if len(key) != KEY_LENGTH:  
                return render_template('encrypt_file.html', active_page="encrypt_file")

            # Reads file content and gets file name
            file_content = file.read()
            file_name = file.filename

            # Retreives salt from ciphertext
            # Its only [-16:] here because it's already in bytes
            # format, [-32:] is only when ciphertext is in
            # hexadecimal
            salt = file_content[-16:]

            # Gets derived key from key and salt (KDF)
            key=derive_key(key, salt)
            enc = Encryptor(key)

            # Decrypts the content of the file
            enc_content = enc.decrypt(file_content, key)
    
            # Creating temp file so no information is stored
            # mode = wb means it will write bytes
            temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')  
            temp_file.write(enc_content)
            temp_file.flush()
            temp_file.close()

            # Return the encrypted file for download
            # [:-4] removes the .enc extension in the name
            response = send_file(temp_file.name, as_attachment=True, download_name=file_name[:-4])
            return response
        except:
            return render_template('decrypt_file.html', active_page = "decrypt_file")
    return render_template('decrypt_file.html', active_page = "decrypt_file")

if __name__ == "__main__":
    app.run(debug=True)