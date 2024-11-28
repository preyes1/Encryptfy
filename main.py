from flask import Flask, render_template, request, send_file, after_this_request
from encryption import *
from methods import repeat_key, derive_key
import os
import tempfile

app = Flask(__name__)
# Global variables to make code easier to read
MAX_INPUT_LENGTH = 1000
KEY_LENGTH = 16

@app.route('/', methods=["POST", "GET"])
def home():
    return render_template('index.html', active_page="home") 

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
        # have to encode plaintext and key to turn them into bytes
        cipherText = enc.encrypt(plaintext.encode(), key)
        # Appends salt to the ciphertext so we're able to decrypt
        # cipherTextHex[-16:] gets the salt
        cipherTextHex = cipherText.hex() + salt.hex()
            
    return render_template('encrypt.html', cipherText=cipherTextHex, active_page="encrypt")

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
        salt = bytes.fromhex(cipherText[-16:])
        key=derive_key(key, salt)
        print(key)
    
        enc = Encryptor(key)
        #try:
            # Ensures cipherText is a multiple of 16
        if not len(cipherText) % 16 == 0:
            return render_template('decrypt.html', plainText="Invalid ciphertext length, must be a multiple of 16", active_page="decrypt")
            
            # Have to convert cipherText back into a bytes object
        plainText = enc.decrypt(bytes.fromhex(cipherText), key)
        print(plainText)
            # Reverts plainText back from a bytes object to a String object

        return render_template('decrypt.html', plainText=plainText, active_page="decrypt")
               
        #except:
            #return render_template('decrypt.html', plainText="Invalid input", active_page="decrypt")
    
    return render_template('decrypt.html', active_page="decrypt")

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

            enc = Encryptor(key)

            # Reads file content and gets file name
            file_content = file.read()
            file_name = file.filename

            # Encrypts file content and makes a new file .enc
            enc_content = enc.encrypt(file_content, key.encode())
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

@app.route('/decrypt-file', methods=["POST", "GET"])
def decrypt_file():
    if request.method == "POST": 
        try:
            # Gets file and key from HTML Form
            file = request.files.get("file")
            key = request.form["key"]

            enc = Encryptor(key)

            # Reads file content and gets file name
            file_content = file.read()
            file_name = file.filename

            # Decrypts the content of the file and saves it to a 
            # [:-4] removes the .enc extension in the name
            enc_content = enc.decrypt(file_content, key.encode())

            # Creating temp file so no information is stored
            # mode = wb means it will write bytes
            temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')  
            temp_file.write(enc_content)
            temp_file.flush()
            temp_file.close()

            # Return the encrypted file for download
            response = send_file(temp_file.name, as_attachment=True, download_name=file_name[:-4])
            return response
        except:
            return render_template('decrypt_file.html', active_page = "decrypt_file")
    return render_template('decrypt_file.html', active_page = "decrypt_file")

if __name__ == "__main__":
    app.run(debug=True)