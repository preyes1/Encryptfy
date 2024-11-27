from flask import Flask, render_template, request
from encryption import *
from methods import repeat_key

app = Flask(__name__)

@app.route('/', methods=["POST", "GET"])
def home():
    return render_template('index.html', active_page="home") 

@app.route('/encrypt', methods=["POST", "GET"])
def encrypt():
    cipherTextHex=""
    if request.method == "POST":
        plaintext = request.form["plaintext"]
        key = request.form["key"]

        # If statement ensures there is input in both boxes
        if plaintext and key:
            # Key should be 16 bytes, repeats key until it reaches 16
            key = repeat_key(key)
            enc = Encryptor(key)
            # have to encode plaintext and key to turn them into bytes
            cipherText = enc.encrypt(plaintext.encode(), key.encode())
            cipherTextHex = cipherText.hex()
    return render_template('encrypt.html', cipherText=cipherTextHex, active_page="encrypt")

@app.route('/decrypt', methods=["POST", "GET"])
def decrypt():
    plainText=""
    if request.method == "POST":
        cipherText = request.form["ciphertext"]
        key = request.form["key"]
        # If statement ensures there is input in both boxes and
        # checks if ciphertext is valid (has to be a multiple of 16)
        if (cipherText and key):
            key = repeat_key(key)
            enc = Encryptor(key)
            try:
                if len(cipherText) % 16 == 0:
                    # Have to convert cipherText back into a bytes object
                    plainText = enc.decrypt(bytes.fromhex(cipherText), key.encode())
                    # Reverts plainText back from a bytes object to a String object
                    return render_template('decrypt.html', plainText=plainText.decode(), active_page="decrypt")
                else:
                    return render_template('decrypt.html', plainText="Invalid ciphertext length, must be a multiple of 16", active_page="decrypt")
            except:
                return render_template('decrypt.html', plainText="Invalid input", active_page="decrypt")
            
    return render_template('decrypt.html', active_page="decrypt")

if __name__ == "__main__":
    app.run(debug=True)