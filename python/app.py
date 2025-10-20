from flask import Flask, render_template, request, send_file, jsonify
import base64, hashlib, json, os, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from io import BytesIO

app = Flask(__name__)

class CryptoEngine:
    @staticmethod
    def encrypt_text(plaintext, method, key):
        start = time.time()

        if method == "base64":
            result = base64.b64encode(plaintext.encode()).decode()
        elif method == "hex":
            result = plaintext.encode().hex()
        elif method == "sha256":
            result = hashlib.sha256(plaintext.encode()).hexdigest()
        elif method == "sha512":
            result = hashlib.sha512(plaintext.encode()).hexdigest()
        elif method == "aes-cbc":
            result = CryptoEngine.encrypt_aes_cbc(plaintext, key)
        elif method == "aes-gcm":
            result = CryptoEngine.encrypt_aes_gcm(plaintext, key)
        else:
            raise ValueError(f"Unknown method: {method}")

        elapsed = round(time.time() - start, 4)
        size = len(result.encode())
        return result, elapsed, size

    @staticmethod
    def decrypt_text(ciphertext, method, key):
        start = time.time()
        if method == "aes-cbc":
            result = CryptoEngine.decrypt_aes_cbc(ciphertext, key)
        elif method == "aes-gcm":
            result = CryptoEngine.decrypt_aes_gcm(ciphertext, key)
        else:
            raise ValueError(f"Unknown method for decryption: {method}")

        elapsed = round(time.time() - start, 4)
        size = len(ciphertext.encode())
        return result, elapsed, size

    @staticmethod
    def encrypt_aes_cbc(plaintext, password):
        key = hashlib.sha256(password.encode()).digest()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        pad_len = 16 - (len(plaintext.encode()) % 16)
        padded = plaintext.encode() + bytes([pad_len]) * pad_len

        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt_aes_cbc(ciphertext, password):
        raw = base64.b64decode(ciphertext)
        iv = raw[:16]
        data = raw[16:]
        key = hashlib.sha256(password.encode()).digest()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()

        pad_len = decrypted[-1]
        return decrypted[:-pad_len].decode()

    @staticmethod
    def encrypt_aes_gcm(plaintext, password):
        key = hashlib.sha256(password.encode()).digest()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        combined = {
            "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(ciphertext).decode()
        }
        return base64.b64encode(json.dumps(combined).encode()).decode()

    @staticmethod
    def decrypt_aes_gcm(ciphertext, password):
        decoded = json.loads(base64.b64decode(ciphertext).decode())
        nonce = base64.b64decode(decoded["nonce"])
        data = base64.b64decode(decoded["data"])
        key = hashlib.sha256(password.encode()).digest()
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, data, None)
        return plaintext.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.form
    text = data.get('plaintext')
    method = data.get('method')
    key = data.get('key')

    result, elapsed, size = CryptoEngine.encrypt_text(text, method, key)
    return jsonify({
        "result": result,
        "time": elapsed,
        "size": size
    })

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.form
    text = data.get('ciphertext')
    method = data.get('method')
    key = data.get('key')

    try:
        result, elapsed, size = CryptoEngine.decrypt_text(text, method, key)
        return jsonify({
            "result": result,
            "time": elapsed,
            "size": size
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
