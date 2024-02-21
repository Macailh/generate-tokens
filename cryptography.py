from cryptography.fernet import Fernet
import json
import base64
import time


def generate_token(payload, key):
    payload["iat"] = int(time.time())
    token = Fernet(key).encrypt(json.dumps(payload).encode())
    return token.decode()


def verify_token(token, key):
    try:
        decrypted_token = Fernet(key).decrypt(token.encode())
        return json.loads(decrypted_token)
    except Exception as e:
        print("Error:", e)
        return None


# Genera una clave para encriptar y desencriptar los tokens
key = Fernet.generate_key()

payload = {"user_id": 12345}
token = generate_token(payload, key)

print("Token generado:", token)
decoded_payload = verify_token(token, key)
print("Payload decodificado:", decoded_payload)
