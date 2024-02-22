import base64
import json
import hmac
import hashlib
import time
import secrets


def generate_token(payload, secret_key, expiry_time=3600):
    payload["iat"] = int(time.time())
    payload["exp"] = payload["iat"] + expiry_time

    json_data = json.dumps(payload)

    # Generar un salt aleatorio
    salt = secrets.token_bytes(16)
    print(salt)

    # Codificar el salt
    encoded_salt = base64.urlsafe_b64encode(salt).decode()

    # Agregar el salt al payload
    payload["salt"] = encoded_salt
    print(payload)

    # Codificar el payload actualizado
    json_data = json.dumps(payload)

    # Calcular la firma
    signature = hmac.new(
        secret_key.encode(), json_data.encode(), hashlib.sha256
    ).digest()

    # Crear el token
    token = base64.urlsafe_b64encode(json_data.encode() + signature).decode()

    return token


def verify_token(token, secret_key):
    try:
        decoded_token = base64.urlsafe_b64decode(token)
        json_data = decoded_token[:-32]
        signature = decoded_token[-32:]

        # Obtener el salt del payload
        payload = json.loads(json_data)
        salt = base64.urlsafe_b64decode(payload["salt"])

        # Recalcular la firma utilizando el salt
        expected_signature = hmac.new(
            secret_key.encode(), json_data, hashlib.sha256
        ).digest()

        # Verificar si las firmas coinciden
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        print("Error:", e)
        return False


def decode_token(token):
    try:
        decoded_token = base64.urlsafe_b64decode(token)
        json_data = decoded_token[:-32]
        return json.loads(json_data)
    except Exception as e:
        print("Error:", e)
        return None


payload = {}
secret_key = "secret"
token = generate_token(payload, secret_key)

print(token)
print(verify_token(token, secret_key))
print(decode_token(token))
