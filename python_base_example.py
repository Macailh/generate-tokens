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
    salt = secrets.token_bytes(32)

    signature = hmac.new(
        secret_key.encode(), json_data.encode() + salt, hashlib.sha256
    ).digest()
    token = base64.urlsafe_b64encode(json_data.encode() + salt + signature).decode()

    return token, salt


def verify_token(token, secret_key, salt):
    try:
        decoded_token = base64.urlsafe_b64decode(token)
        json_data = decoded_token[:-64]
        signature = decoded_token[-32:]

        expected_signature = hmac.new(
            secret_key.encode(), json_data + salt, hashlib.sha256
        ).digest()

        if not hmac.compare_digest(signature, expected_signature):
            return False

        payload = json.loads(json_data)
        if "exp" in payload:
            if int(time.time()) > payload["exp"]:
                return False  # Token has expired

        return True
    except Exception as e:
        print("Error:", e)
        return False


def decode_token(token):
    try:
        decoded_token = base64.urlsafe_b64decode(token)
        json_data = decoded_token[:-64]
        return json.loads(json_data)
    except Exception as e:
        print("Error:", e)
        return None


payload = {}
secret_key = "secret"
expiry_time = 3600  # 1 hour
token, salt = generate_token(payload, secret_key, expiry_time)

print(token)
print(verify_token(token, secret_key, salt))
print(decode_token(token))
