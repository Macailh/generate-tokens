import base64
import json
import hmac
import hashlib
import time


def generate_token(payload, secret_key, expiry_time=3600):
    payload["iat"] = int(time.time())
    payload["exp"] = payload["iat"] + expiry_time

    json_data = json.dumps(payload)

    signature = hmac.new(
        secret_key.encode(), json_data.encode(), hashlib.sha256
    ).digest()
    token = base64.urlsafe_b64encode(json_data.encode() + signature).decode()

    return token


payload = {"email": "example@email.com"}
secret_key = "secret"
token = generate_token(payload, secret_key)

print(token)
