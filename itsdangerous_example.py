from itsdangerous import URLSafeSerializer
import time
import base64
import secrets

SECRET_KEY = "czlomcq9ttT-hnueY0dT1fKgJrL8RzDD-n3vw2T4WNQ="


def generate_token(payload, secret_key, expiry_time=3600):
    salt = secrets.token_bytes(32)
    serializer = URLSafeSerializer(secret_key)
    payload["iat"] = int(time.time())
    payload["exp"] = payload["iat"] + expiry_time
    token = serializer.dumps(payload, salt=salt)
    return base64.urlsafe_b64encode(token.encode()).decode(), salt


def verify_token(token, secret_key, salt):
    serializer = URLSafeSerializer(secret_key)
    try:
        token = base64.urlsafe_b64decode(token.encode()).decode()
        payload = serializer.loads(token, salt=salt, max_age=None)
        return payload
    except Exception as e:
        print("Error:", e)
        return None


payload = {}

token, salt = generate_token(payload, SECRET_KEY, expiry_time=3600)

print("Token generado:", token)

decoded_payload = verify_token(token, SECRET_KEY, salt)
print("Payload decodificado:", decoded_payload)
