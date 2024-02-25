import jwt
import datetime

# Replace with your strong secret key
secret_key = "your_strong_secret_key"


def generate_jwt_token():
    """Generates a JWT with dynamic iat and exp timestamps"""
    now = datetime.datetime.utcnow()
    payload = {
        "iat": now,  # Issued at - set to 'now'
        "exp": now + datetime.timedelta(minutes=30),  # Expiration - 30 minutes from now
    }

    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token


def decode_jwt_token(token):
    """Decodes a JWT"""
    try:
        decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
        return decoded
    except jwt.exceptions.DecodeError:
        return None  # Indicate invalid token


# Generate the token
token = generate_jwt_token()
print("Encoded token:", token)

# Decode the token
decoded_token = decode_jwt_token(token)
if decoded_token:
    print("Decoded payload:", decoded_token)
else:
    print("Error: Invalid token.")
