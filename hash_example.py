import hashlib
import hmac


def genearte_token(email, secreto):
    hash_digest = hashlib.sha256(email.encode()).hexdigest()
    return hmac.new(secreto.encode(), hash_digest.encode(), hashlib.sha256).hexdigest()


def verify_token(token, email, secret):
    hash_digest = hashlib.sha256(email.encode()).hexdigest()
    token_calculado = hmac.new(
        secret.encode(), hash_digest.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(token, token_calculado)


email = "usuario@ejemplo.com"
secret = "un_secreto_compartido"

token = genearte_token(email, secret)
valido = verify_token(token, email, secret)

print(f"Token: {token}")
print(f"Válido: {valido}")
