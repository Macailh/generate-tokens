import secrets


def generate_token():
    """
    Generates a secure token using the 'secrets' module.

    Returns:
    str: The secure token.
    """
    return secrets.token_hex(16)


# Example usage
secure_token = generate_token()
print("Generated secure token:", secure_token)
