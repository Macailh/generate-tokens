import secrets
import re


def generate_token(info):
    """
    Generates a token combining a unique identifier and additional information.

    Args:
    info (str): Additional information to include in the token.

    Returns:
    str: The generated token.
    """
    unique_id = secrets.token_hex(8)  # Generates an 8-byte unique identifier
    return f"{unique_id}-{info}"


def validate_token(token):
    """
    Validates a token using a regular expression.

    Args:
    token (str): The token to validate.

    Returns:
    bool: True if the token is valid, False otherwise.
    """
    pattern = re.compile(r"^[a-f0-9]{16}-[a-zA-Z0-9]+$")
    return bool(pattern.match(token))


# Example usage
additional_info = "example_info"
generated_token = generate_token(additional_info)
print("Generated token:", generated_token)

# Validation
print("Token validation result:", validate_token(generated_token))
