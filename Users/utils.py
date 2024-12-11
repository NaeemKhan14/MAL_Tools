import secrets


def generate_code_verifier():
    """
    Generate a secure, URL-safe code verifier.
    """
    return secrets.token_urlsafe(96)  # Generates a string ~128 characters long


def generate_state():
    """
    Generate a secure, URL-safe random state value.
    """
    return secrets.token_urlsafe(32)
