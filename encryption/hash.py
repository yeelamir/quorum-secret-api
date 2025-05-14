from hashlib import sha256
import secrets


PEPPER = "d5f3ce1e98860bbc95b7140df809db5f"

def hash_password_with_salt(password: str, salt: str) -> str:
    sha256_val = sha256((salt + PEPPER + password).encode())
    # Return the hexadecimal representation of the hash
    return sha256_val.hexdigest()

def random_salt() -> str:
    return secrets.token_hex(16)
