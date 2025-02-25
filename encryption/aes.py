from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad



# Generate AES Key (256-bit)
def get_secret_key():
    return get_random_bytes(32)

# Generate IV (16 bytes for AES)
def get_iv():
    return get_random_bytes(16)

# Encrypt the secret
def encrypt_secret(secret: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(secret, AES.block_size))
    return ct_bytes

# Decrypt the secret
def decrypt_secret(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt
