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
# IV (nonce) must be 16 bytes for AES-GCM
# aad (Additional Authenticated Data) is optional data that is authenticated but not encrypted
def encrypt_secret(secret: bytes, key: bytes, iv: bytes, aad: str = None) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher.update(aad.encode('utf-8'))  # aad is authenticated but not encrypted
    ct_bytes, tag = cipher.encrypt_and_digest(secret)
    return ct_bytes + tag  # Combine ciphertext and tag

# Decrypt the secret
def decrypt_secret(ciphertext_and_tag: bytes, key: bytes, iv: bytes, aad: str = None) -> bytes:
    tag_length = 16  # AES-GCM tag is always 16 bytes
    ciphertext = ciphertext_and_tag[:-tag_length]
    tag = ciphertext_and_tag[-tag_length:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher.update(aad.encode('utf-8'))
    pt = cipher.decrypt_and_verify(ciphertext, tag)
    return pt
