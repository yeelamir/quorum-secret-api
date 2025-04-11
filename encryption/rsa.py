from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Encrypts the plaintext using the public key (pem format)
# Returns the ciphertext
def encrypt(public_key_pem: str, plaintext: bytes) -> bytes:
    try:
        #public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(plaintext)
    except Exception as e:
                print(f"An unexpected error occurred: {e}")
                return None
    
# Decrypts the ciphertext using the private key (pem format)
# Returns the plaintext
def decrypt(private_key_pem: str , ciphertext: bytes) -> bytes:
    private_key = RSA.import_key(private_key_pem)
    decrypt_cipher = PKCS1_OAEP.new(private_key)
    return decrypt_cipher.decrypt(ciphertext)

# Generate RSA key pair
# Returns a tuple containing the public key and the private key (both in pem format)
def generate_key() -> tuple:  
    key = RSA.generate(4096)
    public_key = key.public_key().export_key(format='PEM')
    private_key = key.export_key(format='PEM')
    return public_key.decode('utf-8'), private_key.decode('utf-8')

