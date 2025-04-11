import secrets
import base64
from typing import List, Tuple

# Prime just greater than 2^256
PRIME = 2**256 + 297

def _eval_polynomial(coeffs: List[int], x: int) -> int:
    result = 0
    for i, coeff in enumerate(coeffs):
        result = (result + coeff * pow(x, i, PRIME)) % PRIME
    return result

def _modinv(a: int, p: int) -> int:
    """Modular inverse using extended Euclidean algorithm"""
    if a == 0:
        raise ValueError("Inverse does not exist")
    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % p

def split_secret(secret_bytes: bytes, n: int, k: int) -> List[str]:
    """Split a bytes secret into n shares with threshold k and return as base64-encoded strings"""
    secret_int = int.from_bytes(secret_bytes, byteorder='big')
    if not (0 <= secret_int < PRIME):
        raise ValueError("Secret too large for field")
    if not (0 < k <= n):
        raise ValueError("Threshold k must be <= n and > 0")

    coeffs = [secret_int] + [secrets.randbelow(PRIME) for _ in range(k - 1)]
    shares = [(x, _eval_polynomial(coeffs, x)) for x in range(1, n + 1)]
    
    # Convert shares to bytes and then base64 encode them
    base64_shares = []
    for x, y in shares:
        # Convert the x and y values to bytes
        x_bytes = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
        y_bytes = y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')
        
        # Concatenate x and y bytes
        share_bytes = x_bytes + y_bytes
        
        # Base64 encode the share bytes and append to the result list
        base64_shares.append(base64.b64encode(share_bytes).decode('utf-8'))
    
    return base64_shares

def reconstruct_secret(base64_shares: List[str]) -> bytes:
    """Reconstruct the bytes secret from base64-encoded shares"""
    shares = []
    
    # Decode each base64 share and split into x, y components
    for share in base64_shares:
        share_bytes = base64.b64decode(share)
        # Split the bytes into x and y parts
        x_len = (share_bytes[0] & 0xFF)  # The length of x in bytes (assuming it's 1 byte length)
        x = int.from_bytes(share_bytes[:x_len], byteorder='big')
        y = int.from_bytes(share_bytes[x_len:], byteorder='big')
        shares.append((x, y))

    secret_int = 0
    for j, (xj, yj) in enumerate(shares):
        numerator, denominator = 1, 1
        for m, (xm, _) in enumerate(shares):
            if m != j:
                numerator = (numerator * -xm) % PRIME
                denominator = (denominator * (xj - xm)) % PRIME
        lagrange_coeff = numerator * _modinv(denominator, PRIME)
        secret_int = (secret_int + yj * lagrange_coeff) % PRIME

    # Convert integer back to bytes
    byte_len = (secret_int.bit_length() + 7) // 8
    return secret_int.to_bytes(byte_len, byteorder='big')


import numpy  as np

def get_coefficients(X: np.array, Y: np.array) -> np.array:
    A = np.zeros(len(X) - 1)        

    for i in range(0, len(X) - 1):
        values = X[i] - X

        A[i] = Y[i] / np.prod(values[values != 0])

    return A

if __name__ == '__main__':

    X = np.array([1,2,3])
    Y = np.array([1,4,9])

    A = get_coefficients(X, Y)
    print(A)