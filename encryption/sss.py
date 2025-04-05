import pylibscrypt

# Split into n shares, requiring k to reconstruct
def split_secret(secret: str, n: int, k: int):
    return pylibscrypt.shamir.split(secret, k, n)

# Recover the secret using at least k shares
def reconstruct_secret(shares: list):
    return pylibscrypt.sss.combine(shares)



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