## Generating a Private Key and Certificate with OpenSSL

To generate a private key and a self-signed certificate, you can use the `openssl` command-line tool. This is commonly used for creating certificates for development or internal use.

### Step-by-Step Instructions

1. **Open a terminal** on your system.

2. **Run the following command:**

    ```sh
    openssl req -x509 -newkey rsa:4096 -keyout test-quorum-secret-key.pem -out test-quorum-secret-cert.pem -days 365 -nodes -subj "/CN=quorum-secret.com"
    ```

    - `-x509`: Generates a self-signed certificate instead of a certificate request.
    - `-newkey rsa:4096`: Creates a new RSA key pair with a 4096-bit key size.
    - `-keyout test-quorum-secret-key.pem`: Specifies the output file for the private key.
    - `-out test-quorum-secret-cert.pem`: Specifies the output file for the certificate.
    - `-days 365`: Sets the certificate validity period to 365 days.
    - `-nodes`: Skips encrypting the private key with a passphrase.
    - `-subj "/CN=quorum-secret.com"`: Sets the subject (Common Name) for the certificate.

### Output

After running the command, you will have two files in your current directory:

- `test-quorum-secret-key.pem` — The generated private key.
- `test-quorum-secret-cert.pem` — The self-signed certificate.

You can now use these files for your Quorum Secret API setup.