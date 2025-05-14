import datetime
from fastapi import FastAPI, HTTPException, Request
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import jwt
from pydantic import BaseModel
import os
from authenticationMiddleware import AuthenticationMiddleware
import uvicorn
from hashlib import sha256
import secrets
from db_layer.db_querries import data_access_layer
from db_layer.entities.user import User, User_id_name
from db_layer.entities.secret import Secret, NewSecret
from encryption import aes, rsa, sss, hash
import base64



def get_secret_key():
    return os.getenv("QUORUM_APP_SECRET_KEY", "defaultsecretkey") 

app = FastAPI(
    title="Quorum Secret API",
    description="API for managing secrets with quorum-based sharing and encryption.",
    version="1.0.0"
)


from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method.setdefault("security", []).append({"BearerAuth": []})
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi



origins = [
    # This is the origin of the frontend application
    "http://localhost:3000",
]

# Add CORSMiddleware to the FastAPI app
# Allow the frontend application to access the backend REST API
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# List of exempt routes for authentication middleware
# These routes will not require authentication
exempt_routes = [
    r"/login",  # Exact match for public data endpoint
    r"^/register",         # Allow access to documentation without authentication
    r"^/openapi.json$", # Allow access to OpenAPI schema without authentication
    r"^/docs$" # Allow access to OpenAPI schema without authentication
]

# Add the authentication middleware
app.add_middleware(AuthenticationMiddleware, secret_key=get_secret_key(), exempt_routes=exempt_routes)


data_access_layer = data_access_layer(
    db_host=os.getenv("QUORUM_APP_DB_HOST", "localhost"),
    db_user=os.getenv("QUORUM_APP_DB_USER", "root"),
    db_password=os.getenv("QUORUM_APP_DB_PASSWORD", "abc123"),
    db_name=os.getenv("QUORUM_APP_DB_NAME", "quorum_secrets")
);

def generate_jwt_token(user_id: int, username: str, secret_key):
    #TODO: Change the expiration to 60 minutes
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=360)  # expiration time 
    # Create the payload with user ID and username
    payload = {
        'user_id': user_id, 
        'username': username, 
        'exp': expiration
    }

    # Create the JWT token, signed with HMAC SHA-256
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token, expiration


# Get all the secrets for the user
@app.get("/secrets", response_model=List[Secret])
async def get_secrets(request: Request):
    try:
        # Get the user ID from the request state
        user_id = request.state.user['user_id']
        return data_access_layer.get_all_secrets(user_id)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


# Get a secret by ID
@app.get("/secrets/{secret_id}", response_model=Secret)
async def get_secret_by_id(request: Request, secret_id: int):
    user_id = request.state.user['user_id']
    return data_access_layer.get_shared_secret_by_id(user_id, secret_id)


# Delete secret by ID - only the owner can delete it
@app.delete("/secrets/{secret_id}")
async def delete_secret_by_id(request: Request, secret_id: int):
    user_id = request.state.user['user_id']
    secret = data_access_layer.get_shared_secret_by_id(user_id, secret_id)
    if not secret:
        return {"validation": False, "message": "Secret not found"}
    if not secret['IsOwner']:
        return {"validation": False, "message": "You are not the owner of this secret"}

    data_access_layer.delete_secret_by_id(secret_id)

    return {"validation": True, "message": "Secret deleted successfully!"}


class PrivateKey(BaseModel):
    private_key: str

# Set the DecryptRequest for a secret
@app.patch("/secrets/set_decrypt_request/{secret_id}")
async def set_decrypt_request(request: Request, secret_id: int, decrypt_request: PrivateKey):
    user_id = request.state.user['user_id']
    secret_data = data_access_layer.get_shared_secret_by_id(user_id, secret_id)
    if not secret_data:
        return {"validation": False, "message": "Secret not found"}
    
    if secret_data['StartingDate'] is not None:
        starting_date = secret_data['StartingDate'].replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) < starting_date:
            return {"validation": False, "message": "Secret is not available yet"}
    
    if secret_data['NDecryptRequest'] >= secret_data['Quorum']:
        return {"validation": False, "message": "Secret is already decrypted"}

    #Check if the quorum is reached
    quorum = secret_data['Quorum']
    n_decrypt_request = secret_data['NDecryptRequest']
    #Decrypt the secret share with the private key of the user
    #1. Get the secret share from the database
    secret_share = secret_data['SecretShare']
    #2. Decrypt the secret share with the private key of the user
    decrypted_secret_share = rsa.decrypt(decrypt_request.private_key, base64.b64decode(secret_share))

    # Update the secret share in the database with the decrypted secret share
    # and set the decrypt request to true
    data_access_layer.set_decrypt_request(user_id, secret_id, base64.b64encode(decrypted_secret_share))


    if n_decrypt_request == quorum -1:
        #Get all the secret shares that their decripy request is true from the database
        decrypted_secret_shares = [n['SecretShare'] for n in data_access_layer.get_decrypted_secret_shares(secret_id)]
        # Reconstruct the secret with the secret shares
        sss_secret = sss.reconstruct_secret(decrypted_secret_shares)

        #Decrypt the secret for all the users that the secret is shared with
        # Get the secret shares from the database
        secret_shares = data_access_layer.get_secret_shares(secret_id)
        # Decrypt the secret for all the users that the secret is shared with
        for share in secret_shares:
            user_id = share['UserId']
            encrypted_secret = rsa.encrypt(share['PublicKey'], sss_secret)
            # Update the encrypted secret in the database and delete the secret share
            data_access_layer.set_encrypted_secret(user_id, secret_id, base64.b64encode(encrypted_secret))
        


    return {"validation": True, "message": "Secret updated successfully!"}

# Get the secret content by ID - Available only for the secret owner or 
# if the secret is shared with the user and the number of decrypt requests is equal to the quorum
@app.post("/secrets/secret_content/{secret_id}")
async def set_decrypt_request(request: Request, secret_id: int, user_private_key: PrivateKey):
    user_id = request.state.user['user_id']
    secret_data = data_access_layer.get_shared_secret_by_id(user_id, secret_id)
    if not secret_data:
        return {"validation": False, "message": "Secret not found"}
    
    if secret_data['EncryptedSecret'] == None:
        return {"validation": False, "message": "Secret is not available yet"}
    
    #Decrypt the secret with the private key of the user
    aes_key = rsa.decrypt(user_private_key.private_key, base64.b64decode(secret_data['EncryptedSecret'])) 
    cipher_and_iv = data_access_layer.get_cipher_by_id(secret_id)
    #Decrypt the secret with the AES256 key and IV
    iv = cipher_and_iv['IV']  
    the_secret = aes.decrypt_secret(cipher_and_iv['Cipher'], aes_key, iv)
    return the_secret.decode('utf-8')




# Secure endpoint that requires authentication
@app.get("/users", response_model=List[User_id_name])
async def get_users():
    return data_access_layer.get_users()

class User(BaseModel):
    username: str
    password: str

class TokenModel(BaseModel):
    token: str
    expiration: str


@app.post("/secrets")
def insert_new_secret(request: Request, secret: NewSecret):
    secret_data = data_access_layer.get_secret_by_name([secret.name])
    if secret_data:
        return {"validation": False, "message": "Secret name already exists"}
    
    #Creating a new secret
    #1. Generate a random AES256 key and IV
    iv = aes.get_iv()
    aes_key = aes.get_secret_key()
    #2. Encrypt the secret with the AES256 key and store it in the Secrets table together with the metadata
    encrypted_secret = aes.encrypt_secret(secret.secret.encode('utf-8'), aes_key, iv)
    secret_id = data_access_layer.insert_secret(secret.quorum, encrypted_secret, secret.name, secret.comment, secret.starting_date, iv)
    #3. Encrypt the AES256 key with the public keys of the owner and the group members and store it in the UserSecret table
    user_id = request.state.user['user_id']
    owner_public_key = data_access_layer.get_user_publickey(user_id)
    owner_encrypted_key = rsa.encrypt(owner_public_key, aes_key)
    owner_encrypted_key_str = base64.b64encode(owner_encrypted_key).decode('utf-8')
    data_access_layer.insert_user_secret(user_id, secret_id, True, owner_encrypted_key_str)
    #4. Create the AES256 key shares for all the group members. Encrypt each share with the user public key and store it in the UserSecret table
    secret_shares = sss.split_secret(aes_key, len(secret.group_users), secret.quorum)

    for i, user in enumerate(secret.group_users):
        user_public_key = data_access_layer.get_user_publickey(user)
        secret_share_bytes = base64.b64decode(secret_shares[i])
        user_encrypted_share = rsa.encrypt(user_public_key, secret_share_bytes)
        user_encrypted_share_str = base64.b64encode(user_encrypted_share).decode('utf-8')
        data_access_layer.insert_user_secret(user, secret_id, False, user_encrypted_share_str)

    return {"validation": True, "message": "Secret inserted successfully!"}

@app.post("/login", response_model=TokenModel)
def login(user: User):
    user_data = data_access_layer.get_user_by_username([user.username])
    if user_data:
        password_hash = user_data['PasswordHash']
        salt = user_data['Salt']
        if hash.hash_password_with_salt(user.password, salt) == password_hash:
            user_id = user_data['Id']
            token, expiration = generate_jwt_token(user_id, user.username, get_secret_key())
            return TokenModel(expiration=expiration.isoformat(), token = token)
    #Wrong credentials
    raise HTTPException(status_code=401, detail="Invalid credentials")
    
@app.post("/register")
def register(user: User):
    username = data_access_layer.get_user_by_username([user.username])
    if username:
        return {"validation": False, "message": "Username already exists"}
    else:
        public_key, private_key = rsa.generate_key()
        salt = hash.random_salt()
        data_access_layer.insert_user(public_key, user.username, salt, hash.hash_password_with_salt(user.password, salt))
        return {"validation": True, "message": "User registered successfully!", "private_key": private_key}



uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")