import datetime
from fastapi import FastAPI, HTTPException, Request
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import jwt
from pydantic import BaseModel
import os
from authenticationMiddleware import AuthenticationMiddleware
import uvicorn
from db_layer import db_querries
from hashlib import sha256
import secrets
from db_layer.entities.user import User, User_id_name
from db_layer.entities.secret import Secret, NewSecret
from encryption import aes, rsa

PEPPER = "d5f3ce1e98860bbc95b7140df809db5f"

def hash_password_with_salt(password: str, salt: str) -> str:
    sha256_val = sha256((salt + PEPPER + password).encode())
    # Return the hexadecimal representation of the hash
    return sha256_val.hexdigest()

def random_salt() -> str:
    return secrets.token_hex(16)

def get_secret_key():
    return os.getenv("QUORUM_APP_SECRET_KEY", "defaultsecretkey") 

app = FastAPI()



origins = [
    "http://localhost:3000",
]

# Add CORSMiddleware to the FastAPI app
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


exempt_routes = [
    r"/login",  # Exact match for public data endpoint
    r"^/register",         # Allow access to documentation without authentication
    r"^/openapi.json$", # Allow access to OpenAPI schema without authentication
    r"^/docs$" # Allow access to OpenAPI schema without authentication
]

# Add the authentication middleware
app.add_middleware(AuthenticationMiddleware, secret_key=get_secret_key(), exempt_routes=exempt_routes)


def generate_jwt_token(user_id: int, username: str, secret_key):
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


# Secure endpoint that requires authentication
@app.get("/secrets", response_model=List[Secret])
async def get_secrets(request: Request):
    user_id = request.state.user['user_id']
    db_querriess = db_querries.db_querries()
    return db_querriess.get_all_secrets(user_id)

# Secure endpoint that requires authentication
@app.get("/users", response_model=List[User_id_name])
async def get_users():
    db_querriess = db_querries.db_querries()
    return db_querriess.get_users()

class User(BaseModel):
    username: str
    password: str

class TokenModel(BaseModel):
    token: str
    expiration: str


@app.post("/secrets")
def insert_new_secret(request: Request, secret: NewSecret):
    db_querriess = db_querries.db_querries()
    secret_data = db_querriess.get_secret_by_name([secret.name])
    if secret_data:
        return {"validation": False, "message": "Secret name already exists"}
    

    #Creating a new secret
    #1. Generate a random AES256 key and IV
    iv = aes.get_iv()
    aes_key = aes.get_secret_key()

    #2. Encrypt the secret with the AES256 key and store it in the Secrets table together with the metadata
    encrypted_secret = aes.encrypt_secret(secret.secret.encode('utf-8'), aes_key, iv)
    secret_id = db_querriess.insert_secret(secret.quorum, encrypted_secret, secret.name, secret.comment, secret.starting_date)
    #3. Encrypt the AES256 key with the public keys of the owner and the group members and store it in the UserSecret table
    user_id = request.state.user['user_id']
    owner_public_key = db_querriess.get_user_publickey(user_id)
    owner_encrypted_key = rsa.encrypt(owner_public_key, aes_key)
    db_querriess.insert_user_secret(user_id, secret_id, True, owner_encrypted_key)
    #4. Create the AES256 key shares for all the group members. Encrypt each share with the user public key and store it in the UserSecret table
    secret_shares = sss.split_secret(aes_key, secret.quorum, len(secret.group_users))
    i = 0
    for user in secret.group_users:
        user_public_key = db_querriess.get_user_publickey(user)
        user_encrypted_key = rsa.encrypt(user_public_key, aes_key)
        db_querriess.insert_user_secret(user_id, secret_id, False, secret_shares[i])
        i += 1


    return {"validation": True, "message": "Secret inserted successfully!"}

@app.post("/login", response_model=TokenModel)
def login(user: User):
    db_querriess = db_querries.db_querries()
    user_data = db_querriess.get_user_by_username([user.username])
    if user_data:
        password_hash = user_data['PasswordHash']
        salt = user_data['Salt']
        if hash_password_with_salt(user.password, salt) == password_hash:
            user_id = user_data['Id']
            token, expiration = generate_jwt_token(user_id, user.username, get_secret_key())
            return TokenModel(expiration=expiration.isoformat(), token = token)
    #Wrong credentials
    raise HTTPException(status_code=401, detail="Invalid credentials")
    
@app.post("/register")
def register(user: User):
    db_querriess = db_querries.db_querries()
    username = db_querriess.get_user_by_username([user.username])
    if username:
        return {"validation": False, "message": "Username already exists"}
    else:
        public_key, private_key = rsa.generate_key()
        salt = random_salt()
        db_querriess.insert_user(public_key, user.username, salt, hash_password_with_salt(user.password, salt))
        return {"validation": True, "message": "User registered successfully!", "private_key": private_key}



uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")