# app/utils/jwt_handler.py
import jwt
import datetime
import os
# It's better to import the SECRET_KEY from a central config file
# e.g., from ..config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

# For demonstration, let's assume it's loaded here (not ideal for this file directly)
SECRET_KEY = os.getenv("QUORUM_APP_SECRET_KEY", "defaultsecretkey")
ALGORITHM = "HS256" # Or load from config


def generate_jwt_token(user_id: int, username: str):
    #TODO: Change the expiration to 60 minutes
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=360)  # expiration time 
    # Create the payload with user ID and username
    payload = {
        'user_id': user_id, 
        'username': username, 
        'exp': expiration
    }

    # Create the JWT token, signed with HMAC SHA-256
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, expiration


def decode_jwt_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
