# api/routers/auth.py
from fastapi import APIRouter, HTTPException
from api.models.auth_models import TokenModel, UserCredentials
from db_layer.db_accessor import get_data_access_layer
from encryption import rsa, hash
from utils.jwt_handler import generate_jwt_token


router = APIRouter(
    tags=["Authentication"],
)

@router.post("/login", response_model=TokenModel)
def login(user: UserCredentials):
    user_data = get_data_access_layer().get_user_by_username([user.username])
    if user_data:
        password_hash = user_data['PasswordHash']
        salt = user_data['Salt']
        if hash.hash_password_with_salt(user.password, salt) == password_hash:
            user_id = user_data['Id']
            token, expiration = generate_jwt_token(user_id, user.username)
            return TokenModel(expiration=expiration.isoformat(), token = token)
    #Wrong credentials
    raise HTTPException(status_code=401, detail="Invalid credentials")
    


@router.post("/register", status_code=200)
def register(user: UserCredentials):
    username = get_data_access_layer().get_user_by_username([user.username])
    if username:
        return {"validation": False, "message": "Username already exists"}
    else:
        public_key, private_key = rsa.generate_key()
        salt = hash.random_salt()
        get_data_access_layer().insert_user(public_key, user.username, salt, hash.hash_password_with_salt(user.password, salt))
        return {"validation": True, "message": "User registered successfully!", "private_key": private_key}

