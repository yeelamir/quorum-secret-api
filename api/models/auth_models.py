from pydantic import BaseModel


class UserCredentials(BaseModel):
    username: str
    password: str

class TokenModel(BaseModel):
    token: str
    expiration: str
