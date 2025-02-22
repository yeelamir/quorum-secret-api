from pydantic import BaseModel
from typing import List


class User(BaseModel):
    UserId: int
    PublicKey: str
    Username: str
    Salt: str
    PasswordHash: str
    class Config:
        orm_mode = True  # This tells Pydantic to work with dictionary-like data (from SQL query results)

class User_id_name(BaseModel):
    Id: int
    Username: str

    class Config:
        orm_mode = True  # This tells Pydantic to work with dictionary-like data (from SQL query results)