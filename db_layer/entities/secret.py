from pydantic import BaseModel
from typing import List

# Pydantic model to represent each secret
class Secret(BaseModel):
    SecretId: int
    Name: str
    Quorum: int
    Comments: str
    startingDate: str

    class Config:
        orm_mode = True  # This tells Pydantic to work with dictionary-like data (from SQL query results)
