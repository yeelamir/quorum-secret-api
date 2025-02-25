from pydantic import BaseModel
import datetime
from typing import Optional
from typing import List

# Pydantic model to represent each secret

class Secret(BaseModel):
    SecretId: int
    DecryptRequest: bool
    IsOwner: bool
    Name: str
    Quorum: int
    Comments: str
    StartingDate: Optional[datetime.datetime]
    NDecryptRequest: int


    class Config:
        orm_mode = True  # This tells Pydantic to work with dictionary-like data (from SQL query results)

    #{"name":"sha256","secret":"shhhh","quorum":"2","comment":"","starting_date":"2025-02-28","group_users":[13,18,15]}
class NewSecret(BaseModel):
    name: str
    secret: str
    quorum: int
    comment: str
    starting_date: datetime.datetime
    group_users: List[int]

    class Config:
        orm_mode = True  # This tells Pydantic to work with dictionary-like data (from SQL query results)
