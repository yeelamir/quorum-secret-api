from pydantic import BaseModel


class User_id_name(BaseModel):
    Id: int
    Username: str

    class Config:
        orm_mode = True  # This tells Pydantic to work with dictionary-like data (from SQL query results)
