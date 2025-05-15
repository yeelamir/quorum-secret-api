# api/routers/users.py
from typing import List
from fastapi import APIRouter

from db_layer.db_accessor import get_data_access_layer
from db_layer.entities.user import User_id_name

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

@router.get("", response_model=List[User_id_name]) # Changed path to empty for /users
async def get_users():
    return get_data_access_layer().get_users()
