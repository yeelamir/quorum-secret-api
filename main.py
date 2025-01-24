from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


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

fake_users_db = {}

class User(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(user: User):
    global fake_users_db
    if user.username in fake_users_db:
        return {"validation": True}
    else:
        return {"validation": False}    

@app.post("/register")
def register(user: User):
    global fake_users_db  
    if user.username in fake_users_db:
        # Username already exists
        return {"validation": False, "message": "Username already exists"}
    else:
        fake_users_db[user.username] = user.password
        for key in fake_users_db.keys():
            print("un: " + key + " ps: " + fake_users_db[key])
        return {"validation": True, "message": "User registered successfully"}


