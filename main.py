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

class UserInfo(BaseModel):
    username: str
    password: str


@app.get("/admin")
async def root(username: str, password: str):
    result = False
    if username == "tomer" and password == "king1":
        result = True
    return {"access granted": result}


@app.post("/singup")
async def root(info: UserInfo):
    return {"error" : info.username}