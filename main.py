from fastapi import FastAPI

app = FastAPI()

@app.get("/admin")
async def root(username: str, password: str):
    result = False
    if username == "tomer" and password == "king":
        result = True
    return {"access granted?": result}
