import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from authenticationMiddleware import AuthenticationMiddleware
import uvicorn
from api.routers import auth as auth_router
from api.routers import users as users_router
from api.routers import secrets as secrets_router
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="Quorum Secret API",
    description="API for managing secrets with quorum-based sharing and encryption.",
    version="1.0.0"
)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method.setdefault("security", []).append({"BearerAuth": []})
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi



origins = [
    # This is the origin of the frontend application
    "http://localhost:3000",
]

# Add CORSMiddleware to the FastAPI app
# Allow the frontend application to access the backend REST API
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# List of exempt routes for authentication middleware
# These routes will not require authentication
exempt_routes = [
    r"^/api/login",  # Exact match for public data endpoint
    r"^/api/register",         # Allow access to documentation without authentication
]

# Add the authentication middleware
app.add_middleware(AuthenticationMiddleware, exempt_routes=exempt_routes)

# Mount the dist directory to serve static assets (JS, CSS, etc.)
# Mount /ui/assets
app.mount("/ui/assets", StaticFiles(directory="../quorum-secret-frontend/dist/assets"), name="ui-assets")

# Serve the index.html at the root or as fallback
@app.get("/", include_in_schema=False)
async def serve_index():
    return RedirectResponse(url="/ui/auth")

@app.get("/ui", include_in_schema=False)
@app.get("/ui/", include_in_schema=False)
@app.get("/ui/{path:path}", include_in_schema=False)
async def serve_vue(path: str = ""):
    candidate_path = os.path.join("dist", path)
    if os.path.exists(candidate_path) and not os.path.isdir(candidate_path):
        return FileResponse(candidate_path)
    return FileResponse("../quorum-secret-frontend/dist/index.html")

# --- Include Routers ---
app.include_router(auth_router.router, prefix="/api") # Auth routes at root (e.g. /login)
app.include_router(users_router.router, prefix="/api") # Default prefix is /users from the router file
app.include_router(secrets_router.router, prefix="/api") # Default prefix is /secrets from the router file

#uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


uvicorn.run(
    app,
    host="0.0.0.0",
    port=4430,
    log_level="info",
    ssl_keyfile="quorum_certificate/test-quorum-secret-key.pem",
    ssl_certfile="quorum_certificate/test-quorum-secret-cert.pem"    
)