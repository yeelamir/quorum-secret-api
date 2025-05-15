from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from authenticationMiddleware import AuthenticationMiddleware
import uvicorn
from api.routers import auth as auth_router
from api.routers import users as users_router
from api.routers import secrets as secrets_router
from fastapi.openapi.utils import get_openapi


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
    r"/login",  # Exact match for public data endpoint
    r"^/register",         # Allow access to documentation without authentication
    r"^/openapi.json$", # Allow access to OpenAPI schema without authentication
    r"^/docs$" # Allow access to OpenAPI schema without authentication
]

# Add the authentication middleware
app.add_middleware(AuthenticationMiddleware, exempt_routes=exempt_routes)

# --- Include Routers ---
app.include_router(auth_router.router, prefix="") # Auth routes at root (e.g. /login)
app.include_router(users_router.router) # Default prefix is /users from the router file
app.include_router(secrets_router.router) # Default prefix is /secrets from the router file

uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")