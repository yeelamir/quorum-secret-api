from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
import jwt
from typing import Optional
import re


class AuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, secret_key: str, exempt_routes: Optional[list] = None):
        super().__init__(app)
        self.secret_key = secret_key
        self.exempt_routes = exempt_routes if exempt_routes else []

    async def dispatch(self, request: Request, call_next):
        # Check if the current endpoint is exempt from authentication
        if self._is_exempt_route(request.url.path) or request.method == "OPTIONS" :
            response = await call_next(request)
            return response

        token: Optional[str] = request.headers.get("Authorization")
        if token is None:
            return JSONResponse(status_code=401, content={"detail": "Token is missing"})

        try:
            token = token.split(" ")[1]  # Extract token part (Bearer <token>)
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            request.state.user = payload  # Store the user data in request state
        except jwt.ExpiredSignatureError:
            return JSONResponse(status_code=401, content={"detail": "Token has expired"})
        except jwt.InvalidTokenError:
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})

        # Continue with the request if authentication is successful
        response = await call_next(request)
        return response

    def _is_exempt_route(self, path: str) -> bool:
        """
        Checks if the current request path matches any of the exempt routes.
        """
        for exempt_route in self.exempt_routes:
            if re.match(exempt_route, path):
                return True
        return False
