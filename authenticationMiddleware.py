from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
import jwt
from typing import Optional
import re

from utils.jwt_handler import decode_jwt_token


class AuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, exempt_routes: Optional[list] = None):
        super().__init__(app)
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
            payload = decode_jwt_token(token)
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
