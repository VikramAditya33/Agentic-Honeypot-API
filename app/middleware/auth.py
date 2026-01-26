from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import settings


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip auth for health check, metrics, and analytics endpoints
        if request.url.path in ["/health", "/metrics", "/analytics"]:
            return await call_next(request)
        
        # Check for API key in headers
        api_key = request.headers.get("x-api-key")
        
        if not api_key:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": "error", "message": "API key is required"}
            )
        
        if api_key != settings.api_key:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": "error", "message": "Invalid API key"}
            )
        
        return await call_next(request)
