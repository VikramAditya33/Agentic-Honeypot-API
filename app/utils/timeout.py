import asyncio
from functools import wraps
import logging

logger = logging.getLogger(__name__)


def async_timeout(seconds: int):
    """
    Decorator to add timeout to async functions
    
    Usage:
        @async_timeout(5)
        async def my_function():
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=seconds
                )
            except asyncio.TimeoutError:
                logger.error(f"Function {func.__name__} timed out after {seconds}s")
                raise
        return wrapper
    return decorator
