"""
Groq API Key Manager with automatic rotation
"""
from groq import Groq
from app.config import settings
import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)


class GroqClientManager:
    """Manages multiple Groq API keys with automatic rotation"""
    
    def __init__(self):
        self.api_keys = settings.get_groq_api_keys()
        self.current_index = 0
        self.lock = threading.Lock()
        self.clients = {}
        
        # Initialize clients for all keys
        for i, key in enumerate(self.api_keys):
            try:
                self.clients[i] = Groq(api_key=key)
                logger.info(f"Initialized Groq client {i+1}/{len(self.api_keys)}")
            except Exception as e:
                logger.error(f"Failed to initialize Groq client {i+1}: {e}")
        
        if not self.clients:
            logger.error("No Groq clients could be initialized!")
        else:
            logger.info(f"Groq manager initialized with {len(self.clients)} API keys")
    
    def get_client(self) -> Optional[Groq]:
        """
        Get the next available Groq client using round-robin rotation
        
        Returns:
            Groq client instance or None if no clients available
        """
        if not self.clients:
            return None
        
        with self.lock:
            # Get current client
            client = self.clients.get(self.current_index)
            
            # Rotate to next key for next request
            self.current_index = (self.current_index + 1) % len(self.clients)
            
            return client
    
    def get_client_with_retry(self, max_retries: int = None) -> Optional[Groq]:
        """
        Get a Groq client with retry logic across all available keys
        
        Args:
            max_retries: Maximum number of keys to try (default: all keys)
        
        Returns:
            Groq client instance or None if all keys fail
        """
        if not self.clients:
            return None
        
        if max_retries is None:
            max_retries = len(self.clients)
        
        for _ in range(min(max_retries, len(self.clients))):
            client = self.get_client()
            if client:
                return client
        
        return None
    
    def get_total_keys(self) -> int:
        """Get total number of API keys configured"""
        return len(self.api_keys)
    
    def get_active_keys(self) -> int:
        """Get number of successfully initialized clients"""
        return len(self.clients)


# Global instance
groq_manager = GroqClientManager()
