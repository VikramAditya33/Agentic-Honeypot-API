from functools import lru_cache
import hashlib
import json
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


def generate_message_hash(message: str) -> str:
    """Generate hash for message caching"""
    return hashlib.md5(message.encode()).hexdigest()


class SimpleCache:
    """Simple in-memory cache for scam detection results"""
    
    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, Any] = {}
        self.max_size = max_size
        self.access_count: Dict[str, int] = {}
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key in self.cache:
            self.access_count[key] = self.access_count.get(key, 0) + 1
            logger.debug(f"Cache hit for key: {key[:8]}...")
            
            # Record cache hit in metrics
            try:
                from app.utils.metrics import metrics
                metrics.record_cache_hit()
            except:
                pass
            
            return self.cache[key]
        
        logger.debug(f"Cache miss for key: {key[:8]}...")
        
        # Record cache miss in metrics
        try:
            from app.utils.metrics import metrics
            metrics.record_cache_miss()
        except:
            pass
        
        return None
    
    def set(self, key: str, value: Any) -> None:
        """Set value in cache with LRU eviction"""
        if len(self.cache) >= self.max_size:
            # Evict least recently used
            lru_key = min(self.access_count, key=self.access_count.get)
            del self.cache[lru_key]
            del self.access_count[lru_key]
            logger.debug(f"Cache evicted key: {lru_key[:8]}...")
        
        self.cache[key] = value
        self.access_count[key] = 0
        logger.debug(f"Cache set for key: {key[:8]}...")
    
    def clear(self) -> None:
        """Clear all cache"""
        self.cache.clear()
        self.access_count.clear()
        logger.info("Cache cleared")
    
    def size(self) -> int:
        """Get current cache size"""
        return len(self.cache)


# Global cache instances
scam_detection_cache = SimpleCache(max_size=1000)
intelligence_cache = SimpleCache(max_size=500)
