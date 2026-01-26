from pydantic_settings import BaseSettings
from pydantic import ConfigDict, field_validator
from typing import Optional, List
import os


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", case_sensitive=False)
    
    # API Configuration
    api_key: str
    port: int = 8000
    
    # Groq Configuration - supports multiple keys
    groq_api_keys: str  # Comma-separated list of API keys
    groq_model: str = "llama-3.3-70b-versatile"
    
    # Upstash Redis
    upstash_redis_url: str
    upstash_redis_token: str
    
    # GUVI Callback
    guvi_callback_url: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    
    # Session Configuration
    session_ttl: int = 3600
    max_conversation_turns: int = 50
    
    @field_validator('groq_api_keys')
    @classmethod
    def parse_api_keys(cls, v: str) -> str:
        """Validate that at least one API key is provided"""
        keys = [k.strip() for k in v.split(',') if k.strip()]
        if not keys:
            raise ValueError("At least one Groq API key must be provided")
        return v
    
    def get_groq_api_keys(self) -> List[str]:
        """Get list of Groq API keys"""
        return [k.strip() for k in self.groq_api_keys.split(',') if k.strip()]


settings = Settings()
