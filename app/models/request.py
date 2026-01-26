from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Union
from datetime import datetime, UTC


class Message(BaseModel):
    sender: str
    text: str
    timestamp: Union[str, int, float]
    
    @field_validator('timestamp')
    @classmethod
    def convert_timestamp(cls, v):
        if isinstance(v, (int, float)):
            if v > 10000000000:
                v = v / 1000
            return datetime.fromtimestamp(v, UTC).isoformat()
        return v or datetime.now(UTC).isoformat()


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = "English"
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str = Field(..., alias="sessionId")
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None
    
    class Config:
        populate_by_name = True

