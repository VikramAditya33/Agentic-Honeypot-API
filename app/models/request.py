from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, UTC


class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = None
    
    def __init__(self, **data):
        if 'timestamp' not in data or not data['timestamp']:
            data['timestamp'] = datetime.now(UTC).isoformat()
        super().__init__(**data)


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
