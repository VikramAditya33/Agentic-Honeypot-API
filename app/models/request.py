from pydantic import BaseModel
from typing import List, Optional


class Message(BaseModel):
    sender: str  # "scammer" or "user"
    text: str
    timestamp: str


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None
