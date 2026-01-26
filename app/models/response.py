from pydantic import BaseModel
from typing import List


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []


class HoneypotResponse(BaseModel):
    status: str
    scamDetected: bool
    agentResponse: str  # The actual reply to scammer
    engagementMetrics: EngagementMetrics
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str
