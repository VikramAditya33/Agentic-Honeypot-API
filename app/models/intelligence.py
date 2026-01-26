"""
Enhanced intelligence models with confidence scoring
"""
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class IntelligenceItem(BaseModel):
    """Individual intelligence item with metadata"""
    value: str
    confidence: float  # 0.0 to 1.0
    source: str  # "regex", "llm", "both"
    extracted_at: str
    message_turn: int  # Which turn was this extracted


class EnhancedIntelligence(BaseModel):
    """Enhanced intelligence with confidence scores"""
    bankAccounts: List[IntelligenceItem] = []
    upiIds: List[IntelligenceItem] = []
    phishingLinks: List[IntelligenceItem] = []
    phoneNumbers: List[IntelligenceItem] = []
    suspiciousKeywords: List[IntelligenceItem] = []
    
    def to_simple_format(self):
        """Convert to simple format for API response"""
        return {
            "bankAccounts": [item.value for item in self.bankAccounts],
            "upiIds": [item.value for item in self.upiIds],
            "phishingLinks": [item.value for item in self.phishingLinks],
            "phoneNumbers": [item.value for item in self.phoneNumbers],
            "suspiciousKeywords": [item.value for item in self.suspiciousKeywords]
        }
    
    def get_high_confidence_items(self, threshold: float = 0.7):
        """Get only high confidence items"""
        return {
            "bankAccounts": [item for item in self.bankAccounts if item.confidence >= threshold],
            "upiIds": [item for item in self.upiIds if item.confidence >= threshold],
            "phishingLinks": [item for item in self.phishingLinks if item.confidence >= threshold],
            "phoneNumbers": [item for item in self.phoneNumbers if item.confidence >= threshold],
            "suspiciousKeywords": [item for item in self.suspiciousKeywords if item.confidence >= threshold]
        }
    
    def get_statistics(self):
        """Get statistics about extracted intelligence"""
        all_items = (
            self.bankAccounts + self.upiIds + self.phishingLinks + 
            self.phoneNumbers + self.suspiciousKeywords
        )
        
        if not all_items:
            return {
                "total_items": 0,
                "average_confidence": 0.0,
                "high_confidence_count": 0,
                "sources": {}
            }
        
        return {
            "total_items": len(all_items),
            "average_confidence": sum(item.confidence for item in all_items) / len(all_items),
            "high_confidence_count": sum(1 for item in all_items if item.confidence >= 0.7),
            "sources": {
                "regex": sum(1 for item in all_items if item.source == "regex"),
                "llm": sum(1 for item in all_items if item.source == "llm"),
                "both": sum(1 for item in all_items if item.source == "both")
            }
        }
