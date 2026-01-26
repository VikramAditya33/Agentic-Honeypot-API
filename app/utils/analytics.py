"""
Conversation analytics for tracking patterns and effectiveness
"""
from typing import Dict, List, Optional
from datetime import datetime, UTC
import logging

logger = logging.getLogger(__name__)


class ConversationAnalytics:
    """Track conversation patterns and effectiveness"""
    
    def __init__(self):
        # Track when intelligence is extracted
        self.intelligence_extraction_turns: Dict[str, List[int]] = {
            "upiIds": [],
            "bankAccounts": [],
            "phoneNumbers": [],
            "phishingLinks": []
        }
        
        # Track agent response effectiveness
        self.response_effectiveness: Dict[str, int] = {}
        
        # Track scammer behavior patterns
        self.scammer_patterns: Dict[str, int] = {
            "urgency_tactics": 0,
            "threats": 0,
            "payment_requests": 0,
            "credential_requests": 0,
            "link_sharing": 0,
            "emotional_manipulation": 0
        }
        
        # Track success rate by scam type
        self.scam_type_stats: Dict[str, Dict] = {}
        
        # Track conversation lengths
        self.conversation_lengths: List[int] = []
        
        # Track extraction timeline
        self.extraction_timeline: List[Dict] = []
    
    def record_intelligence_extraction(
        self,
        intel_type: str,
        turn_number: int,
        value: str,
        session_id: str
    ):
        """Record when intelligence was extracted"""
        if intel_type in self.intelligence_extraction_turns:
            self.intelligence_extraction_turns[intel_type].append(turn_number)
        
        self.extraction_timeline.append({
            "session_id": session_id,
            "intel_type": intel_type,
            "turn": turn_number,
            "value": value,
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        logger.info(f"Analytics: {intel_type} extracted at turn {turn_number}")
    
    def record_response_effectiveness(
        self,
        response: str,
        led_to_extraction: bool
    ):
        """Track which responses lead to intelligence extraction"""
        # Simplified tracking - count effective responses
        key = "effective" if led_to_extraction else "ineffective"
        self.response_effectiveness[key] = self.response_effectiveness.get(key, 0) + 1
    
    def record_scammer_behavior(self, behavior_type: str):
        """Record scammer behavior patterns"""
        if behavior_type in self.scammer_patterns:
            self.scammer_patterns[behavior_type] += 1
    
    def record_scam_type_outcome(
        self,
        scam_type: str,
        intelligence_extracted: int,
        conversation_length: int
    ):
        """Record outcome for a scam type"""
        if scam_type not in self.scam_type_stats:
            self.scam_type_stats[scam_type] = {
                "total_sessions": 0,
                "total_intelligence": 0,
                "total_turns": 0,
                "successful_extractions": 0
            }
        
        stats = self.scam_type_stats[scam_type]
        stats["total_sessions"] += 1
        stats["total_intelligence"] += intelligence_extracted
        stats["total_turns"] += conversation_length
        
        if intelligence_extracted > 0:
            stats["successful_extractions"] += 1
        
        self.conversation_lengths.append(conversation_length)
    
    def get_average_turns_to_extract(self, intel_type: str) -> float:
        """Get average number of turns to extract specific intelligence"""
        turns = self.intelligence_extraction_turns.get(intel_type, [])
        if not turns:
            return 0.0
        return sum(turns) / len(turns)
    
    def get_most_effective_responses(self, top_n: int = 5) -> List[str]:
        """Get most effective agent responses (placeholder)"""
        # This would require more detailed tracking
        return ["Responses that led to extraction would be tracked here"]
    
    def get_scammer_behavior_summary(self) -> Dict:
        """Get summary of scammer behavior patterns"""
        total = sum(self.scammer_patterns.values())
        if total == 0:
            return self.scammer_patterns
        
        return {
            behavior: {
                "count": count,
                "percentage": (count / total) * 100
            }
            for behavior, count in self.scammer_patterns.items()
        }
    
    def get_success_rate_by_scam_type(self) -> Dict:
        """Get success rate for each scam type"""
        results = {}
        
        for scam_type, stats in self.scam_type_stats.items():
            if stats["total_sessions"] == 0:
                continue
            
            results[scam_type] = {
                "total_sessions": stats["total_sessions"],
                "success_rate": (stats["successful_extractions"] / stats["total_sessions"]) * 100,
                "avg_intelligence_per_session": stats["total_intelligence"] / stats["total_sessions"],
                "avg_conversation_length": stats["total_turns"] / stats["total_sessions"]
            }
        
        return results
    
    def get_analytics_summary(self) -> Dict:
        """Get comprehensive analytics summary"""
        return {
            "intelligence_extraction": {
                "avg_turns_to_upi": self.get_average_turns_to_extract("upiIds"),
                "avg_turns_to_bank": self.get_average_turns_to_extract("bankAccounts"),
                "avg_turns_to_phone": self.get_average_turns_to_extract("phoneNumbers"),
                "avg_turns_to_link": self.get_average_turns_to_extract("phishingLinks"),
                "total_extractions": len(self.extraction_timeline)
            },
            "response_effectiveness": self.response_effectiveness,
            "scammer_behavior": self.get_scammer_behavior_summary(),
            "scam_type_performance": self.get_success_rate_by_scam_type(),
            "conversation_stats": {
                "total_conversations": len(self.conversation_lengths),
                "avg_length": sum(self.conversation_lengths) / len(self.conversation_lengths) if self.conversation_lengths else 0,
                "min_length": min(self.conversation_lengths) if self.conversation_lengths else 0,
                "max_length": max(self.conversation_lengths) if self.conversation_lengths else 0
            }
        }
    
    def log_analytics(self):
        """Log analytics summary"""
        summary = self.get_analytics_summary()
        logger.info("=== Conversation Analytics ===")
        logger.info(f"Total Extractions: {summary['intelligence_extraction']['total_extractions']}")
        logger.info(f"Avg Turns to UPI: {summary['intelligence_extraction']['avg_turns_to_upi']:.1f}")
        logger.info(f"Avg Conversation Length: {summary['conversation_stats']['avg_length']:.1f}")
        logger.info(f"Total Conversations: {summary['conversation_stats']['total_conversations']}")
        logger.info("============================")


# Global analytics instance
analytics = ConversationAnalytics()
