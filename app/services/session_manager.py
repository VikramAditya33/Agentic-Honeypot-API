from upstash_redis import Redis
from app.config import settings
from app.models.request import Message
from app.models.response import EngagementMetrics, ExtractedIntelligence
from typing import Optional, Dict, Any, List
from datetime import datetime, UTC
import json
import logging

logger = logging.getLogger(__name__)


class SessionData:
    def __init__(self, data: Dict[str, Any]):
        self.session_id = data.get("session_id")
        self.start_time = data.get("start_time")
        self.scam_detected = data.get("scam_detected", False)
        self.scam_type = data.get("scam_type", "unknown")
        self.conversation_history = data.get("conversation_history", [])
        self.extracted_intelligence = data.get("extracted_intelligence", {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        })
        self.message_count = data.get("message_count", 0)
        self.agent_notes = data.get("agent_notes", [])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "scam_detected": self.scam_detected,
            "scam_type": self.scam_type,
            "conversation_history": self.conversation_history,
            "extracted_intelligence": self.extracted_intelligence,
            "message_count": self.message_count,
            "agent_notes": self.agent_notes
        }


class SessionManager:
    def __init__(self):
        try:
            self.redis = Redis(
                url=settings.upstash_redis_url,
                token=settings.upstash_redis_token
            )
            logger.info("Redis connection initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            self.redis = None
    
    def _get_key(self, session_id: str) -> str:
        """Generate Redis key for session"""
        return f"session:{session_id}"
    
    async def create_session(
        self,
        session_id: str,
        scam_detected: bool = False,
        scam_type: str = "unknown"
    ) -> SessionData:
        """Create a new session"""
        try:
            session_data = {
                "session_id": session_id,
                "start_time": datetime.now(UTC).isoformat(),
                "scam_detected": scam_detected,
                "scam_type": scam_type,
                "conversation_history": [],
                "extracted_intelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": []
                },
                "message_count": 0,
                "agent_notes": []
            }
            
            if self.redis:
                self.redis.set(
                    self._get_key(session_id),
                    json.dumps(session_data),
                    ex=settings.session_ttl
                )
            
            logger.info(f"Created session: {session_id}")
            return SessionData(session_data)
        
        except Exception as e:
            logger.error(f"Error creating session {session_id}: {e}")
            raise

    async def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session data by ID"""
        try:
            if not self.redis:
                return None
            
            data = self.redis.get(self._get_key(session_id))
            
            if not data:
                logger.info(f"Session not found: {session_id}")
                return None
            
            session_data = json.loads(data)
            return SessionData(session_data)
        
        except Exception as e:
            logger.error(f"Error getting session {session_id}: {e}")
            return None
    
    async def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Update session with new data"""
        try:
            if not self.redis:
                return False
            
            session = await self.get_session(session_id)
            if not session:
                return False
            session_dict = session.to_dict()
            session_dict.update(data)
            
            self.redis.set(
                self._get_key(session_id),
                json.dumps(session_dict),
                ex=settings.session_ttl
            )
            
            logger.info(f"Updated session: {session_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error updating session {session_id}: {e}")
            return False
    
    async def add_message(self, session_id: str, message: Message) -> bool:
        """Add a message to conversation history"""
        try:
            session = await self.get_session(session_id)
            if not session:
                return False
            session.conversation_history.append(message.model_dump())
            session.message_count += 1
            return await self.update_session(session_id, {
                "conversation_history": session.conversation_history,
                "message_count": session.message_count
            })
        
        except Exception as e:
            logger.error(f"Error adding message to session {session_id}: {e}")
            return False
    
    async def add_intelligence(
        self,
        session_id: str,
        intel: ExtractedIntelligence
    ) -> bool:
        """Add extracted intelligence to session"""
        try:
            session = await self.get_session(session_id)
            if not session:
                return False
            current = session.extracted_intelligence
            
            current["bankAccounts"] = list(set(
                current.get("bankAccounts", []) + intel.bankAccounts
            ))
            current["upiIds"] = list(set(
                current.get("upiIds", []) + intel.upiIds
            ))
            current["phishingLinks"] = list(set(
                current.get("phishingLinks", []) + intel.phishingLinks
            ))
            current["phoneNumbers"] = list(set(
                current.get("phoneNumbers", []) + intel.phoneNumbers
            ))
            current["suspiciousKeywords"] = list(set(
                current.get("suspiciousKeywords", []) + intel.suspiciousKeywords
            ))
            return await self.update_session(session_id, {
                "extracted_intelligence": current
            })
        
        except Exception as e:
            logger.error(f"Error adding intelligence to session {session_id}: {e}")
            return False
    
    async def add_agent_note(self, session_id: str, note: str) -> bool:
        """Add an agent note to session"""
        try:
            session = await self.get_session(session_id)
            if not session:
                return False
            
            session.agent_notes.append(note)
            
            return await self.update_session(session_id, {
                "agent_notes": session.agent_notes
            })
        
        except Exception as e:
            logger.error(f"Error adding note to session {session_id}: {e}")
            return False
    
    async def get_metrics(self, session_id: str) -> Optional[EngagementMetrics]:
        """Get engagement metrics for session"""
        try:
            session = await self.get_session(session_id)
            if not session:
                return None
            start_time = datetime.fromisoformat(session.start_time)
            duration = int((datetime.now(UTC) - start_time).total_seconds())
            
            return EngagementMetrics(
                engagementDurationSeconds=duration,
                totalMessagesExchanged=session.message_count
            )
        
        except Exception as e:
            logger.error(f"Error getting metrics for session {session_id}: {e}")
            return None
    
    async def get_intelligence(self, session_id: str) -> Optional[ExtractedIntelligence]:
        """Get extracted intelligence for session"""
        try:
            session = await self.get_session(session_id)
            if not session:
                return None
            
            return ExtractedIntelligence(**session.extracted_intelligence)
        
        except Exception as e:
            logger.error(f"Error getting intelligence for session {session_id}: {e}")
            return None
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        try:
            if not self.redis:
                return False
            
            self.redis.delete(self._get_key(session_id))
            logger.info(f"Deleted session: {session_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error deleting session {session_id}: {e}")
            return False
