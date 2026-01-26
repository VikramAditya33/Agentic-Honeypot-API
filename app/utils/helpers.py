from app.services.session_manager import SessionData
import logging

logger = logging.getLogger(__name__)


def should_trigger_callback(session: SessionData) -> bool:
    """
    Determine if callback should be triggered for this session
    
    Args:
        session: Current session data
    
    Returns:
        True if callback should be sent, False otherwise
    """
    try:
        # Don't trigger if not a scam
        if not session.scam_detected:
            return False
        if session.message_count >= 15:
            logger.info(f"Callback trigger: Message count threshold reached ({session.message_count})")
            return True
        from app.config import settings
        if session.message_count >= settings.max_conversation_turns:
            logger.info(f"Callback trigger: Max turns reached ({session.message_count})")
            return True
        intel = session.extracted_intelligence
        total_intel = (
            len(intel.get("bankAccounts", [])) +
            len(intel.get("upiIds", [])) +
            len(intel.get("phishingLinks", [])) +
            len(intel.get("phoneNumbers", []))
        )
        
        if total_intel >= 3 and session.message_count >= 10:
            logger.info(f"Callback trigger: Significant intelligence extracted ({total_intel} items)")
            return True
        
        # Don't trigger yet
        return False
    
    except Exception as e:
        logger.error(f"Error checking callback trigger: {e}")
        return False
