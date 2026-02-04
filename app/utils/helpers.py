from app.services.session_manager import SessionData
import logging

logger = logging.getLogger(__name__)


def should_trigger_callback(session: SessionData) -> bool:
    """
    Determine if callback should be triggered for this session
    
    MANDATORY: Callback is sent after every scam detection as per GUVI requirements
    
    Args:
        session: Current session data
    
    Returns:
        True if callback should be sent, False otherwise
    """
    try:
        # MANDATORY: Always trigger callback if scam is detected
        # This is required for GUVI evaluation
        if session.scam_detected:
            logger.info(f"Callback trigger: Scam detected (mandatory for evaluation)")
            return True
        
        # Don't trigger for non-scam messages
        return False
    
    except Exception as e:
        logger.error(f"Error checking callback trigger: {e}")
        return False
