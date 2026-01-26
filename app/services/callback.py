from app.config import settings
from app.services.session_manager import SessionData
import httpx
import logging

logger = logging.getLogger(__name__)

# Create a shared httpx client with connection pooling
# This client will be reused across all callback requests
_http_client: httpx.AsyncClient = None


def get_http_client() -> httpx.AsyncClient:
    """Get or create shared HTTP client with connection pooling"""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=10.0,
            limits=httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
                keepalive_expiry=30.0
            )
        )
        logger.info("HTTP client initialized with connection pooling")
    return _http_client


async def close_http_client():
    """Close the shared HTTP client"""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None
        logger.info("HTTP client closed")


async def send_final_result_to_guvi(
    session_id: str,
    session_data: SessionData
) -> bool:
    """
    Send final intelligence to GUVI evaluation endpoint
    
    Args:
        session_id: Session identifier
        session_data: Complete session data with intelligence
    
    Returns:
        True if callback successful, False otherwise
    """
    try:
        # Build payload according to GUVI specification
        payload = {
            "sessionId": session_id,
            "scamDetected": session_data.scam_detected,
            "totalMessagesExchanged": session_data.message_count,
            "extractedIntelligence": {
                "bankAccounts": session_data.extracted_intelligence.get("bankAccounts", []),
                "upiIds": session_data.extracted_intelligence.get("upiIds", []),
                "phishingLinks": session_data.extracted_intelligence.get("phishingLinks", []),
                "phoneNumbers": session_data.extracted_intelligence.get("phoneNumbers", []),
                "suspiciousKeywords": session_data.extracted_intelligence.get("suspiciousKeywords", [])
            },
            "agentNotes": " | ".join(session_data.agent_notes) if session_data.agent_notes else "No additional notes"
        }
        
        logger.info(f"Sending final result callback for session {session_id}")
        logger.info(f"Payload: scamDetected={payload['scamDetected']}, "
                   f"messages={payload['totalMessagesExchanged']}, "
                   f"intelligence items={sum(len(v) for v in payload['extractedIntelligence'].values())}")
        
        # Get shared HTTP client with connection pooling
        client = get_http_client()
        
        # Send POST request to GUVI endpoint
        response = await client.post(
            settings.guvi_callback_url,
            json=payload,
            timeout=10.0
        )
        
        if response.status_code == 200:
            logger.info(f"Callback successful for session {session_id}")
            return True
        else:
            logger.warning(f"Callback failed for session {session_id}: "
                          f"Status {response.status_code}, Response: {response.text}")
            return False
    
    except httpx.TimeoutException:
        logger.error(f"Callback timeout for session {session_id}")
        return False
    
    except Exception as e:
        logger.error(f"Callback failed for session {session_id}: {e}", exc_info=True)
        return False


async def trigger_callback_if_needed(session_id: str, session_data: SessionData) -> bool:
    """
    Check if callback should be triggered and send if needed
    
    Args:
        session_id: Session identifier
        session_data: Current session data
    
    Returns:
        True if callback was sent, False otherwise
    """
    from app.utils.helpers import should_trigger_callback
    
    if should_trigger_callback(session_data):
        logger.info(f"Triggering callback for session {session_id}")
        return await send_final_result_to_guvi(session_id, session_data)
    
    return False
