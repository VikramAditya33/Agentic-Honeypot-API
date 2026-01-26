from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from app.middleware.auth import APIKeyMiddleware
from app.config import settings
from app.models.request import HoneypotRequest, Message
from app.models.response import HoneypotResponse, EngagementMetrics, ExtractedIntelligence
from app.services.session_manager import SessionManager
from app.services.scam_detector import ScamDetector
from app.services.agent import HoneypotAgent
from app.services.intel_extractor import IntelligenceExtractor
from app.services.callback import trigger_callback_if_needed, send_final_result_to_guvi
from app.prompts.system_prompts import NON_SCAM_RESPONSE
from app.utils.metrics import metrics
from app.utils.analytics import analytics
from datetime import datetime, UTC
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting up Honeypot API...")
    # HTTP client will be initialized on first use
    yield
    # Shutdown
    logger.info("Shutting down Honeypot API...")
    from app.services.callback import close_http_client
    await close_http_client()

# Initialize FastAPI app with lifespan
app = FastAPI(
    title="Agentic Honey-Pot API",
    description="AI-powered honeypot for scam detection and intelligence extraction",
    version="1.0.0",
    lifespan=lifespan
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add API key authentication middleware
app.add_middleware(APIKeyMiddleware)


# Request timing middleware for performance monitoring
class TimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Record request
        metrics.record_request()
        
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Record response time
        metrics.record_response_time(process_time)
        
        response.headers["X-Process-Time"] = str(process_time)
        logger.info(f"{request.method} {request.url.path} - {process_time:.3f}s")
        return response


app.add_middleware(TimingMiddleware)


# Initialize services
session_manager = SessionManager()
scam_detector = ScamDetector()
agent = HoneypotAgent()
intel_extractor = IntelligenceExtractor()


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "message": "Internal server error occurred"
        }
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint - no authentication required"""
    return {
        "status": "healthy",
        "service": "honeypot-api",
        "version": "1.0.0"
    }


# Metrics endpoint
@app.get("/metrics")
async def get_metrics():
    """Get system metrics - no authentication required for monitoring"""
    return metrics.get_summary()


# Analytics endpoint
@app.get("/analytics")
async def get_analytics():
    """Get conversation analytics - no authentication required for monitoring"""
    return analytics.get_analytics_summary()


# Main honeypot endpoint
@app.post("/api/honeypot")
@limiter.limit("100/minute")  # Rate limit: 100 requests per minute
async def honeypot_endpoint(request: Request, honeypot_request: HoneypotRequest):
    """
    Main endpoint for honeypot interactions
    Accepts scam messages and returns agent responses with extracted intelligence
    """
    try:
        logger.info(f"Processing request for session: {honeypot_request.sessionId}")
        
        # 1. Get or create session
        session = await session_manager.get_session(honeypot_request.sessionId)
        
        # 2. If first message (no session or empty history), detect scam
        if not session or len(honeypot_request.conversationHistory) == 0:
            logger.info(f"First message for session {honeypot_request.sessionId}, detecting scam...")
            
            # Detect scam intent
            metadata_dict = honeypot_request.metadata.model_dump() if honeypot_request.metadata else {}
            scam_result = await scam_detector.detect_scam(
                honeypot_request.message.text,
                metadata_dict
            )
            
            logger.info(f"Scam detection: {scam_result.is_scam} (confidence: {scam_result.confidence})")
            
            # Record scam detection
            metrics.record_scam_detection(scam_result.is_scam)
            
            # Create new session
            session = await session_manager.create_session(
                honeypot_request.sessionId,
                scam_detected=scam_result.is_scam,
                scam_type=scam_result.scam_type
            )
            
            # Add initial note
            await session_manager.add_agent_note(
                honeypot_request.sessionId,
                f"Initial detection: {scam_result.reasoning}"
            )
        
        # 3. Extract intelligence from scammer message
        logger.info(f"Extracting intelligence from message...")
        new_intel = await intel_extractor.extract(honeypot_request.message.text)
        await session_manager.add_intelligence(honeypot_request.sessionId, new_intel)
        
        # Record intelligence extraction for analytics
        turn_number = len(honeypot_request.conversationHistory) // 2 + 1
        if new_intel.upiIds:
            for upi in new_intel.upiIds:
                analytics.record_intelligence_extraction("upiIds", turn_number, upi, honeypot_request.sessionId)
        if new_intel.bankAccounts:
            for acc in new_intel.bankAccounts:
                analytics.record_intelligence_extraction("bankAccounts", turn_number, acc, honeypot_request.sessionId)
        if new_intel.phoneNumbers:
            for phone in new_intel.phoneNumbers:
                analytics.record_intelligence_extraction("phoneNumbers", turn_number, phone, honeypot_request.sessionId)
        if new_intel.phishingLinks:
            for link in new_intel.phishingLinks:
                analytics.record_intelligence_extraction("phishingLinks", turn_number, link, honeypot_request.sessionId)
        
        # Record intelligence extraction for metrics
        metrics.record_intelligence("upiIds", len(new_intel.upiIds))
        metrics.record_intelligence("bankAccounts", len(new_intel.bankAccounts))
        metrics.record_intelligence("phoneNumbers", len(new_intel.phoneNumbers))
        metrics.record_intelligence("phishingLinks", len(new_intel.phishingLinks))
        metrics.record_intelligence("keywords", len(new_intel.suspiciousKeywords))
        
        # 4. Generate agent response
        if session.scam_detected:
            logger.info(f"Generating agent response for scam type: {session.scam_type}")
            
            # Analyze scammer message
            message_analysis = await agent.analyze_scammer_message(honeypot_request.message.text)
            
            # Record scammer behavior for analytics
            if message_analysis.get("urgency_level") == "high":
                analytics.record_scammer_behavior("urgency_tactics")
            if message_analysis.get("threat_detected"):
                analytics.record_scammer_behavior("threats")
            if message_analysis.get("request_type") == "payment":
                analytics.record_scammer_behavior("payment_requests")
            elif message_analysis.get("request_type") == "credentials":
                analytics.record_scammer_behavior("credential_requests")
            elif message_analysis.get("request_type") == "link":
                analytics.record_scammer_behavior("link_sharing")
            if message_analysis.get("emotional_manipulation"):
                analytics.record_scammer_behavior("emotional_manipulation")
            
            # Get language from metadata
            language = honeypot_request.metadata.language if honeypot_request.metadata else "English"
            
            # Generate response with language support
            agent_response = await agent.generate_response(
                honeypot_request.sessionId,
                honeypot_request.message.text,
                honeypot_request.conversationHistory,
                session.scam_type,
                language=language
            )
            
            # Generate and add agent note
            turn_number = len(honeypot_request.conversationHistory) // 2 + 1
            agent_note = agent.generate_agent_note(
                session.scam_type,
                message_analysis,
                turn_number
            )
            await session_manager.add_agent_note(honeypot_request.sessionId, agent_note)
        else:
            logger.info(f"Not a scam, sending neutral response")
            agent_response = NON_SCAM_RESPONSE
        
        # 5. Update session with new messages
        # Add scammer's message
        await session_manager.add_message(honeypot_request.sessionId, honeypot_request.message)
        
        # Add agent's response
        agent_message = Message(
            sender="user",
            text=agent_response,
            timestamp=datetime.now(UTC).isoformat()
        )
        await session_manager.add_message(honeypot_request.sessionId, agent_message)
        
        # 6. Get current metrics and intelligence
        engagement_metrics = await session_manager.get_metrics(honeypot_request.sessionId)
        intelligence = await session_manager.get_intelligence(honeypot_request.sessionId)
        
        # Record session duration for monitoring
        if engagement_metrics:
            metrics.record_session_duration(engagement_metrics.engagementDurationSeconds)
            
            # Record scam type outcome for analytics
            total_intel = (
                len(intelligence.bankAccounts) + len(intelligence.upiIds) +
                len(intelligence.phoneNumbers) + len(intelligence.phishingLinks)
            )
            analytics.record_scam_type_outcome(
                session.scam_type,
                total_intel,
                engagement_metrics.totalMessagesExchanged
            )
        
        # Get updated session for notes
        updated_session = await session_manager.get_session(honeypot_request.sessionId)
        agent_notes = " | ".join(updated_session.agent_notes) if updated_session else ""
        
        # 7. Build and return response
        response = HoneypotResponse(
            status="success",
            scamDetected=session.scam_detected,
            agentResponse=agent_response,
            engagementMetrics=engagement_metrics,
            extractedIntelligence=intelligence,
            agentNotes=agent_notes
        )
        
        logger.info(f"Session {honeypot_request.sessionId}: Response generated successfully")
        
        # 8. Check if callback should be triggered (automatic)
        await trigger_callback_if_needed(honeypot_request.sessionId, updated_session)
        
        return response
    
    except Exception as e:
        logger.error(f"Error in honeypot endpoint: {e}", exc_info=True)
        metrics.record_error("other")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Failed to process request"
            }
        )


# Manual callback endpoint for testing
@app.post("/api/finalize-session/{session_id}")
@limiter.limit("10/minute")  # Lower rate limit for manual operations
async def finalize_session(request: Request, session_id: str):
    """
    Manually trigger callback for testing purposes
    Requires API key authentication
    """
    try:
        logger.info(f"Manual callback triggered for session: {session_id}")
        
        # Get session data
        session = await session_manager.get_session(session_id)
        
        if not session:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "message": f"Session {session_id} not found"
                }
            )
        
        # Send callback
        success = await send_final_result_to_guvi(session_id, session)
        
        if success:
            return {
                "status": "success",
                "message": f"Callback sent successfully for session {session_id}",
                "sessionId": session_id,
                "scamDetected": session.scam_detected,
                "totalMessages": session.message_count
            }
        else:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "status": "error",
                    "message": "Failed to send callback"
                }
            )
    
    except Exception as e:
        logger.error(f"Error in manual callback: {e}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Failed to process callback request"
            }
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.port)
