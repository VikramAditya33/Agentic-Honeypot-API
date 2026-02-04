from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up Honeypot API...")
    yield
    logger.info("Shutting down Honeypot API...")
    from app.services.callback import close_http_client
    await close_http_client()

app = FastAPI(
    title="Agentic Honey-Pot API",
    description="AI-powered honeypot for scam detection and intelligence extraction",
    version="1.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(APIKeyMiddleware)


class TimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        metrics.record_request()
        
        response = await call_next(request)
        process_time = time.time() - start_time
        
        metrics.record_response_time(process_time)
        response.headers["X-Process-Time"] = str(process_time)
        logger.info(f"{request.method} {request.url.path} - {process_time:.3f}s")
        return response


app.add_middleware(TimingMiddleware)

session_manager = SessionManager()
scam_detector = ScamDetector()
agent = HoneypotAgent()
intel_extractor = IntelligenceExtractor()


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


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    body = await request.body()
    logger.error(f"Validation error. Body received: {body.decode()}")
    logger.error(f"Validation errors: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "error",
            "message": "Invalid request format",
            "details": exc.errors()
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


@app.get("/metrics")
async def get_metrics():
    return metrics.get_summary()


@app.get("/analytics")
async def get_analytics():
    return analytics.get_analytics_summary()


@app.post("/api/honeypot")
@limiter.limit("100/minute")
async def honeypot_endpoint(request: Request, honeypot_request: HoneypotRequest):
    try:
        logger.info(f"Processing request for session: {honeypot_request.sessionId}")
        
        session = await session_manager.get_session(honeypot_request.sessionId)
        
        if not session or len(honeypot_request.conversationHistory) == 0:
            logger.info(f"First message for session {honeypot_request.sessionId}, detecting scam...")
            
            metadata_dict = honeypot_request.metadata.model_dump() if honeypot_request.metadata else {}
            scam_result = await scam_detector.detect_scam(
                honeypot_request.message.text,
                metadata_dict
            )
            
            logger.info(f"Scam detection: {scam_result.is_scam} (confidence: {scam_result.confidence})")
            
            metrics.record_scam_detection(scam_result.is_scam)
            
            session = await session_manager.create_session(
                honeypot_request.sessionId,
                scam_detected=scam_result.is_scam,
                scam_type=scam_result.scam_type
            )
            await session_manager.add_agent_note(
                honeypot_request.sessionId,
                f"Initial detection: {scam_result.reasoning}"
            )
        logger.info(f"Extracting intelligence from message...")
        new_intel = await intel_extractor.extract(honeypot_request.message.text)
        await session_manager.add_intelligence(honeypot_request.sessionId, new_intel)
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
        metrics.record_intelligence("upiIds", len(new_intel.upiIds))
        metrics.record_intelligence("bankAccounts", len(new_intel.bankAccounts))
        metrics.record_intelligence("phoneNumbers", len(new_intel.phoneNumbers))
        metrics.record_intelligence("phishingLinks", len(new_intel.phishingLinks))
        metrics.record_intelligence("keywords", len(new_intel.suspiciousKeywords))
        if session.scam_detected:
            logger.info(f"Generating agent response for scam type: {session.scam_type}")
            message_analysis = await agent.analyze_scammer_message(honeypot_request.message.text)
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
            
            language = honeypot_request.metadata.language if honeypot_request.metadata else "English"
            
            agent_response = await agent.generate_response(
                honeypot_request.sessionId,
                honeypot_request.message.text,
                honeypot_request.conversationHistory,
                session.scam_type,
                language=language
            )
            
            agent_note = agent.generate_agent_note(
                session.scam_type,
                message_analysis,
                turn_number
            )
            await session_manager.add_agent_note(honeypot_request.sessionId, agent_note)
        else:
            logger.info(f"Not a scam, sending neutral response")
            agent_response = NON_SCAM_RESPONSE
        await session_manager.add_message(honeypot_request.sessionId, honeypot_request.message)
        agent_message = Message(
            sender="user",
            text=agent_response,
            timestamp=datetime.now(UTC).isoformat()
        )
        await session_manager.add_message(honeypot_request.sessionId, agent_message)
        engagement_metrics = await session_manager.get_metrics(honeypot_request.sessionId)
        intelligence = await session_manager.get_intelligence(honeypot_request.sessionId)
        if engagement_metrics:
            metrics.record_session_duration(engagement_metrics.engagementDurationSeconds)
            total_intel = (
                len(intelligence.bankAccounts) + len(intelligence.upiIds) +
                len(intelligence.phoneNumbers) + len(intelligence.phishingLinks)
            )
            analytics.record_scam_type_outcome(
                session.scam_type,
                total_intel,
                engagement_metrics.totalMessagesExchanged
            )
        updated_session = await session_manager.get_session(honeypot_request.sessionId)
        agent_notes = " | ".join(updated_session.agent_notes) if updated_session else ""
        
        # Build full response for internal tracking
        full_response = HoneypotResponse(
            status="success",
            scamDetected=session.scam_detected,
            agentResponse=agent_response,
            engagementMetrics=engagement_metrics,
            extractedIntelligence=intelligence,
            agentNotes=agent_notes
        )
        
        logger.info(f"Session {honeypot_request.sessionId}: Response generated successfully")
        
        # Trigger callback if needed
        await trigger_callback_if_needed(honeypot_request.sessionId, updated_session)
        
        # Return simplified response format as per GUVI requirements
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "reply": agent_response
            }
        )
    
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
@limiter.limit("10/minute")
async def finalize_session(request: Request, session_id: str):
    """
    Manually trigger callback for testing purposes
    Requires API key authentication
    """
    try:
        logger.info(f"Manual callback triggered for session: {session_id}")
        session = await session_manager.get_session(session_id)
        
        if not session:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "status": "error",
                    "message": f"Session {session_id} not found"
                }
            )
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
