import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings
from datetime import datetime, UTC


@pytest.mark.asyncio
async def test_health_check():
    """Test health check endpoint (no auth required)"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_api_key_required():
    """Test that API key is required for honeypot endpoint"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/honeypot", json={})
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_invalid_api_key():
    """Test that invalid API key is rejected"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/honeypot",
            json={},
            headers={"x-api-key": "invalid_key"}
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_honeypot_endpoint_basic():
    """Test basic honeypot endpoint functionality"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "sessionId": "test-session-001",
            "message": {
                "sender": "scammer",
                "text": "Your account will be blocked. Verify immediately.",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": [],
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }
        
        response = await client.post(
            "/api/honeypot",
            json=payload,
            headers={"x-api-key": settings.api_key}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert "scamDetected" in data
        assert "agentResponse" in data
        assert "engagementMetrics" in data
        assert "extractedIntelligence" in data
        assert "agentNotes" in data
        
        assert data["scamDetected"] == True
        assert len(data["agentResponse"]) > 0


@pytest.mark.asyncio
async def test_multi_turn_conversation():
    """Test multi-turn conversation handling"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        session_id = "test-session-002"
        
        payload1 = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Your bank account will be suspended. Send ₹500 to verify@paytm",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": []
        }
        
        response1 = await client.post(
            "/api/honeypot",
            json=payload1,
            headers={"x-api-key": settings.api_key}
        )
        
        assert response1.status_code == 200
        data1 = response1.json()
        agent_response1 = data1["agentResponse"]
        
        payload2 = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Send money now or account will be closed!",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": [
                payload1["message"],
                {
                    "sender": "user",
                    "text": agent_response1,
                    "timestamp": datetime.now(UTC).isoformat()
                }
            ]
        }
        
        response2 = await client.post(
            "/api/honeypot",
            json=payload2,
            headers={"x-api-key": settings.api_key}
        )
        
        assert response2.status_code == 200
        data2 = response2.json()
        
        assert data2["engagementMetrics"]["totalMessagesExchanged"] >= 2
        
        intel = data2["extractedIntelligence"]
        assert "verify@paytm" in intel["upiIds"] or len(intel["upiIds"]) > 0


@pytest.mark.asyncio
async def test_manual_callback_endpoint():
    """Test manual callback trigger endpoint"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "sessionId": "test-callback-001",
            "message": {
                "sender": "scammer",
                "text": "Send money to test@paytm",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": []
        }
        
        await client.post(
            "/api/honeypot",
            json=payload,
            headers={"x-api-key": settings.api_key}
        )
        
        response = await client.post(
            "/api/finalize-session/test-callback-001",
            headers={"x-api-key": settings.api_key}
        )
        
        assert response.status_code == 200
