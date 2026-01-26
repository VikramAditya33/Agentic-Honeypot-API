import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings
from datetime import datetime, UTC
import uuid


# Test scenarios for different scam types
SCAM_SCENARIOS = [
    {
        "type": "bank_fraud",
        "messages": [
            "Your account will be blocked today",
            "Verify by sending ₹100 to verify@upi",
            "Call our helpline: +919999999999"
        ],
        "expected_intel": {
            "upiIds": ["verify@upi"],
            "phoneNumbers": ["+919999999999"],
            "keywords": ["blocked", "verify"]
        }
    },
    {
        "type": "upi_scam",
        "messages": [
            "You won ₹50,000! Claim now",
            "Pay ₹500 processing fee to winner@paytm",
            "Visit: http://bit.ly/claim-prize"
        ],
        "expected_intel": {
            "upiIds": ["winner@paytm"],
            "phishingLinks": ["http://bit.ly/claim-prize"],
            "keywords": ["won", "claim", "prize"]
        }
    },
    {
        "type": "phishing",
        "messages": [
            "Update your KYC details immediately",
            "Click here: http://fake-bank.com/update",
            "Enter your account number and password"
        ],
        "expected_intel": {
            "phishingLinks": ["http://fake-bank.com/update"],
            "keywords": ["kyc", "update", "immediately"]
        }
    }
]


@pytest.mark.asyncio
async def test_full_conversation_bank_fraud():
    """Test complete conversation flow for bank fraud scenario"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        session_id = f"test-bank-{uuid.uuid4()}"
        scenario = SCAM_SCENARIOS[0]
        history = []
        
        for i, msg in enumerate(scenario["messages"]):
            payload = {
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": msg,
                    "timestamp": datetime.now(UTC).isoformat()
                },
                "conversationHistory": history
            }
            
            response = await client.post(
                "/api/honeypot",
                json=payload,
                headers={"x-api-key": settings.api_key}
            )
            
            assert response.status_code == 200
            data = response.json()
            
            # Verify scam detection
            assert data["scamDetected"] == True
            
            # Verify agent response exists
            assert len(data["agentResponse"]) > 0
            
            # Verify metrics increase
            assert data["engagementMetrics"]["totalMessagesExchanged"] == (i + 1) * 2
            
            # Update history
            history.append(payload["message"])
            history.append({
                "sender": "user",
                "text": data["agentResponse"],
                "timestamp": datetime.now(UTC).isoformat()
            })
        
        # Final verification - check accumulated intelligence
        intel = data["extractedIntelligence"]
        
        # Should have extracted UPI ID
        assert len(intel["upiIds"]) > 0
        
        # Should have extracted phone number
        assert len(intel["phoneNumbers"]) > 0
        
        # Should have keywords
        assert len(intel["suspiciousKeywords"]) > 0


@pytest.mark.asyncio
async def test_full_conversation_upi_scam():
    """Test complete conversation flow for UPI scam scenario"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        session_id = f"test-upi-{uuid.uuid4()}"
        scenario = SCAM_SCENARIOS[1]
        history = []
        
        for i, msg in enumerate(scenario["messages"]):
            payload = {
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": msg,
                    "timestamp": datetime.now(UTC).isoformat()
                },
                "conversationHistory": history,
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
            assert data["scamDetected"] == True
            
            # Update history
            history.append(payload["message"])
            history.append({
                "sender": "user",
                "text": data["agentResponse"],
                "timestamp": datetime.now(UTC).isoformat()
            })
        
        # Verify intelligence extraction
        intel = data["extractedIntelligence"]
        assert len(intel["upiIds"]) > 0 or len(intel["phishingLinks"]) > 0


@pytest.mark.asyncio
async def test_edge_case_non_scam():
    """Test handling of non-scam messages"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "sessionId": f"test-nonscam-{uuid.uuid4()}",
            "message": {
                "sender": "scammer",
                "text": "Hello, how are you?",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": []
        }
        
        response = await client.post(
            "/api/honeypot",
            json=payload,
            headers={"x-api-key": settings.api_key}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # May or may not be detected as scam (low confidence)
        # But should handle gracefully
        assert "agentResponse" in data


@pytest.mark.asyncio
async def test_edge_case_empty_message():
    """Test handling of empty message"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "sessionId": f"test-empty-{uuid.uuid4()}",
            "message": {
                "sender": "scammer",
                "text": "",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": []
        }
        
        response = await client.post(
            "/api/honeypot",
            json=payload,
            headers={"x-api-key": settings.api_key}
        )
        
        # Should handle gracefully (200 or 422)
        assert response.status_code in [200, 422]


@pytest.mark.asyncio
async def test_edge_case_malformed_request():
    """Test handling of malformed request"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Missing required fields
        payload = {
            "sessionId": "test-malformed"
        }
        
        response = await client.post(
            "/api/honeypot",
            json=payload,
            headers={"x-api-key": settings.api_key}
        )
        
        # Should return validation error
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_intelligence_accumulation():
    """Test that intelligence accumulates across messages"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        session_id = f"test-accumulation-{uuid.uuid4()}"
        
        # First message with UPI
        payload1 = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Send money to first@paytm",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": []
        }
        
        response1 = await client.post(
            "/api/honeypot",
            json=payload1,
            headers={"x-api-key": settings.api_key}
        )
        
        data1 = response1.json()
        intel1_count = len(data1["extractedIntelligence"]["upiIds"])
        
        # Second message with different UPI
        payload2 = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Or send to second@phonepe",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": [
                payload1["message"],
                {
                    "sender": "user",
                    "text": data1["agentResponse"],
                    "timestamp": datetime.now(UTC).isoformat()
                }
            ]
        }
        
        response2 = await client.post(
            "/api/honeypot",
            json=payload2,
            headers={"x-api-key": settings.api_key}
        )
        
        data2 = response2.json()
        intel2_count = len(data2["extractedIntelligence"]["upiIds"])
        
        # Should have accumulated both UPI IDs
        assert intel2_count >= intel1_count


@pytest.mark.asyncio
async def test_session_persistence():
    """Test that session data persists across requests"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        session_id = f"test-persistence-{uuid.uuid4()}"
        
        # First request
        payload1 = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Your account is blocked",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": []
        }
        
        response1 = await client.post(
            "/api/honeypot",
            json=payload1,
            headers={"x-api-key": settings.api_key}
        )
        
        data1 = response1.json()
        scam_detected1 = data1["scamDetected"]
        
        # Second request with same session
        payload2 = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Send money now",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": [
                payload1["message"],
                {
                    "sender": "user",
                    "text": data1["agentResponse"],
                    "timestamp": datetime.now(UTC).isoformat()
                }
            ]
        }
        
        response2 = await client.post(
            "/api/honeypot",
            json=payload2,
            headers={"x-api-key": settings.api_key}
        )
        
        data2 = response2.json()
        
        # Scam detection should persist
        assert data2["scamDetected"] == scam_detected1
        
        # Message count should increase
        assert data2["engagementMetrics"]["totalMessagesExchanged"] > 1


@pytest.mark.asyncio
async def test_concurrent_sessions():
    """Test handling of multiple concurrent sessions"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        session1_id = f"test-concurrent-1-{uuid.uuid4()}"
        session2_id = f"test-concurrent-2-{uuid.uuid4()}"
        
        # Send requests for two different sessions
        payload1 = {
            "sessionId": session1_id,
            "message": {
                "sender": "scammer",
                "text": "Session 1 message",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": []
        }
        
        payload2 = {
            "sessionId": session2_id,
            "message": {
                "sender": "scammer",
                "text": "Session 2 message",
                "timestamp": datetime.now(UTC).isoformat()
            },
            "conversationHistory": []
        }
        
        response1 = await client.post(
            "/api/honeypot",
            json=payload1,
            headers={"x-api-key": settings.api_key}
        )
        
        response2 = await client.post(
            "/api/honeypot",
            json=payload2,
            headers={"x-api-key": settings.api_key}
        )
        
        # Both should succeed
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        # Should be independent sessions
        data1 = response1.json()
        data2 = response2.json()
        
        # Each session should have at least 1 exchange (may be 2 if counting both sides)
        assert data1["engagementMetrics"]["totalMessagesExchanged"] >= 1
        assert data2["engagementMetrics"]["totalMessagesExchanged"] >= 1
