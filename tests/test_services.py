import pytest
from app.services.scam_detector import ScamDetector
from app.services.intel_extractor import IntelligenceExtractor
from app.services.agent import HoneypotAgent
from app.models.request import Message


@pytest.mark.asyncio
async def test_scam_detection_bank_fraud():
    """Test scam detection for bank fraud"""
    detector = ScamDetector()
    message = "Your account will be blocked. Send ₹500 to verify@upi"
    result = await detector.detect_scam(message, {})
    
    assert result.is_scam == True
    assert result.confidence > 0.5
    assert result.scam_type in ["bank_fraud", "upi_scam", "payment_scam"]


@pytest.mark.asyncio
async def test_scam_detection_upi_scam():
    """Test scam detection for UPI scam"""
    detector = ScamDetector()
    message = "Congratulations! You won ₹50,000. Pay ₹500 to winner@paytm to claim"
    result = await detector.detect_scam(message, {})
    
    assert result.is_scam == True
    assert result.confidence > 0.5


@pytest.mark.asyncio
async def test_scam_detection_legitimate():
    """Test that legitimate messages are not flagged"""
    detector = ScamDetector()
    message = "Hello, how are you today?"
    result = await detector.detect_scam(message, {})
    
    # Should have low confidence or not be scam
    assert result.confidence < 0.7 or result.is_scam == False


@pytest.mark.asyncio
async def test_intelligence_extraction_upi():
    """Test UPI ID extraction"""
    extractor = IntelligenceExtractor()
    message = "Send money to scammer@paytm or scammer@phonepe"
    intel = await extractor.extract(message)
    
    assert len(intel.upiIds) >= 1
    assert any("paytm" in upi.lower() or "phonepe" in upi.lower() for upi in intel.upiIds)


@pytest.mark.asyncio
async def test_intelligence_extraction_phone():
    """Test phone number extraction"""
    extractor = IntelligenceExtractor()
    message = "Call me at +919876543210 or 9123456789"
    intel = await extractor.extract(message)
    
    assert len(intel.phoneNumbers) >= 1


@pytest.mark.asyncio
async def test_intelligence_extraction_url():
    """Test URL extraction"""
    extractor = IntelligenceExtractor()
    message = "Click here: http://fake-bank.com or bit.ly/scam123"
    intel = await extractor.extract(message)
    
    assert len(intel.phishingLinks) >= 1


@pytest.mark.asyncio
async def test_intelligence_extraction_keywords():
    """Test keyword extraction"""
    extractor = IntelligenceExtractor()
    message = "URGENT: Your account is blocked. Verify immediately with OTP"
    intel = await extractor.extract(message)
    
    assert len(intel.suspiciousKeywords) >= 2
    assert any(kw in ["urgent", "blocked", "verify", "otp"] for kw in intel.suspiciousKeywords)


@pytest.mark.asyncio
async def test_agent_response_generation():
    """Test agent response generation"""
    agent = HoneypotAgent()
    
    message = "Your account will be blocked"
    history = []
    scam_type = "bank_fraud"
    
    response = await agent.generate_response(
        "test-session",
        message,
        history,
        scam_type
    )
    
    assert len(response) > 0
    assert len(response) < 500  # Should be brief
    # Should not reveal scam detection
    assert "scam" not in response.lower()


@pytest.mark.asyncio
async def test_agent_message_analysis():
    """Test scammer message analysis"""
    agent = HoneypotAgent()
    
    message = "URGENT! Send money NOW or account will be blocked!"
    analysis = await agent.analyze_scammer_message(message)
    
    assert analysis["urgency_level"] == "high"
    assert analysis["threat_detected"] == True
    assert analysis["request_type"] == "payment"


@pytest.mark.asyncio
async def test_agent_multi_turn_context():
    """Test agent maintains context across turns"""
    agent = HoneypotAgent()
    
    history = [
        Message(sender="scammer", text="Your account is blocked", timestamp="2026-01-26T10:00:00Z"),
        Message(sender="user", text="Why is it blocked?", timestamp="2026-01-26T10:01:00Z"),
        Message(sender="scammer", text="Send ₹500 to verify", timestamp="2026-01-26T10:02:00Z")
    ]
    
    response = await agent.generate_response(
        "test-session",
        "Send money now!",
        history,
        "bank_fraud"
    )
    
    assert len(response) > 0
    # Response should be contextual (not just generic)
    assert len(response) < 500


def test_regex_patterns():
    """Test regex pattern matching"""
    extractor = IntelligenceExtractor()
    
    # Test UPI pattern
    message = "Pay to test@paytm"
    intel = extractor._extract_with_regex(message)
    assert len(intel.upiIds) >= 1
    
    # Test phone pattern
    message = "Call +919876543210"
    intel = extractor._extract_with_regex(message)
    assert len(intel.phoneNumbers) >= 1
    
    # Test URL pattern
    message = "Visit http://example.com"
    intel = extractor._extract_with_regex(message)
    assert len(intel.phishingLinks) >= 1
