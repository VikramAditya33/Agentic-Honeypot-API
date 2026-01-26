from groq import Groq
from app.config import settings
from app.utils.groq_manager import groq_manager
from typing import Dict, Any, Optional
from pydantic import BaseModel
from app.utils.cache import scam_detection_cache, generate_message_hash
import json
import logging

logger = logging.getLogger(__name__)


class ScamDetectionResult(BaseModel):
    is_scam: bool
    confidence: float
    scam_type: str
    reasoning: str


class ScamDetector:
    def __init__(self):
        self.groq_manager = groq_manager
        logger.info(f"Scam detector initialized with {self.groq_manager.get_active_keys()} Groq API keys")
    
    def _build_detection_prompt(self, message: str, metadata: Optional[Dict] = None) -> str:
        """Build prompt for scam detection"""
        prompt = f"""Analyze the following message and determine if it's a scam or fraudulent attempt.

Message: "{message}"
"""
        
        if metadata:
            prompt += f"\nChannel: {metadata.get('channel', 'Unknown')}"
            prompt += f"\nLanguage: {metadata.get('language', 'Unknown')}"
            prompt += f"\nLocale: {metadata.get('locale', 'Unknown')}"
        
        prompt += """

Common scam patterns to detect:
1. Bank account verification/blocking threats
2. UPI payment requests or verification
3. Urgency tactics ("account will be blocked", "immediate action required")
4. Phishing links (shortened URLs, suspicious domains)
5. Prize/lottery scams ("you won", "claim prize")
6. OTP/PIN requests
7. Impersonation (bank, government, delivery services)
8. Payment redirection or fake refunds
9. Fake customer support
10. Investment/crypto scams

Scam indicators:
- Keywords: verify, blocked, suspended, urgent, OTP, prize, winner, claim, payment, transfer, account, KYC
- Requests for: money, UPI ID, bank details, OTP, personal information, passwords
- Suspicious links (bit.ly, tinyurl, or unknown domains)
- Impersonation language (claiming to be from official organizations)
- Threats or time pressure
- Too-good-to-be-true offers

Respond in JSON format with:
{
    "is_scam": true/false,
    "confidence": 0.0-1.0,
    "scam_type": "bank_fraud" | "upi_scam" | "phishing" | "prize_scam" | "otp_scam" | "impersonation" | "payment_scam" | "investment_scam" | "not_scam",
    "reasoning": "brief explanation of why this is/isn't a scam"
}
"""
        return prompt
    
    async def detect_scam(
        self,
        message: str,
        metadata: Optional[Dict] = None
    ) -> ScamDetectionResult:
        """
        Detect if a message is a scam
        
        Args:
            message: The message text to analyze
            metadata: Optional metadata (channel, language, locale)
        
        Returns:
            ScamDetectionResult with detection details
        """
        try:
            # Check cache first
            cache_key = generate_message_hash(message)
            cached_result = scam_detection_cache.get(cache_key)
            
            if cached_result:
                logger.info("Using cached scam detection result")
                return ScamDetectionResult(**cached_result)
            
            # Get Groq client
            client = self.groq_manager.get_client()
            
            if not client:
                # Fallback: keyword-based detection
                result = self._fallback_detection(message)
                scam_detection_cache.set(cache_key, result.model_dump())
                return result
            
            # Build prompt
            prompt = self._build_detection_prompt(message, metadata)
            
            # Call Groq API with JSON mode
            response = client.chat.completions.create(
                model=settings.groq_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert at detecting scams and fraudulent messages. Analyze messages carefully and respond in JSON format."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.3,
                max_tokens=500
            )
            
            # Parse response
            result_text = response.choices[0].message.content
            result_data = json.loads(result_text)
            
            logger.info(f"Scam detection result: {result_data}")
            
            result = ScamDetectionResult(**result_data)
            
            # Cache the result
            scam_detection_cache.set(cache_key, result.model_dump())
            
            return result
        
        except Exception as e:
            logger.error(f"Error in scam detection: {e}")
            # Fallback to keyword-based detection
            result = self._fallback_detection(message)
            return result
    
    def _fallback_detection(self, message: str) -> ScamDetectionResult:
        """Fallback keyword-based scam detection"""
        message_lower = message.lower()
        
        # Scam keywords
        scam_keywords = [
            "verify", "blocked", "suspended", "urgent", "otp", "prize", "winner",
            "claim", "payment", "transfer", "account", "kyc", "upi", "bank",
            "refund", "cashback", "won", "lottery", "congratulations"
        ]
        
        # Count keyword matches
        matches = sum(1 for keyword in scam_keywords if keyword in message_lower)
        
        # Check for URLs
        has_url = any(x in message_lower for x in ["http://", "https://", "bit.ly", "tinyurl"])
        
        # Check for money requests
        has_money_request = any(x in message_lower for x in ["₹", "rs", "rupees", "send money", "pay"])
        
        # Calculate confidence
        confidence = min(0.9, (matches * 0.15) + (0.2 if has_url else 0) + (0.3 if has_money_request else 0))
        
        is_scam = confidence > 0.5
        
        # Determine scam type
        scam_type = "not_scam"
        if is_scam:
            if "upi" in message_lower or has_money_request:
                scam_type = "upi_scam"
            elif "bank" in message_lower or "account" in message_lower:
                scam_type = "bank_fraud"
            elif has_url:
                scam_type = "phishing"
            elif "prize" in message_lower or "won" in message_lower:
                scam_type = "prize_scam"
            elif "otp" in message_lower:
                scam_type = "otp_scam"
            else:
                scam_type = "payment_scam"
        
        reasoning = f"Keyword-based detection: {matches} scam indicators found"
        if has_url:
            reasoning += ", suspicious URL detected"
        if has_money_request:
            reasoning += ", money request detected"
        
        return ScamDetectionResult(
            is_scam=is_scam,
            confidence=confidence,
            scam_type=scam_type,
            reasoning=reasoning
        )
