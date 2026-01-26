from groq import Groq
from app.config import settings
from app.utils.groq_manager import groq_manager
from app.models.response import ExtractedIntelligence
from app.models.intelligence import IntelligenceItem, EnhancedIntelligence
from app.utils.cache import intelligence_cache, generate_message_hash
from datetime import datetime, UTC
import re
import json
import logging

logger = logging.getLogger(__name__)


# Regex patterns for extraction
PATTERNS = {
    "upi_id": r'\b[\w\.-]+@[\w\.-]+\b',
    "bank_account": r'\b\d{9,18}\b',
    "phone": r'\+?\d{10,13}\b',
    "url": r'https?://[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+',
    "ifsc": r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
}

# Scam keywords
SCAM_KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "immediately",
    "otp", "prize", "winner", "claim", "congratulations",
    "account", "payment", "transfer", "bank", "upi",
    "kyc", "update", "confirm", "refund", "cashback",
    "lottery", "selected", "won", "free", "offer"
]


class IntelligenceExtractor:
    def __init__(self):
        self.groq_manager = groq_manager
        logger.info(f"Intelligence extractor initialized with {self.groq_manager.get_active_keys()} Groq API keys")
    
    def _extract_with_regex(self, message: str) -> ExtractedIntelligence:
        """Layer 1: Extract intelligence using regex patterns"""
        intel = ExtractedIntelligence()
        
        try:
            # Extract UPI IDs
            upi_matches = re.findall(PATTERNS["upi_id"], message)
            # Filter to only valid UPI patterns (has @ and common providers)
            upi_providers = ["paytm", "phonepe", "googlepay", "ybl", "oksbi", "okaxis", "okicici"]
            intel.upiIds = [
                upi for upi in upi_matches 
                if any(provider in upi.lower() for provider in upi_providers)
            ]
            
            # Extract bank account numbers (9-18 digits)
            bank_accounts = re.findall(PATTERNS["bank_account"], message)
            # Filter out phone numbers (usually 10 digits)
            intel.bankAccounts = [acc for acc in bank_accounts if len(acc) > 10]
            
            # Extract phone numbers
            phone_matches = re.findall(PATTERNS["phone"], message)
            # Filter valid Indian phone numbers
            intel.phoneNumbers = [
                phone for phone in phone_matches 
                if len(phone.replace("+", "").replace("-", "")) >= 10
            ]
            
            # Extract URLs
            url_matches = re.findall(PATTERNS["url"], message, re.IGNORECASE)
            intel.phishingLinks = list(set(url_matches))
            
            # Extract IFSC codes (for bank accounts)
            ifsc_matches = re.findall(PATTERNS["ifsc"], message)
            if ifsc_matches:
                # Add IFSC to bank accounts list with context
                for ifsc in ifsc_matches:
                    intel.bankAccounts.append(f"IFSC:{ifsc}")
            
            # Extract keywords
            message_lower = message.lower()
            found_keywords = [
                keyword for keyword in SCAM_KEYWORDS 
                if keyword in message_lower
            ]
            intel.suspiciousKeywords = list(set(found_keywords))
            
            logger.info(f"Regex extraction: {len(intel.upiIds)} UPIs, {len(intel.bankAccounts)} accounts, {len(intel.phoneNumbers)} phones")
            
        except Exception as e:
            logger.error(f"Error in regex extraction: {e}")
        
        return intel
    
    async def _extract_with_llm(self, message: str) -> ExtractedIntelligence:
        """Layer 2: Extract intelligence using LLM"""
        try:
            # Get Groq client
            client = self.groq_manager.get_client()
            
            if not client:
                return ExtractedIntelligence()
            
            prompt = f"""Analyze the following message and extract any scam-related intelligence.

Message: "{message}"

Extract and return in JSON format:
{{
    "bankAccounts": ["list of bank account numbers found"],
    "upiIds": ["list of UPI IDs found (format: name@provider)"],
    "phishingLinks": ["list of URLs or links found"],
    "phoneNumbers": ["list of phone numbers found"],
    "suspiciousKeywords": ["list of scam-related keywords found"]
}}

Rules:
- Only include actual data found in the message
- UPI IDs must have @ symbol
- Phone numbers should be 10+ digits
- Include all URLs, even shortened ones
- Keywords should be scam-related terms
- Return empty arrays if nothing found
"""
            
            response = client.chat.completions.create(
                model=settings.groq_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert at extracting structured information from scam messages. Return only valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content
            result_data = json.loads(result_text)
            
            intel = ExtractedIntelligence(**result_data)
            
            logger.info(f"LLM extraction: {len(intel.upiIds)} UPIs, {len(intel.bankAccounts)} accounts")
            
            return intel
        
        except Exception as e:
            logger.error(f"Error in LLM extraction: {e}")
            return ExtractedIntelligence()
    
    def _merge_intelligence(
        self,
        regex_intel: ExtractedIntelligence,
        llm_intel: ExtractedIntelligence
    ) -> ExtractedIntelligence:
        """Merge and deduplicate intelligence from multiple sources"""
        merged = ExtractedIntelligence(
            bankAccounts=list(set(regex_intel.bankAccounts + llm_intel.bankAccounts)),
            upiIds=list(set(regex_intel.upiIds + llm_intel.upiIds)),
            phishingLinks=list(set(regex_intel.phishingLinks + llm_intel.phishingLinks)),
            phoneNumbers=list(set(regex_intel.phoneNumbers + llm_intel.phoneNumbers)),
            suspiciousKeywords=list(set(regex_intel.suspiciousKeywords + llm_intel.suspiciousKeywords))
        )
        
        return merged
    
    def _create_enhanced_intelligence(
        self,
        regex_intel: ExtractedIntelligence,
        llm_intel: ExtractedIntelligence,
        turn_number: int = 0
    ) -> EnhancedIntelligence:
        """Create enhanced intelligence with confidence scores"""
        enhanced = EnhancedIntelligence()
        timestamp = datetime.now(UTC).isoformat()
        
        # Process each type of intelligence
        for field in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
            regex_items = getattr(regex_intel, field)
            llm_items = getattr(llm_intel, field)
            enhanced_items = []
            
            # Items found by both (highest confidence)
            both_items = set(regex_items) & set(llm_items)
            for item in both_items:
                enhanced_items.append(IntelligenceItem(
                    value=item,
                    confidence=0.95,
                    source="both",
                    extracted_at=timestamp,
                    message_turn=turn_number
                ))
            
            # Items found only by regex (medium confidence)
            regex_only = set(regex_items) - set(llm_items)
            for item in regex_only:
                enhanced_items.append(IntelligenceItem(
                    value=item,
                    confidence=0.75,
                    source="regex",
                    extracted_at=timestamp,
                    message_turn=turn_number
                ))
            
            # Items found only by LLM (medium-high confidence)
            llm_only = set(llm_items) - set(regex_items)
            for item in llm_only:
                enhanced_items.append(IntelligenceItem(
                    value=item,
                    confidence=0.85,
                    source="llm",
                    extracted_at=timestamp,
                    message_turn=turn_number
                ))
            
            setattr(enhanced, field, enhanced_items)
        
        return enhanced
    
    async def extract(self, message: str) -> ExtractedIntelligence:
        """
        Extract intelligence from message using multi-layered approach
        
        Args:
            message: The message text to analyze
        
        Returns:
            ExtractedIntelligence with all found data
        """
        try:
            # Check cache first
            cache_key = generate_message_hash(message)
            cached_result = intelligence_cache.get(cache_key)
            
            if cached_result:
                logger.info("Using cached intelligence extraction result")
                return ExtractedIntelligence(**cached_result)
            
            # Layer 1: Regex extraction
            regex_intel = self._extract_with_regex(message)
            
            # Layer 2: LLM extraction
            llm_intel = await self._extract_with_llm(message)
            
            # Merge results
            final_intel = self._merge_intelligence(regex_intel, llm_intel)
            
            logger.info(f"Final extraction: {len(final_intel.upiIds)} UPIs, "
                       f"{len(final_intel.bankAccounts)} accounts, "
                       f"{len(final_intel.phoneNumbers)} phones, "
                       f"{len(final_intel.phishingLinks)} links, "
                       f"{len(final_intel.suspiciousKeywords)} keywords")
            
            # Cache the result
            intelligence_cache.set(cache_key, final_intel.model_dump())
            
            return final_intel
        
        except Exception as e:
            logger.error(f"Error in intelligence extraction: {e}")
            # Return regex results as fallback
            return self._extract_with_regex(message)
