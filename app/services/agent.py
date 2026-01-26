from groq import Groq
from app.config import settings
from app.utils.groq_manager import groq_manager
from app.models.request import Message
from app.prompts.system_prompts import (
    AGENT_SYSTEM_PROMPT,
    LANGUAGE_PROMPTS,
    SCAM_TYPE_STRATEGIES,
    RESPONSE_TEMPLATES,
    NON_SCAM_RESPONSE
)
from typing import List, Optional
import random
import logging

logger = logging.getLogger(__name__)


class HoneypotAgent:
    def __init__(self):
        self.groq_manager = groq_manager
        logger.info(f"Agent initialized with {self.groq_manager.get_active_keys()} Groq API keys")
    
    def _build_conversation_context(self, history: List[Message]) -> str:
        """Convert conversation history to readable format for LLM"""
        if not history:
            return "This is the first message in the conversation."
        
        context = "Previous conversation:\n"
        for msg in history:
            role = "Scammer" if msg.sender == "scammer" else "You"
            context += f"{role}: {msg.text}\n"
        
        return context
    
    def _get_strategy_for_turn(self, turn_number: int, scam_type: str) -> str:
        """Get response strategy based on conversation turn"""
        strategy = ""
        
        if turn_number <= 2:
            strategy = "Show confusion and concern. Ask 'why' questions. Be worried."
        elif turn_number <= 5:
            strategy = "Show concern and ask for more details. Request clarification."
        elif turn_number <= 10:
            strategy = "Show interest but ask for official information or proof. Be cautious."
        else:
            strategy = "Show willingness to cooperate. Ask for step-by-step instructions."
        
        # Add scam-type specific guidance
        if scam_type in SCAM_TYPE_STRATEGIES:
            strategy += f"\n\nScam type: {scam_type}"
            strategy += f"\nPersona: {SCAM_TYPE_STRATEGIES[scam_type]['persona']}"
        
        return strategy
    
    def _add_human_imperfections(self, text: str) -> str:
        """Add occasional typos or grammar mistakes to make response more human"""
        # 30% chance to add imperfection
        if random.random() > 0.7:
            return text
        
        # Simple imperfections
        imperfections = [
            lambda t: t.replace("?", "??"),  # Double question mark
            lambda t: t.replace(".", ".."),  # Double period
            lambda t: t.lower() if t[0].isupper() else t,  # Lowercase start
            lambda t: t.replace("you", "u") if random.random() > 0.5 else t,  # Text speak
            lambda t: t.replace("okay", "ok") if "okay" in t.lower() else t,
        ]
        
        imperfection = random.choice(imperfections)
        return imperfection(text)
    
    async def generate_response(
        self,
        session_id: str,
        current_message: str,
        conversation_history: List[Message],
        scam_type: str,
        language: Optional[str] = "English"
    ) -> str:
        """
        Generate human-like response to scammer
        
        Args:
            session_id: Session identifier
            current_message: Latest message from scammer
            conversation_history: Previous messages
            scam_type: Type of scam detected
            language: Language for response (English, Hindi, Tamil, Telugu, Malayalam)
        
        Returns:
            Agent's response text
        """
        try:
            # Get Groq client
            client = self.groq_manager.get_client()
            
            if not client:
                return self._fallback_response(scam_type, len(conversation_history))
            
            # Build conversation context
            context = self._build_conversation_context(conversation_history)
            
            # Determine turn number (count user messages)
            turn_number = sum(1 for msg in conversation_history if msg.sender == "user") + 1
            
            # Get strategy for this turn
            strategy = self._get_strategy_for_turn(turn_number, scam_type)
            
            # Get language-specific system prompt
            system_prompt = LANGUAGE_PROMPTS.get(language, AGENT_SYSTEM_PROMPT)
            
            # Add language instruction if not English
            language_instruction = ""
            if language != "English":
                language_instruction = f"\n\nIMPORTANT: Respond in {language} language. Match the language style of the scammer's message."
            
            # Build prompt
            prompt = f"""{context}

Current message from scammer: "{current_message}"

{strategy}{language_instruction}

Generate a natural, human-like response (1-3 sentences only). Remember:
- Stay in character as a concerned individual
- Don't reveal you know it's a scam
- Ask questions that make them reveal more information
- Show appropriate emotions
- Keep it brief and natural
"""
            
            # Call Groq API
            response = client.chat.completions.create(
                model=settings.groq_model,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.8,  # Higher temperature for more natural variation
                max_tokens=150
            )
            
            # Get response text
            agent_response = response.choices[0].message.content.strip()
            
            # Add human imperfections occasionally
            agent_response = self._add_human_imperfections(agent_response)
            
            logger.info(f"Session {session_id}: Generated response in {language} (turn {turn_number})")
            
            return agent_response
        
        except Exception as e:
            logger.error(f"Error generating response for session {session_id}: {e}")
            return self._fallback_response(scam_type, len(conversation_history))
    
    def _fallback_response(self, scam_type: str, turn_number: int) -> str:
        """Generate fallback response if Groq API fails"""
        # Use predefined responses based on scam type
        if scam_type in SCAM_TYPE_STRATEGIES:
            strategy = SCAM_TYPE_STRATEGIES[scam_type]
            
            if turn_number == 0:
                # First response
                return random.choice(strategy["initial_response"])
            else:
                # Follow-up question
                return random.choice(strategy["follow_up_questions"])
        
        # Generic fallback
        generic_responses = [
            "Can you tell me more about this?",
            "I'm not sure I understand. Can you explain?",
            "What do I need to do exactly?",
            "Is this really necessary?",
            "How do I know this is legitimate?"
        ]
        
        return random.choice(generic_responses)

    
    async def analyze_scammer_message(self, message: str) -> dict:
        """
        Analyze scammer's message for behavioral patterns
        
        Args:
            message: The scammer's message text
        
        Returns:
            Dictionary with analysis results
        """
        try:
            analysis = {
                "urgency_level": "low",
                "threat_detected": False,
                "request_type": None,
                "emotional_manipulation": False
            }
            
            message_lower = message.lower()
            
            # Check urgency
            urgency_keywords = ["urgent", "immediately", "now", "today", "asap", "hurry", "quick"]
            if any(keyword in message_lower for keyword in urgency_keywords):
                analysis["urgency_level"] = "high"
            
            # Check threats
            threat_keywords = ["blocked", "suspended", "closed", "terminated", "legal action", "police"]
            if any(keyword in message_lower for keyword in threat_keywords):
                analysis["threat_detected"] = True
            
            # Identify request type
            if any(x in message_lower for x in ["send", "pay", "transfer", "₹", "rs"]):
                analysis["request_type"] = "payment"
            elif any(x in message_lower for x in ["otp", "code", "pin", "password"]):
                analysis["request_type"] = "credentials"
            elif any(x in message_lower for x in ["click", "link", "visit", "website"]):
                analysis["request_type"] = "link"
            elif any(x in message_lower for x in ["verify", "confirm", "update", "details"]):
                analysis["request_type"] = "information"
            
            # Check emotional manipulation
            emotion_keywords = ["congratulations", "winner", "lucky", "selected", "prize", "free"]
            if any(keyword in message_lower for keyword in emotion_keywords):
                analysis["emotional_manipulation"] = True
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error analyzing scammer message: {e}")
            return {
                "urgency_level": "unknown",
                "threat_detected": False,
                "request_type": None,
                "emotional_manipulation": False
            }
    
    def generate_agent_note(
        self,
        scam_type: str,
        message_analysis: dict,
        turn_number: int
    ) -> str:
        """
        Generate agent note summarizing scammer behavior
        
        Args:
            scam_type: Type of scam
            message_analysis: Analysis of scammer's message
            turn_number: Current conversation turn
        
        Returns:
            Agent note string
        """
        notes = []
        
        # Scam type
        notes.append(f"Scam type: {scam_type}")
        
        # Urgency
        if message_analysis.get("urgency_level") == "high":
            notes.append("using urgency tactics")
        
        # Threats
        if message_analysis.get("threat_detected"):
            notes.append("making threats")
        
        # Request type
        request_type = message_analysis.get("request_type")
        if request_type:
            notes.append(f"requesting {request_type}")
        
        # Emotional manipulation
        if message_analysis.get("emotional_manipulation"):
            notes.append("using emotional manipulation")
        
        # Turn info
        notes.append(f"turn {turn_number}")
        
        return ", ".join(notes)
