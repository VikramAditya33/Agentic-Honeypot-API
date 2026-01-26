"""
Metrics tracking for monitoring and analytics
"""
from typing import Dict, List
from datetime import datetime, UTC
import logging

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Simple in-memory metrics collector"""
    
    def __init__(self):
        self.response_times: List[float] = []
        self.scam_detections: Dict[str, int] = {
            "total": 0,
            "scam": 0,
            "not_scam": 0
        }
        self.intelligence_extracted: Dict[str, int] = {
            "upiIds": 0,
            "bankAccounts": 0,
            "phoneNumbers": 0,
            "phishingLinks": 0,
            "keywords": 0
        }
        self.api_errors: Dict[str, int] = {
            "total": 0,
            "groq_errors": 0,
            "redis_errors": 0,
            "other_errors": 0
        }
        self.session_durations: List[int] = []
        self.cache_stats: Dict[str, int] = {
            "hits": 0,
            "misses": 0
        }
        self.requests_total: int = 0
        self.start_time: datetime = datetime.now(UTC)
    
    def record_response_time(self, duration: float):
        """Record API response time"""
        self.response_times.append(duration)
        # Keep only last 1000 entries
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-1000:]
    
    def record_scam_detection(self, is_scam: bool):
        """Record scam detection result"""
        self.scam_detections["total"] += 1
        if is_scam:
            self.scam_detections["scam"] += 1
        else:
            self.scam_detections["not_scam"] += 1
    
    def record_intelligence(self, intel_type: str, count: int):
        """Record intelligence extraction"""
        if intel_type in self.intelligence_extracted:
            self.intelligence_extracted[intel_type] += count
    
    def record_error(self, error_type: str = "other"):
        """Record API error"""
        self.api_errors["total"] += 1
        error_key = f"{error_type}_errors"
        if error_key in self.api_errors:
            self.api_errors[error_key] += 1
        else:
            self.api_errors["other_errors"] += 1
    
    def record_session_duration(self, duration: int):
        """Record session duration in seconds"""
        self.session_durations.append(duration)
        # Keep only last 1000 entries
        if len(self.session_durations) > 1000:
            self.session_durations = self.session_durations[-1000:]
    
    def record_cache_hit(self):
        """Record cache hit"""
        self.cache_stats["hits"] += 1
    
    def record_cache_miss(self):
        """Record cache miss"""
        self.cache_stats["misses"] += 1
    
    def record_request(self):
        """Record incoming request"""
        self.requests_total += 1
    
    def get_summary(self) -> Dict:
        """Get metrics summary"""
        uptime = (datetime.now(UTC) - self.start_time).total_seconds()
        avg_response_time = (
            sum(self.response_times) / len(self.response_times)
            if self.response_times else 0
        )
        
        avg_session_duration = (
            sum(self.session_durations) / len(self.session_durations)
            if self.session_durations else 0
        )
        scam_detection_rate = (
            self.scam_detections["scam"] / self.scam_detections["total"]
            if self.scam_detections["total"] > 0 else 0
        )
        
        error_rate = (
            self.api_errors["total"] / self.requests_total
            if self.requests_total > 0 else 0
        )
        
        cache_hit_rate = (
            self.cache_stats["hits"] / (self.cache_stats["hits"] + self.cache_stats["misses"])
            if (self.cache_stats["hits"] + self.cache_stats["misses"]) > 0 else 0
        )
        
        return {
            "uptime_seconds": uptime,
            "requests_total": self.requests_total,
            "requests_per_second": self.requests_total / uptime if uptime > 0 else 0,
            "response_time": {
                "average_ms": avg_response_time * 1000,
                "samples": len(self.response_times)
            },
            "scam_detection": {
                "total": self.scam_detections["total"],
                "scam_count": self.scam_detections["scam"],
                "not_scam_count": self.scam_detections["not_scam"],
                "scam_rate": scam_detection_rate
            },
            "intelligence_extracted": self.intelligence_extracted,
            "errors": {
                "total": self.api_errors["total"],
                "error_rate": error_rate,
                "by_type": {
                    "groq": self.api_errors["groq_errors"],
                    "redis": self.api_errors["redis_errors"],
                    "other": self.api_errors["other_errors"]
                }
            },
            "sessions": {
                "average_duration_seconds": avg_session_duration,
                "samples": len(self.session_durations)
            },
            "cache": {
                "hits": self.cache_stats["hits"],
                "misses": self.cache_stats["misses"],
                "hit_rate": cache_hit_rate
            }
        }
    
    def log_summary(self):
        """Log metrics summary"""
        summary = self.get_summary()
        logger.info("=== Metrics Summary ===")
        logger.info(f"Uptime: {summary['uptime_seconds']:.0f}s")
        logger.info(f"Total Requests: {summary['requests_total']}")
        logger.info(f"Avg Response Time: {summary['response_time']['average_ms']:.2f}ms")
        logger.info(f"Scam Detection Rate: {summary['scam_detection']['scam_rate']:.2%}")
        logger.info(f"Error Rate: {summary['errors']['error_rate']:.2%}")
        logger.info(f"Cache Hit Rate: {summary['cache']['hit_rate']:.2%}")
        logger.info("=====================")


# Global metrics collector
metrics = MetricsCollector()
