"""Global state management for CT Watcher."""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Set, Any, Optional


@dataclass
class WatcherState:
    """Holds all mutable state for the watcher."""
    
    # Deduplication sets
    seen_domains: Set[str] = field(default_factory=set)
    alerted_domains: Set[str] = field(default_factory=set)
    alerted_certificates: Set[int] = field(default_factory=set)
    
    # Known data (loaded from files)
    known_attacker_domains: Set[str] = field(default_factory=set)
    known_attacker_ips: Set[str] = field(default_factory=set)
    target_mapping: Dict[str, Dict[str, str]] = field(default_factory=dict)
    email_template: str = ""
    attacker_ips_data: Dict[str, Any] = field(default_factory=lambda: {"ips": {}, "last_updated": None})
    
    # Stats
    cert_count: int = 0
    last_stats_time: float = field(default_factory=time.time)
    total_alerts_count: int = 0
    
    # Reconnection
    reconnect_delay: int = 1

    # Locks
    lock: threading.Lock = field(default_factory=threading.Lock)
    ip_save_lock: threading.Lock = field(default_factory=threading.Lock)

    def clear_seen_domains(self):
        """Clear seen domains set."""
        self.seen_domains.clear()
    
    def clear_alerted_domains(self):
        """Clear alerted domains set."""
        self.alerted_domains.clear()
    
    def clear_alerted_certificates(self):
        """Clear alerted certificates set."""
        self.alerted_certificates.clear()
    
    def reset_stats(self):
        """Reset stats for new interval."""
        self.cert_count = 0
        self.last_stats_time = time.time()


# Global state instance
state = WatcherState()
