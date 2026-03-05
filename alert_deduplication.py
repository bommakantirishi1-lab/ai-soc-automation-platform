import pickle
import hashlib
from datetime import datetime, timedelta
import os
import json

class AlertDeduplicator:
    """RAG-based alert deduplication - learns from past alerts"""
    
    def __init__(self, model_path="./models/alert_dedup_model.pkl"):
        self.model_path = model_path
        self.knowledge_base = {}  # RAG knowledge base
        self.ip_patterns = {}     # IP patterns learned
        self._load_knowledge()
    
    def _load_knowledge(self):
        """Load learned patterns from previous alerts"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.knowledge_base = data.get('knowledge_base', {})
                    self.ip_patterns = data.get('ip_patterns', {})
            except:
                pass
    
    def should_trigger_alert(self, new_alert, historical_alerts):
        """Check if alert should trigger based on learned patterns"""
        ip = new_alert['ip']
        severity = new_alert.get('severity', 'Low')
        events = new_alert.get('events', [])
        
        # Check 1: Is this IP already learned?
        if ip in self.ip_patterns:
            pattern = self.ip_patterns[ip]
            
            # Same severity + events = skip (duplicate)
            if (pattern['severity'] == severity and 
                set(pattern['events']) == set(events)):
                return False, f"Duplicate: {ip} with {severity} (seen {pattern['count']} times)"
            
            # Same IP, different severity within 24h = suppress
            if pattern['severity'] == severity:
                time_gap = datetime.now() - pattern['last_seen']
                if time_gap < timedelta(hours=24):
                    return False, f"Suppressed: Same IP/severity within 24h"
        
        # Check 2: Similar pattern detection
        similar_count = self._check_similar_pattern(ip, events)
        if similar_count >= 3:
            return False, f"Pattern suppressed: {similar_count} related IPs with same events"
        
        # Alert passes checks - should trigger
        self._learn_from_alert(new_alert)
        return True, "New unique threat pattern detected"
    
    def _check_similar_pattern(self, ip, events):
        """Check if similar event pattern from other IPs"""
        event_sig = tuple(sorted(events))
        similar = 0
        
        for known_ip, pattern in self.ip_patterns.items():
            if known_ip != ip:
                known_sig = tuple(sorted(pattern['events']))
                if event_sig == known_sig:
                    similar += 1
        
        return similar
    
    def _learn_from_alert(self, alert):
        """Learn from new alert and update knowledge base"""
        ip = alert['ip']
        
        self.ip_patterns[ip] = {
            'severity': alert.get('severity', 'Low'),
            'events': alert.get('events', []),
            'count': self.ip_patterns.get(ip, {}).get('count', 0) + 1,
            'first_seen': self.ip_patterns.get(ip, {}).get('first_seen', datetime.now()),
            'last_seen': datetime.now(),
            'score': alert.get('score', 0)
        }
        
        self._save_knowledge()
    
    def _save_knowledge(self):
        """Save learned patterns for future use"""
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'knowledge_base': self.knowledge_base,
                    'ip_patterns': self.ip_patterns
                }, f)
        except:
            pass
    
    def get_stats(self):
        """Get deduplication statistics"""
        return {
            'known_ips': len(self.ip_patterns),
            'patterns_learned': len(self.knowledge_base)
        }

alert_dedup = AlertDeduplicator()
