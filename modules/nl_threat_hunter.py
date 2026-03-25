"""Integrated Natural Language Threat Hunter Module
Combines NL query translation, SIEM query execution, and IOC enrichment.
Integrated with AI SOC Automation Platform.
"""

import json
import pandas as pd
import requests
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
import os
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ============================================
# QUERY TRANSLATOR - NL to KQL/EQL
# ============================================
class NLQueryTranslator:
    """Translates natural language threat hunting queries to KQL/EQL."""
    
    def __init__(self):
        self.few_shot_examples = {
            'kql': [
                {
                    'nl': 'find powershell executions',
                    'query': 'process_name == "powershell.exe"'
                },
                {
                    'nl': 'suspicious logins from russia',
                    'query': 'event_type == "login_failed" AND country == "Russia"'
                },
                {
                    'nl': 'network connections to c2 servers',
                    'query': 'destination_ip IN ("malicious_ips") AND protocol IN ("tcp", "udp")'
                }
            ],
            'eql': [
                {
                    'nl': 'process chain with cmd and powershell',
                    'query': 'process where (name == "cmd.exe" or name == "powershell.exe") and parent.name != "explorer.exe"'
                }
            ]
        }
    
    def translate_to_query(self, nl_query: str, target_lang: str = 'KQL') -> str:
        """Translate NL query to KQL/EQL. In production, use LLM like Ollama/GPT."""
        nl_query_lower = nl_query.lower()
        
        # Rule-based fallback until LLM integration
        if 'powershell' in nl_query_lower:
            return 'process_name == "powershell.exe"' if target_lang == 'KQL' else 'process where name == "powershell.exe"'
        elif 'cmd' in nl_query_lower:
            return 'process_name == "cmd.exe"' if target_lang == 'KQL' else 'process where name == "cmd.exe"'
        elif 'network' in nl_query_lower or 'connection' in nl_query_lower:
            return 'event_type == "network_connection"'
        elif 'login' in nl_query_lower or 'auth' in nl_query_lower:
            return 'event_type == "authentication"'
        else:
            return f'event_type contains "{nl_query[:20]}"'
    
    def validate_query(self, query: str) -> Tuple[bool, str]:
        """Validate query syntax."""
        if not query or len(query) < 3:
            return False, "Query too short"
        if '"' not in query and "'" not in query:
            logger.warning(f"Query may be invalid (no quotes): {query}")
        return True, "Valid"


# ============================================
# THREAT HUNT EXECUTOR
# ============================================
class ThreatHuntExecutor:
    """Executes translated queries on SIEM data."""
    
    def __init__(self, data_path: str = None):
        self.data_path = data_path or 'data/sample_logs.json'
        self.sample_data = self._generate_sample_data()
    
    def _generate_sample_data(self) -> pd.DataFrame:
        """Generate realistic sample security logs."""
        processes = ['powershell.exe', 'cmd.exe', 'svchost.exe', 'explorer.exe', 'rundll32.exe']
        ips = [f'192.168.1.{i}' for i in range(1, 256)] + [f'10.0.0.{i}' for i in range(1, 256)]
        event_types = ['suspicious_execution', 'network_connection', 'authentication', 'registry_mod']
        
        data = []
        base_time = datetime.now() - timedelta(days=1)
        for i in range(100):
            data.append({
                'timestamp': (base_time + timedelta(minutes=i*15)).isoformat() + 'Z',
                'ip': pd.Series(ips).sample(1).values[0],
                'process_name': pd.Series(processes).sample(1).values[0],
                'event_type': pd.Series(event_types).sample(1).values[0],
                'risk_score': pd.Series(range(30, 100)).sample(1).values[0]
            })
        return pd.DataFrame(data)
    
    def execute_hunt(self, query: str) -> pd.DataFrame:
        """Execute hunting query on sample data using pandas query."""
        try:
            # Parse simple query (in production, use proper SQL parser)
            if '==' in query and '"' in query:
                # Extract field and value
                parts = query.split('==')
                field = parts[0].strip()
                value = parts[1].strip().strip('"')
                
                if field in self.sample_data.columns:
                    results = self.sample_data[self.sample_data[field] == value]
                    return results if not results.empty else pd.DataFrame()
            return self.sample_data.head(10)  # Return sample if query unclear
        except Exception as e:
            logger.error(f"Query execution error: {str(e)}")
            return pd.DataFrame()
    
    def parse_query_results(self, results: pd.DataFrame) -> List[Dict]:
        """Parse and structure query results."""
        return results.to_dict('records') if not results.empty else []


# ============================================
# IOC ENRICHMENT
# ============================================
class IOCEnricher:
    """Enriches Indicators of Compromise with threat intelligence."""
    
    def __init__(self):
        self.abuseipdb_key = os.getenv('ABUSEIPDB_KEY', '')
        self.virustotal_key = os.getenv('VIRUSTOTAL_KEY', '')
        self.cache = {}
    
    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP address with threat intelligence."""
        if ip in self.cache:
            return self.cache[ip]
        
        enrichment = {
            'ip': ip,
            'abuseipdb_score': 0,
            'virustotal_detections': 0,
            'is_malicious': False,
            'last_seen': None
        }
        
        # Mock enrichment (replace with real API calls in production)
        suspicious_ips = ['185.220.101.12', '45.95.147.23', '103.21.244.15']
        if any(ip.startswith(prefix) for prefix in suspicious_ips):
            enrichment['abuseipdb_score'] = 75
            enrichment['is_malicious'] = True
        
        self.cache[ip] = enrichment
        return enrichment
    
    def enrich_hash(self, hash_value: str) -> Dict[str, Any]:
        """Enrich file hash with threat intelligence."""
        return {
            'hash': hash_value,
            'virustotal_detections': 0,
            'is_malware': False
        }
    
    def enrich_results(self, results: List[Dict]) -> List[Dict]:
        """Enrich all IOCs in results."""
        enriched = []
        for result in results:
            enriched_result = result.copy()
            if 'ip' in result:
                enriched_result['enrichment'] = self.enrich_ip(result['ip'])
            enriched.append(enriched_result)
        return enriched


# ============================================
# MITRE ATT&CK MAPPER
# ============================================
class MITREMapper:
    """Maps hunting results to MITRE ATT&CK framework."""
    
    def __init__(self):
        self.technique_map = {
            'powershell': ['T1059.001'],  # PowerShell
            'cmd': ['T1059.003'],          # Windows Command Shell
            'network': ['T1071'],          # Application Layer Protocol
            'registry': ['T1112'],         # Modify Registry
            'authentication': ['T1078'],   # Valid Accounts
            'lateral_movement': ['T1570'], # Lateral Tool Transfer
        }
    
    def map_to_mitre(self, query: str, results: List[Dict]) -> Dict[str, List[str]]:
        """Map query results to MITRE techniques."""
        techniques = set()
        query_lower = query.lower()
        
        for keyword, ttps in self.technique_map.items():
            if keyword in query_lower:
                techniques.update(ttps)
        
        return {'techniques': list(techniques), 'framework': 'MITRE ATT&CK v13'}


# ============================================
# INTEGRATED THREAT HUNTER
# ============================================
class IntegratedThreatHunter:
    """Main integrated threat hunting platform combining all components."""
    
    def __init__(self):
        self.translator = NLQueryTranslator()
        self.executor = ThreatHuntExecutor()
        self.enricher = IOCEnricher()
        self.mitre_mapper = MITREMapper()
        self.hunt_history = []
    
    def hunt(self, nl_query: str, target_lang: str = 'KQL') -> Dict[str, Any]:
        """Execute complete threat hunting workflow."""
        hunt_id = datetime.now().isoformat()
        
        try:
            # Step 1: Translate NL to query
            generated_query = self.translator.translate_to_query(nl_query, target_lang)
            is_valid, validation_msg = self.translator.validate_query(generated_query)
            
            if not is_valid:
                return {'error': validation_msg, 'hunt_id': hunt_id}
            
            # Step 2: Execute hunt
            results = self.executor.execute_hunt(generated_query)
            parsed_results = self.executor.parse_query_results(results)
            
            # Step 3: Enrich IOCs
            enriched_results = self.enricher.enrich_results(parsed_results)
            
            # Step 4: Map to MITRE ATT&CK
            mitre_mapping = self.mitre_mapper.map_to_mitre(nl_query, enriched_results)
            
            # Step 5: Compile response
            hunt_result = {
                'hunt_id': hunt_id,
                'timestamp': datetime.now().isoformat(),
                'nl_query': nl_query,
                'generated_query': generated_query,
                'query_language': target_lang,
                'result_count': len(enriched_results),
                'results': enriched_results,
                'mitre_mapping': mitre_mapping,
                'status': 'success'
            }
            
            self.hunt_history.append(hunt_result)
            return hunt_result
        
        except Exception as e:
            logger.error(f"Hunt error: {str(e)}")
            return {
                'hunt_id': hunt_id,
                'status': 'error',
                'error': str(e)
            }
    
    def batch_hunt(self, queries: List[str]) -> List[Dict[str, Any]]:
        """Execute multiple hunts."""
        return [self.hunt(query) for query in queries]
    
    def get_hunt_history(self) -> List[Dict]:
        """Retrieve hunt history."""
        return self.hunt_history


# Initialize global instance
threat_hunter = IntegratedThreatHunter()
