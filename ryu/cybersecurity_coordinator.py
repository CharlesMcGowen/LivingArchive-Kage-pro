#!/usr/bin/env python3
"""
Ryu's Cybersecurity Coordinator Service
Coordinates all cybersecurity operations between Ryu's Pokémon team
"""

import logging
import asyncio
import queue
import threading
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from artificial_intelligence.personalities.reconnaissance import EGOQT_SRC  # noqa: F401

logger = logging.getLogger(__name__)

class SecurityStatus(Enum):
    """Security status enumeration"""
    SECURE = "secure"
    VULNERABLE = "vulnerable"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

class AssessmentType(Enum):
    """Assessment type enumeration"""
    VULNERABILITY_SCAN = "vulnerability_scan"
    THREAT_ASSESSMENT = "threat_assessment"
    NETWORK_ANALYSIS = "network_analysis"
    DATA_INTEGRITY = "data_integrity"
    FULL_SECURITY_AUDIT = "full_security_audit"

@dataclass
class SecurityTask:
    """Represents a cybersecurity assessment task"""
    task_id: str
    target_url: str
    assessment_type: AssessmentType
    status: SecurityStatus
    priority: int = 1  # 1=critical, 2=high, 3=medium, 4=low
    created_at: datetime = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    results: Dict[str, Any] = None
    pokemon_team: List[str] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.results is None:
            self.results = {}
        if self.pokemon_team is None:
            self.pokemon_team = []

class RyuCybersecurityCoordinator:
    """
    Ryu's Cybersecurity Coordinator
    Coordinates cybersecurity operations between all Pokémon team members
    """
    
    def __init__(self):
        self.security_queue = queue.PriorityQueue()
        self.active_tasks: Dict[str, SecurityTask] = {}
        self.completed_tasks: Dict[str, SecurityTask] = {}
        self.worker_threads = []
        self.running = False
        
        # Initialize Pokémon team services
        self.porygon_z = None  # Data Analyzer
        self.metagross = None  # Defensive Monitor
        self.gardevoir = None  # Threat Assessment AI
        self.xatu = None       # Network Guardian
        self.alakazam = None   # Vulnerability Scanner
        self.sableye = None    # Decoy Defender
        
        # Configuration
        self.max_concurrent_assessments = 3
        self.assessment_timeout = 600  # 10 minutes
        self.retry_attempts = 3
        
        # Load Nmap knowledge base
        self.nmap_knowledge = self._load_nmap_knowledge()
        
        # Initialize Nmap argument inference engine for Ryu
        try:
            from artificial_intelligence.personalities.reconnaissance.ash.nmap_argument_inference import (
                NmapArgumentInference, ScanScenario
            )
            self.argument_inference = NmapArgumentInference(knowledge_base=self.nmap_knowledge)
            logger.info(f"🧠 Ryu's Nmap argument inference engine initialized ({len(self.argument_inference.arguments)} arguments available)")
        except Exception as e:
            logger.warning(f"⚠️  Argument inference not available: {e}")
            self.argument_inference = None
        
        # Initialize WAF fingerprinting and learning (for security assessments)
        try:
            from artificial_intelligence.personalities.reconnaissance.ash.waf_fingerprinting import WAFFingerprinter
            from artificial_intelligence.personalities.reconnaissance.ash.scan_learning_service import ScanLearningService
            from artificial_intelligence.personalities.reconnaissance.ash.advanced_host_discovery import AdvancedHostDiscovery
            
            self.waf_fingerprinter = WAFFingerprinter()
            self.learning_db = ScanLearningService(
                redis_host='localhost',  # TODO: Get from config
                redis_port=6379,
                redis_db=0
            )
            self.host_discovery = AdvancedHostDiscovery(timeout=10.0)
            logger.info("🛡️  WAF fingerprinting and learning enabled for security assessments")
        except Exception as e:
            logger.warning(f"⚠️  WAF fingerprinting not available: {e}")
            self.waf_fingerprinter = None
            self.learning_db = None
            self.host_discovery = None
        
        logger.info("Ryu's Cybersecurity Coordinator initialized")
        if self.nmap_knowledge:
            logger.info(f"📚 Loaded Nmap knowledge base ({self.nmap_knowledge.get('total_pages', 0)} pages)")
    
    def start(self):
        """Start Ryu's cybersecurity coordinator service"""
        if self.running:
            logger.warning("Ryu's coordinator is already running")
            return
        
        self.running = True
        
        # Start worker threads
        for i in range(self.max_concurrent_assessments):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"RyuSecurityWorker-{i}",
                daemon=True
            )
            worker.start()
            self.worker_threads.append(worker)
        
        logger.info(f"Ryu's Cybersecurity Coordinator started with {self.max_concurrent_assessments} workers")
    
    def stop(self):
        """Stop Ryu's cybersecurity coordinator service"""
        if not self.running:
            logger.warning("Ryu's coordinator is not running")
            return
        
        self.running = False
        
        # Wait for worker threads to finish
        for worker in self.worker_threads:
            worker.join(timeout=5)
        
        logger.info("Ryu's Cybersecurity Coordinator stopped")
    
    def queue_security_assessment(self, target_url: str, assessment_type: AssessmentType, priority: int = 1) -> str:
        """
        Queue a new cybersecurity assessment task
        
        Args:
            target_url: URL to assess
            assessment_type: Type of assessment to perform
            priority: Task priority (1=critical, 2=high, 3=medium, 4=low)
            
        Returns:
            Task ID for tracking
        """
        task_id = f"jade_{assessment_type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        task = SecurityTask(
            task_id=task_id,
            target_url=target_url,
            assessment_type=assessment_type,
            status=SecurityStatus.UNKNOWN,
            priority=priority
        )
        
        # Add to priority queue (lower priority number = higher priority)
        self.security_queue.put((priority, task_id, task))
        
        logger.info(f"Queued security assessment {task_id} for {target_url}")
        return task_id
    
    def get_task_status(self, task_id: str) -> Optional[SecurityTask]:
        """Get the status of a specific task"""
        if task_id in self.active_tasks:
            return self.active_tasks[task_id]
        elif task_id in self.completed_tasks:
            return self.completed_tasks[task_id]
        return None
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status and statistics"""
        return {
            'queue_size': self.security_queue.qsize(),
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len(self.completed_tasks),
            'running': self.running,
            'max_concurrent': self.max_concurrent_assessments
        }
    
    def _worker_loop(self):
        """Worker thread loop for processing security tasks"""
        while self.running:
            try:
                # Get next task from queue (blocking with timeout)
                priority, task_id, task = self.security_queue.get(timeout=1)
                
                # Mark task as active
                task.status = SecurityStatus.UNKNOWN
                task.started_at = datetime.now()
                self.active_tasks[task_id] = task
                
                logger.info(f"Starting security assessment {task_id}")
                
                # Execute the assessment based on type
                try:
                    if task.assessment_type == AssessmentType.VULNERABILITY_SCAN:
                        self._execute_vulnerability_scan(task)
                    elif task.assessment_type == AssessmentType.THREAT_ASSESSMENT:
                        self._execute_threat_assessment(task)
                    elif task.assessment_type == AssessmentType.NETWORK_ANALYSIS:
                        self._execute_network_analysis(task)
                    elif task.assessment_type == AssessmentType.DATA_INTEGRITY:
                        self._execute_data_integrity_check(task)
                    elif task.assessment_type == AssessmentType.FULL_SECURITY_AUDIT:
                        self._execute_full_security_audit(task)
                    
                    # Mark as completed
                    task.status = SecurityStatus.SECURE if not self._has_critical_vulnerabilities(task) else SecurityStatus.CRITICAL
                    task.completed_at = datetime.now()
                    
                except Exception as e:
                    logger.error(f"Security assessment {task_id} failed: {e}")
                    task.status = SecurityStatus.UNKNOWN
                    task.error_message = str(e)
                    task.completed_at = datetime.now()
                
                # Move to completed tasks
                self.completed_tasks[task_id] = task
                if task_id in self.active_tasks:
                    del self.active_tasks[task_id]
                
                logger.info(f"Completed security assessment {task_id}")
                
            except queue.Empty:
                # No tasks in queue, continue
                continue
            except Exception as e:
                logger.error(f"Ryu's security worker thread error: {e}")
    
    def _execute_vulnerability_scan(self, task: SecurityTask):
        """Execute vulnerability scan using Porygon-Z and Alakazam"""
        logger.info(f"Executing vulnerability scan for task {task.task_id}")
        
        try:
            # Import Porygon-Z Data Analyzer
            from .vulnerability_scanner import PorygonZDataAnalyzer
            if not self.porygon_z:
                self.porygon_z = PorygonZDataAnalyzer()
            
            # Execute Signal Beam analysis
            signal_beam_results = self.porygon_z.signal_beam_analysis(task.target_url)
            task.results['signal_beam_analysis'] = signal_beam_results
            
            # Execute Tri Attack analysis
            tri_attack_results = self.porygon_z.tri_attack_analysis(task.target_url)
            task.results['tri_attack_analysis'] = tri_attack_results
            
            # Add Porygon-Z to team
            task.pokemon_team.append("Porygon-Z")
            
            # Import Alakazam Vulnerability Scanner
            from .vulnerability_analyzer_service import AlakazamVulnerabilityScanner
            if not self.alakazam:
                self.alakazam = AlakazamVulnerabilityScanner()
            
            # Execute Psyshock scan
            psyshock_results = self.alakazam.psyshock_scan(task.target_url)
            task.results['psyshock_scan'] = psyshock_results
            
            # Execute Confusion scan
            confusion_results = self.alakazam.confusion_scan(task.target_url)
            task.results['confusion_scan'] = confusion_results
            
            # Add Alakazam to team
            task.pokemon_team.append("Alakazam")
            
        except Exception as e:
            logger.error(f"Vulnerability scan execution failed: {e}")
            raise
    
    def _execute_threat_assessment(self, task: SecurityTask):
        """Execute threat assessment using Gardevoir"""
        logger.info(f"Executing threat assessment for task {task.task_id}")
        
        try:
            # Import Gardevoir Threat Assessment AI
            from .threat_assessment_service import GardevoirThreatAssessmentAI
            if not self.gardevoir:
                self.gardevoir = GardevoirThreatAssessmentAI()
            
            # Execute Psychic analysis
            psychic_results = self.gardevoir.psychic_analysis(task.target_url)
            task.results['psychic_analysis'] = psychic_results
            
            # Execute Future Sight prediction
            future_sight_results = self.gardevoir.future_sight_prediction(task.target_url)
            task.results['future_sight_prediction'] = future_sight_results
            
            # Add Gardevoir to team
            task.pokemon_team.append("Gardevoir")
            
        except Exception as e:
            logger.error(f"Threat assessment execution failed: {e}")
            raise
    
    def _execute_network_analysis(self, task: SecurityTask):
        """Execute network analysis using Xatu"""
        logger.info(f"Executing network analysis for task {task.task_id}")
        
        try:
            # Import Xatu Network Guardian
            from .network_guardian_service import XatuNetworkGuardian
            if not self.xatu:
                self.xatu = XatuNetworkGuardian()
            
            # Execute Miracle Eye analysis
            miracle_eye_results = self.xatu.miracle_eye_analysis(task.target_url)
            task.results['miracle_eye_analysis'] = miracle_eye_results
            
            # Execute Psychic network analysis
            psychic_network_results = self.xatu.psychic_network_analysis(task.target_url)
            task.results['psychic_network_analysis'] = psychic_network_results
            
            # Add Xatu to team
            task.pokemon_team.append("Xatu")
            
        except Exception as e:
            logger.error(f"Network analysis execution failed: {e}")
            raise
    
    def _execute_data_integrity_check(self, task: SecurityTask):
        """Execute data integrity check using Metagross"""
        logger.info(f"Executing data integrity check for task {task.task_id}")
        
        try:
            # Import Metagross Defensive Monitor
            from .defensive_monitor_service import MetagrossDefensiveMonitor
            if not self.metagross:
                self.metagross = MetagrossDefensiveMonitor()
            
            # Execute Zen Headbutt analysis
            zen_headbutt_results = self.metagross.zen_headbutt_analysis(task.target_url)
            task.results['zen_headbutt_analysis'] = zen_headbutt_results
            
            # Execute Bullet Punch analysis
            bullet_punch_results = self.metagross.bullet_punch_analysis(task.target_url)
            task.results['bullet_punch_analysis'] = bullet_punch_results
            
            # Add Metagross to team
            task.pokemon_team.append("Metagross")
            
        except Exception as e:
            logger.error(f"Data integrity check execution failed: {e}")
            raise
    
    def _execute_full_security_audit(self, task: SecurityTask):
        """Execute full security audit using all Pokémon"""
        logger.info(f"Executing full security audit for task {task.task_id}")
        
        # Execute all assessment types (these will add Pokémon to team automatically)
        self._execute_vulnerability_scan(task)  # Adds Porygon-Z and Alakazam
        self._execute_threat_assessment(task)    # Adds Gardevoir
        self._execute_network_analysis(task)    # Adds Xatu
        self._execute_data_integrity_check(task) # Adds Metagross
        
        # Note: Sableye (Decoy Defender) is not yet implemented in full audit
        # All other Pokémon are already added by the individual methods
        
        logger.info(f"Full security audit completed for task {task.task_id} with Pokémon team: {task.pokemon_team}")
    
    def _has_critical_vulnerabilities(self, task: SecurityTask) -> bool:
        """Check if task has critical vulnerabilities"""
        if 'signal_beam_analysis' in task.results:
            vulnerabilities = task.results['signal_beam_analysis'].get('vulnerabilities', [])
            for vuln in vulnerabilities:
                if vuln.get('severity') == 'critical':
                    return True
        
        if 'tri_attack_analysis' in task.results:
            severity_score = task.results['tri_attack_analysis'].get('severity_score', 0)
            if severity_score >= 70:
                return True
        
        return False
    
    def _load_nmap_knowledge(self) -> Optional[Dict[str, Any]]:
        """Load Nmap knowledge base from scraped documentation."""
        knowledge_paths = [
            Path('/mnt/webapps-nvme/nmap_knowledge/jade_nmap_knowledge.json'),
            Path('/mnt/webapps-nvme/artificial_intelligence/personalities/reconnaissance/jade/nmap_knowledge.json'),
            Path('nmap_knowledge/jade_nmap_knowledge.json'),
        ]
        
        for knowledge_path in knowledge_paths:
            if knowledge_path.exists():
                try:
                    with open(knowledge_path, 'r', encoding='utf-8') as f:
                        knowledge = json.load(f)
                    logger.info(f"📚 Loaded Nmap knowledge from {knowledge_path}")
                    return knowledge
                except Exception as e:
                    logger.warning(f"Failed to load Nmap knowledge from {knowledge_path}: {e}")
        
        logger.debug("No Nmap knowledge base found - Ryu will use default security techniques")
        return None
    
    def get_security_scanning_advice(self, assessment_type: AssessmentType, target_url: str = None) -> Dict[str, Any]:
        """
        Get Nmap security scanning advice using inference engine and knowledge base.
        
        Args:
            assessment_type: Type of security assessment
            target_url: Optional target URL
            
        Returns:
            Dictionary with advice, Nmap arguments, and reasoning
        """
        result = {
            'advice': [],
            'nmap_arguments': [],
            'command': None,
            'reasoning': None
        }
        
        # Use inference engine if available
        if self.argument_inference:
            from artificial_intelligence.personalities.reconnaissance.ash.nmap_argument_inference import ScanScenario
            
            # Determine scenario based on assessment type
            stealth_required = assessment_type in [AssessmentType.PENETRATION_TEST]
            service_detection_needed = assessment_type in [AssessmentType.VULNERABILITY_SCAN]
            os_detection_needed = assessment_type in [AssessmentType.FULL_SECURITY_AUDIT]
            
            scenario = ScanScenario(
                target_type='single_host',
                stealth_required=stealth_required,
                service_detection_needed=service_detection_needed,
                os_detection_needed=os_detection_needed,
                speed_priority='normal'
            )
            
            inference_result = self.argument_inference.infer_arguments(scenario)
            
            result['nmap_arguments'] = inference_result.get('recommendations', [])
            result['command'] = inference_result.get('command')
            result['reasoning'] = inference_result.get('reasoning')
        
        # Add knowledge base advice
        if not self.nmap_knowledge:
            return result
        
        categories = self.nmap_knowledge.get('categories', {})
        
        # Map assessment types to knowledge categories
        category_mapping = {
            AssessmentType.VULNERABILITY_SCAN: 'vulnerability_detection',
            AssessmentType.THREAT_ASSESSMENT: 'security_scanning',
            AssessmentType.NETWORK_ANALYSIS: 'network_analysis',
            AssessmentType.FULL_SECURITY_AUDIT: 'security_auditing',
        }
        
        category = category_mapping.get(assessment_type, 'security_scanning')
        
        if category in categories:
            for entry in categories[category][:3]:  # Top 3 entries
                if entry.get('examples'):
                    for example in entry['examples'][:2]:  # Top 2 examples
                        result['advice'].append(f"Security technique: {example[:200]}")
                elif entry.get('text'):
                    text = entry['text'][:300]
                    result['advice'].append(f"Knowledge: {text}")
        
        # Also get firewall/IDS evasion advice for security assessments
        if 'ids_evasion' in categories:
            for entry in categories['ids_evasion'][:2]:
                if entry.get('examples'):
                    result['advice'].append(f"Evasion technique: {entry['examples'][0][:200]}")
        
        return result
    
    def get_stealth_scanning_strategy(self, target_url: str) -> Dict[str, Any]:
        """
        Get stealth scanning strategy using inference engine and knowledge base.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Dictionary with recommended stealth strategy including Nmap arguments
        """
        strategy = {
            'technique': 'stealth',
            'evasion_methods': [],
            'timing': 'slow',
            'advice': [],
            'nmap_arguments': [],
            'command': None,
            'reasoning': None
        }
        
        # Use inference engine if available
        if self.argument_inference:
            from artificial_intelligence.personalities.reconnaissance.ash.nmap_argument_inference import ScanScenario
            
            scenario = ScanScenario(
                target_type='single_host',
                stealth_required=True,
                ids_detected=True,
                speed_priority='normal'
            )
            
            inference_result = self.argument_inference.infer_arguments(scenario)
            
            strategy['nmap_arguments'] = inference_result.get('recommendations', [])
            strategy['command'] = inference_result.get('command')
            strategy['reasoning'] = inference_result.get('reasoning')
            
            # Extract evasion methods from arguments
            for arg in strategy['nmap_arguments']:
                flag = arg.get('flag', '')
                if flag in ['-sF', '-sN', '-sX', '-f', '--scanflags']:
                    strategy['evasion_methods'].append(f"{flag}: {arg.get('reason', '')}")
        
        # Fallback to knowledge base
        if not self.nmap_knowledge:
            return strategy
        
        categories = self.nmap_knowledge.get('categories', {})
        
        # Get stealth techniques
        if 'stealth_techniques' in categories:
            for entry in categories['stealth_techniques'][:3]:
                if entry.get('examples'):
                    strategy['evasion_methods'].extend(entry['examples'][:2])
                strategy['advice'].append(entry.get('text', '')[:200])
        
        # Get IDS evasion techniques
        if 'ids_evasion' in categories:
            for entry in categories['ids_evasion'][:2]:
                if entry.get('examples'):
                    strategy['evasion_methods'].extend(entry['examples'][:1])
        
        # Get firewall testing techniques
        if 'firewall_testing' in categories:
            for entry in categories['firewall_testing'][:2]:
                if entry.get('text'):
                    strategy['advice'].append(entry['text'][:200])
        
        return strategy

# Global coordinator instance
ryu_coordinator = RyuCybersecurityCoordinator()

def get_ryu_coordinator() -> RyuCybersecurityCoordinator:
    """Get Ryu's cybersecurity coordinator instance"""
    return ryu_coordinator

def start_ryu_coordinator():
    """Start Ryu's cybersecurity coordinator"""
    ryu_coordinator.start()

def stop_ryu_coordinator():
    """Stop Ryu's cybersecurity coordinator"""
    ryu_coordinator.stop()

def queue_cybersecurity_assessment(target_url: str, assessment_type: str = "full_security_audit", priority: int = 1) -> str:
    """
    Queue a cybersecurity assessment task
    
    Args:
        target_url: URL to assess
        assessment_type: Type of assessment ("vulnerability_scan", "threat_assessment", "network_analysis", "data_integrity", "full_security_audit")
        priority: Task priority (1=critical, 2=high, 3=medium, 4=low)
        
    Returns:
        Task ID for tracking
    """
    assessment_type_enum = AssessmentType(assessment_type)
    return ryu_coordinator.queue_security_assessment(target_url, assessment_type_enum, priority)


