#!/usr/bin/env python3
"""
Surge Class-Based Nuclei API
============================

Replaces command-line arguments with class-based API for direct code-level control.
Enables learning system integration and on-the-fly adaptations.

Author: EGO Revolution Team
Version: 2.0.0 - Class-Based API with Real-Time Callbacks
"""

import ctypes
import json
import logging
import uuid
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Callable, Any
from datetime import datetime

from django.utils import timezone

# Import Django models for learning system
try:
    from surge.models import (
        NucleiTemplateUsage, NucleiScanSession, 
        NucleiAdaptationRule, NucleiAgentControl
    )
    DJANGO_ORM_AVAILABLE = True
except ImportError:
    DJANGO_ORM_AVAILABLE = False
    NucleiTemplateUsage = None
    NucleiScanSession = None
    NucleiAdaptationRule = None
    NucleiAgentControl = None

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Scan execution status"""
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScanConfig:
    """
    Comprehensive scan configuration using class attributes instead of CLI args.
    Maps to all Nuclei SDK options for full feature exposure.
    """
    # ========== Template Selection ==========
    template_ids: List[str] = field(default_factory=list)
    template_paths: List[str] = field(default_factory=list)
    template_tags: List[str] = field(default_factory=list)
    severity_levels: List[Severity] = field(default_factory=lambda: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM])
    workflows: List[str] = field(default_factory=list)
    
    # ========== Template Types ==========
    enable_code_templates: bool = False  # Enable code protocol templates
    enable_self_contained_templates: bool = False  # Enable self-contained templates
    enable_global_matchers_templates: bool = False  # Enable global-matchers templates
    enable_file_templates: bool = False  # Enable file protocol templates
    
    # ========== Rate Limiting ==========
    rate_limit: int = 10  # Requests per second (global rate limit)
    rate_limit_duration_seconds: float = 1.0  # Duration for rate limit window
    
    # ========== Concurrency ==========
    template_concurrency: int = 5  # Templates per host
    host_concurrency: int = 5  # Hosts per template
    headless_host_concurrency: int = 1  # Headless hosts per template
    headless_template_concurrency: int = 1  # Headless templates per host
    javascript_template_concurrency: int = 1  # JS templates per host
    template_payload_concurrency: int = 25  # Max concurrent payloads per template
    probe_concurrency: int = 50  # Max concurrent HTTP probes
    
    # ========== Network Configuration ==========
    timeout: int = 30  # Request timeout in seconds
    retries: int = 1  # Number of retries
    max_host_error: int = 30  # Max host errors before skipping
    disable_max_host_error: bool = False  # Disable max host error optimization
    interface: Optional[str] = None  # Network interface to use
    source_ip: Optional[str] = None  # Source IP address
    system_resolvers: bool = False  # Use system DNS resolvers
    internal_resolvers: List[str] = field(default_factory=list)  # Custom DNS resolvers
    leave_default_ports: bool = False  # Leave default ports for http/https
    track_error: List[str] = field(default_factory=list)  # Errors to track for max host error
    
    # ========== HTTP Options ==========
    headers: List[str] = field(default_factory=list)  # Format: ["Header: Value"]
    proxies: List[str] = field(default_factory=list)  # Format: ["http://proxy:port"]
    proxy_internal_requests: bool = False  # Proxy internal requests
    follow_redirects: bool = True
    max_redirects: int = 3
    response_read_size: int = 0  # Max response size to read (0 = no limit, bytes)
    
    # ========== Scan Strategy ==========
    scan_strategy: Optional[str] = None  # "auto", "template-spray", "host-spray"
    
    # ========== Verbosity & Debugging ==========
    verbose: bool = False  # Show verbose output
    silent: bool = False  # Show only results
    debug: bool = False  # Show debug output
    debug_request: bool = False  # Show request in debug output
    debug_response: bool = False  # Show response in debug output
    show_var_dump: bool = False  # Show variable dumps
    
    # ========== Matcher Options ==========
    matcher_status: bool = False  # Enable matcher status (call callback for all results)
    
    # ========== Headless Browser ==========
    enable_headless: bool = False
    headless_page_timeout: int = 30  # Page load timeout
    headless_show_browser: bool = False  # Show browser window
    headless_options: List[str] = field(default_factory=list)  # Chrome options
    headless_use_chrome: bool = False  # Use installed Chrome
    
    # ========== Sandbox Options ==========
    allow_local_file_access: bool = False  # Allow local file access
    restrict_local_network_access: bool = False  # Restrict local network access
    
    # ========== Template Variables ==========
    vars: Dict[str, str] = field(default_factory=dict)  # Template variables
    
    # ========== Interactsh (OOB Testing) ==========
    enable_interactsh: bool = False
    interactsh_server_url: Optional[str] = None
    interactsh_token: Optional[str] = None
    
    # ========== Resume & Recovery ==========
    resume_file: Optional[str] = None  # Resume file path
    
    # ========== Passive Mode ==========
    passive_mode: bool = False  # Passive HTTP response processing
    
    # ========== Template Updates ==========
    disable_template_auto_upgrade: bool = False  # Disable template auto-upgrade
    
    # ========== Learning and Adaptation ==========
    enable_learning: bool = True  # Enable learning system
    adaptive_mode: bool = True  # Enable adaptive scanning
    
    # ========== Thread Safety ==========
    use_thread_safe: bool = False  # Use ThreadSafeNucleiEngine for concurrent scans
    
    # ========== Output ==========
    output_format: str = "json"  # json, jsonl, markdown
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            # Template selection
            "templates": self.template_ids,
            "template_paths": self.template_paths,
            "tags": self.template_tags,
            "severities": [s.value for s in self.severity_levels],
            "workflows": self.workflows,
            
            # Template types
            "enable_code_templates": self.enable_code_templates,
            "enable_self_contained_templates": self.enable_self_contained_templates,
            "enable_global_matchers_templates": self.enable_global_matchers_templates,
            "enable_file_templates": self.enable_file_templates,
            
            # Rate limiting
            "rate_limit": self.rate_limit,
            "rate_limit_duration_seconds": self.rate_limit_duration_seconds,
            
            # Concurrency
            "template_concurrency": self.template_concurrency,
            "host_concurrency": self.host_concurrency,
            "headless_host_concurrency": self.headless_host_concurrency,
            "headless_template_concurrency": self.headless_template_concurrency,
            "javascript_template_concurrency": self.javascript_template_concurrency,
            "template_payload_concurrency": self.template_payload_concurrency,
            "probe_concurrency": self.probe_concurrency,
            
            # Network configuration
            "timeout": self.timeout,
            "retries": self.retries,
            "max_host_error": self.max_host_error,
            "disable_max_host_error": self.disable_max_host_error,
            "interface": self.interface,
            "source_ip": self.source_ip,
            "system_resolvers": self.system_resolvers,
            "internal_resolvers": self.internal_resolvers,
            "leave_default_ports": self.leave_default_ports,
            "track_error": self.track_error,
            
            # HTTP options
            "headers": self.headers,
            "proxies": self.proxies,
            "proxy_internal_requests": self.proxy_internal_requests,
            "response_read_size": self.response_read_size,
            
            # Scan strategy
            "scan_strategy": self.scan_strategy,
            
            # Verbosity
            "verbose": self.verbose,
            "silent": self.silent,
            "debug": self.debug,
            "debug_request": self.debug_request,
            "debug_response": self.debug_response,
            "show_var_dump": self.show_var_dump,
            
            # Matcher
            "matcher_status": self.matcher_status,
            
            # Headless
            "enable_headless": self.enable_headless,
            "headless_page_timeout": self.headless_page_timeout,
            "headless_show_browser": self.headless_show_browser,
            "headless_options": self.headless_options,
            "headless_use_chrome": self.headless_use_chrome,
            
            # Sandbox
            "allow_local_file_access": self.allow_local_file_access,
            "restrict_local_network_access": self.restrict_local_network_access,
            
            # Variables
            "vars": self.vars,
            
            # Interactsh
            "enable_interactsh": self.enable_interactsh,
            "interactsh_server_url": self.interactsh_server_url,
            "interactsh_token": self.interactsh_token,
            
            # Resume
            "resume_file": self.resume_file,
            
            # Passive mode
            "passive_mode": self.passive_mode,
            
            # Template updates
            "disable_template_auto_upgrade": self.disable_template_auto_upgrade,
            
            # Learning
            "enable_learning": self.enable_learning,
            "adaptive_mode": self.adaptive_mode,
        }


@dataclass
class VulnerabilityFinding:
    """Vulnerability finding from Nuclei scan"""
    template_id: str
    template_name: str
    severity: Severity
    target: str
    matched_at: str
    request: Optional[str] = None
    response: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    cve_id: Optional[str] = None
    technology: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class ScanProgress:
    """Real-time scan progress information"""
    scan_id: str
    total_requests: int
    completed_requests: int
    successful_requests: int
    failed_requests: int
    vulnerabilities_found: int
    active_templates: List[str]
    current_target: str
    progress_percent: float
    duration_seconds: float
    start_time: datetime
    last_update: datetime


class NucleiEngine:
    """
    Class-based Nuclei engine wrapper with real-time callbacks.
    Replaces command-line arguments with method calls and class attributes.
    """
    
    def __init__(self, engine_id: Optional[str] = None, config: Optional[ScanConfig] = None):
        """
        Initialize Nuclei engine.
        
        Args:
            engine_id: Unique engine identifier (auto-generated if None)
            config: Scan configuration (defaults used if None)
        """
        self.engine_id = engine_id or str(uuid.uuid4())
        self.config = config or ScanConfig()
        self.status = ScanStatus.QUEUED
        self.scan_session: Optional[NucleiScanSession] = None
        
        # Load Go bridge library
        self.bridge = self._load_bridge()
        
        # Event callbacks
        self.on_vulnerability: List[Callable[[VulnerabilityFinding], None]] = []
        self.on_progress: List[Callable[[ScanProgress], None]] = []
        self.on_state_change: List[Callable[[ScanStatus], None]] = []
        self.on_error: List[Callable[[str], None]] = []
        
        # Thread safety for callbacks
        self._callback_lock = threading.Lock()
        
        # Initialize engine via Go bridge
        self._initialize_engine()
        
        logger.info(f"✅ NucleiEngine initialized: {self.engine_id}")
    
    def _load_bridge(self) -> Optional[ctypes.CDLL]:
        """Load Go bridge shared library"""
        bridge_paths = [
            Path(__file__).parent / 'go_bridge' / 'libnuclei_bridge.so',
            Path(__file__).parent.parent / 'nuclei' / 'go_bridge' / 'libnuclei_bridge.so',
        ]
        
        for bridge_path in bridge_paths:
            if bridge_path.exists():
                try:
                    bridge = ctypes.CDLL(str(bridge_path))
                    # Set up function signatures
                    bridge.InitializeNucleiEngine.restype = ctypes.c_char_p
                    bridge.InitializeNucleiEngine.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
                    
                    bridge.RegisterCallbacks.restype = ctypes.c_char_p
                    bridge.RegisterCallbacks.argtypes = [
                        ctypes.c_char_p, ctypes.c_char_p,  # engineID, scanID
                        ctypes.CFUNCTYPE(None, ctypes.c_char_p),  # VulnCallback
                        ctypes.CFUNCTYPE(None, ctypes.c_char_p),  # ProgressCallback
                        ctypes.CFUNCTYPE(None, ctypes.c_char_p),  # StateCallback
                        ctypes.CFUNCTYPE(None, ctypes.c_char_p),  # ErrorCallback
                    ]
                    
                    bridge.ExecuteScan.restype = ctypes.c_char_p
                    bridge.ExecuteScan.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                    
                    bridge.PauseScan.restype = ctypes.c_char_p
                    bridge.PauseScan.argtypes = [ctypes.c_char_p]
                    
                    bridge.ResumeScan.restype = ctypes.c_char_p
                    bridge.ResumeScan.argtypes = [ctypes.c_char_p]
                    
                    bridge.AdjustRateLimit.restype = ctypes.c_char_p
                    bridge.AdjustRateLimit.argtypes = [ctypes.c_char_p, ctypes.c_int]
                    
                    bridge.GetScanState.restype = ctypes.c_char_p
                    bridge.GetScanState.argtypes = [ctypes.c_char_p]
                    
                    bridge.CloseEngine.restype = ctypes.c_char_p
                    bridge.CloseEngine.argtypes = [ctypes.c_char_p]
                    
                    logger.info(f"✅ Loaded Nuclei bridge from {bridge_path}")
                    return bridge
                except Exception as e:
                    logger.warning(f"Failed to load bridge from {bridge_path}: {e}")
        
        logger.warning("⚠️  Nuclei bridge not found - will use subprocess fallback")
        return None
    
    def _initialize_engine(self):
        """Initialize Nuclei engine via Go bridge"""
        if not self.bridge:
            return
        
        config_dict = self.config.to_dict()
        config_json = json.dumps(config_dict)
        use_thread_safe = 1 if self.config.use_thread_safe else 0
        
        result = self.bridge.InitializeNucleiEngine(
            self.engine_id.encode('utf-8'),
            config_json.encode('utf-8'),
            ctypes.c_int(use_thread_safe)
        )
        
        result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
        result_data = json.loads(result_str)
        
        if 'error' in result_data:
            raise RuntimeError(f"Failed to initialize engine: {result_data['error']}")
    
    def scan(self, targets: List[str], egg_record_id: Optional[str] = None) -> str:
        """
        Execute scan on targets with real-time callbacks.
        
        Args:
            targets: List of target URLs/IPs
            egg_record_id: Optional EggRecord ID for tracking
            
        Returns:
            Scan session ID
        """
        scan_id = str(uuid.uuid4())
        
        # Create scan session in database
        if DJANGO_ORM_AVAILABLE:
            self.scan_session = NucleiScanSession.objects.create(
                scan_id=scan_id,
                egg_record_id=egg_record_id,
                target=targets[0] if targets else "",
                scan_config=self.config.to_dict(),
                templates_used=self.config.template_ids,
                status='running',
                start_time=timezone.now(),
            )
        
        # Register callbacks BEFORE executing scan
        if self.bridge:
            self._register_callbacks(scan_id)
        
        # Update status
        self.status = ScanStatus.RUNNING
        self._notify_state_change()
        
        # Execute scan via Go bridge
        if self.bridge:
            targets_json = json.dumps(targets)
            result = self.bridge.ExecuteScan(
                self.engine_id.encode('utf-8'),
                targets_json.encode('utf-8')
            )
            result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
            logger.info(f"Scan started: {result_str}")
        else:
            # Fallback to subprocess (legacy)
            logger.warning("Using subprocess fallback - bridge not available")
            self._scan_via_subprocess(targets, scan_id)
        
        return scan_id
    
    def _register_callbacks(self, scan_id: str):
        """Register C callbacks with Go bridge"""
        if not self.bridge:
            return
        
        # Define C callback functions that Python will provide
        @ctypes.CFUNCTYPE(None, ctypes.c_char_p)
        def vuln_callback(json_data):
            """C callback for vulnerability findings"""
            try:
                json_str = json_data.decode('utf-8') if isinstance(json_data, bytes) else str(json_data)
                vuln_data = json.loads(json_str)
                finding = self._parse_vulnerability(vuln_data)
                
                # Update learning system
                if DJANGO_ORM_AVAILABLE and self.config.enable_learning:
                    self._update_template_usage(finding)
                
                # Update scan session
                if self.scan_session:
                    self._update_scan_session_from_finding(finding)
                
                # Notify Python callbacks
                with self._callback_lock:
                    for callback in self.on_vulnerability:
                        try:
                            callback(finding)
                        except Exception as e:
                            logger.error(f"Error in vulnerability callback: {e}")
            except Exception as e:
                logger.error(f"Error processing vulnerability callback: {e}")
        
        @ctypes.CFUNCTYPE(None, ctypes.c_char_p)
        def progress_callback(json_data):
            """C callback for progress updates"""
            try:
                json_str = json_data.decode('utf-8') if isinstance(json_data, bytes) else str(json_data)
                progress_data = json.loads(json_str)
                progress = self._parse_progress(progress_data)
                
                # Update scan session in real-time
                if self.scan_session:
                    self._update_scan_session_from_progress(progress)
                
                # Notify Python callbacks
                with self._callback_lock:
                    for callback in self.on_progress:
                        try:
                            callback(progress)
                        except Exception as e:
                            logger.error(f"Error in progress callback: {e}")
            except Exception as e:
                logger.error(f"Error processing progress callback: {e}")
        
        @ctypes.CFUNCTYPE(None, ctypes.c_char_p)
        def state_callback(json_data):
            """C callback for state changes"""
            try:
                json_str = json_data.decode('utf-8') if isinstance(json_data, bytes) else str(json_data)
                state_data = json.loads(json_str)
                new_status = ScanStatus(state_data.get('status', 'running'))
                
                self.status = new_status
                
                # Update scan session
                if self.scan_session:
                    self.scan_session.status = new_status.value
                    if new_status == ScanStatus.COMPLETED:
                        self.scan_session.end_time = timezone.now()
                        if self.scan_session.start_time:
                            duration = (self.scan_session.end_time - self.scan_session.start_time).total_seconds()
                            self.scan_session.duration_seconds = duration
                    self.scan_session.save(update_fields=['status', 'end_time', 'duration_seconds'])
                
                # Notify Python callbacks
                with self._callback_lock:
                    self._notify_state_change()
            except Exception as e:
                logger.error(f"Error processing state callback: {e}")
        
        @ctypes.CFUNCTYPE(None, ctypes.c_char_p)
        def error_callback(json_data):
            """C callback for errors"""
            try:
                json_str = json_data.decode('utf-8') if isinstance(json_data, bytes) else str(json_data)
                error_data = json.loads(json_str)
                error_msg = error_data.get('error', 'Unknown error')
                
                logger.error(f"Scan error: {error_msg}")
                
                # Update scan session
                if self.scan_session:
                    self.scan_session.status = 'failed'
                    self.scan_session.end_time = timezone.now()
                    self.scan_session.save(update_fields=['status', 'end_time'])
                
                # Notify Python callbacks
                with self._callback_lock:
                    for callback in self.on_error:
                        try:
                            callback(error_msg)
                        except Exception as e:
                            logger.error(f"Error in error callback: {e}")
            except Exception as e:
                logger.error(f"Error processing error callback: {e}")
        
        # Store callbacks to prevent garbage collection
        self._c_callbacks = {
            'vuln': vuln_callback,
            'progress': progress_callback,
            'state': state_callback,
            'error': error_callback,
        }
        
        # Register with Go bridge
        result = self.bridge.RegisterCallbacks(
            self.engine_id.encode('utf-8'),
            scan_id.encode('utf-8'),
            vuln_callback,
            progress_callback,
            state_callback,
            error_callback
        )
        
        result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
        result_data = json.loads(result_str)
        
        if 'error' in result_data:
            raise RuntimeError(f"Failed to register callbacks: {result_data['error']}")
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any]) -> VulnerabilityFinding:
        """Parse vulnerability data from Nuclei ResultEvent"""
        info = vuln_data.get('info', {})
        
        # Extract CVE ID
        cve_id = None
        classification = info.get('classification', {})
        if isinstance(classification, dict):
            cve_id = classification.get('cve-id')
        if not cve_id:
            # Try extracting from template ID or name
            template_id = vuln_data.get('template-id', '')
            if 'cve-' in template_id.lower():
                cve_id = template_id.upper()
        
        # Extract severity
        severity_str = info.get('severity', 'info').lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO
        
        # Parse timestamp
        timestamp = None
        if 'timestamp' in vuln_data:
            try:
                timestamp = datetime.fromisoformat(vuln_data['timestamp'].replace('Z', '+00:00'))
            except:
                pass
        
        return VulnerabilityFinding(
            template_id=vuln_data.get('template-id', ''),
            template_name=info.get('name', ''),
            severity=severity,
            target=vuln_data.get('matched-at', vuln_data.get('host', '')),
            matched_at=vuln_data.get('matched-at', ''),
            request=vuln_data.get('request'),
            response=vuln_data.get('response'),
            metadata=info,
            cve_id=cve_id,
            technology=info.get('tags', [])[0] if info.get('tags') else None,
            timestamp=timestamp or timezone.now(),
        )
    
    def _parse_progress(self, progress_data: Dict[str, Any]) -> ScanProgress:
        """Parse progress data from Go bridge"""
        return ScanProgress(
            scan_id=progress_data.get('scan_id', ''),
            total_requests=progress_data.get('total_requests', 0),
            completed_requests=progress_data.get('completed_requests', 0),
            successful_requests=progress_data.get('successful_requests', 0),
            failed_requests=progress_data.get('failed_requests', 0),
            vulnerabilities_found=progress_data.get('vulnerabilities_found', 0),
            active_templates=progress_data.get('active_templates', []),
            current_target=progress_data.get('current_target', ''),
            progress_percent=progress_data.get('progress_percent', 0.0),
            duration_seconds=progress_data.get('duration_seconds', 0.0),
            start_time=datetime.fromtimestamp(progress_data.get('start_time', 0)),
            last_update=datetime.fromtimestamp(progress_data.get('last_update', 0)),
        )
    
    def _update_template_usage(self, finding: VulnerabilityFinding):
        """Update template usage statistics for learning"""
        if not DJANGO_ORM_AVAILABLE:
            return
        
        usage, created = NucleiTemplateUsage.objects.get_or_create(
            template_id=finding.template_id,
            defaults={
                'template_path': '',
                'usage_count': 0,
                'success_count': 0,
            }
        )
        
        usage.update_success()
        
        # Update technology tracking
        if finding.technology:
            if finding.technology not in usage.technologies_detected:
                usage.technologies_detected.append(finding.technology)
                usage.save(update_fields=['technologies_detected'])
        
        # Update CVE tracking
        if finding.cve_id:
            if finding.cve_id not in usage.cve_ids:
                usage.cve_ids.append(finding.cve_id)
                usage.save(update_fields=['cve_ids'])
    
    def _update_scan_session_from_finding(self, finding: VulnerabilityFinding):
        """Update scan session with vulnerability finding"""
        if not self.scan_session:
            return
        
        # Add to vulnerabilities_data
        vuln_data = self.scan_session.vulnerabilities_data or []
        vuln_data.append({
            'template_id': finding.template_id,
            'template_name': finding.template_name,
            'severity': finding.severity.value,
            'target': finding.target,
            'cve_id': finding.cve_id,
            'timestamp': finding.timestamp.isoformat() if finding.timestamp else None,
        })
        
        self.scan_session.vulnerabilities_found = len(vuln_data)
        self.scan_session.vulnerabilities_data = vuln_data
        self.scan_session.save(update_fields=['vulnerabilities_found', 'vulnerabilities_data'])
    
    def _update_scan_session_from_progress(self, progress: ScanProgress):
        """Update scan session with real-time progress"""
        if not self.scan_session:
            return
        
        self.scan_session.total_requests = progress.total_requests
        self.scan_session.completed_requests = progress.completed_requests
        self.scan_session.successful_requests = progress.successful_requests
        self.scan_session.failed_requests = progress.failed_requests
        self.scan_session.vulnerabilities_found = progress.vulnerabilities_found
        
        self.scan_session.save(update_fields=[
            'total_requests', 'completed_requests', 'successful_requests',
            'failed_requests', 'vulnerabilities_found'
        ])
    
    def _scan_via_subprocess(self, targets: List[str], scan_id: str):
        """Fallback: scan via subprocess (legacy method)"""
        # This would use the existing integration.py subprocess method
        logger.warning("Subprocess fallback not yet implemented")
    
    def pause(self):
        """Pause running scan"""
        if self.status != ScanStatus.RUNNING:
            logger.warning(f"Cannot pause scan in {self.status.value} state")
            return
        
        if self.bridge:
            result = self.bridge.PauseScan(self.engine_id.encode('utf-8'))
            result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
            logger.info(f"Scan paused: {result_str}")
        
        self.status = ScanStatus.PAUSED
        self._notify_state_change()
        
        if self.scan_session:
            self.scan_session.status = 'paused'
            self.scan_session.save(update_fields=['status'])
    
    def resume(self):
        """Resume paused scan"""
        if self.status != ScanStatus.PAUSED:
            logger.warning(f"Cannot resume scan in {self.status.value} state")
            return
        
        if self.bridge:
            result = self.bridge.ResumeScan(self.engine_id.encode('utf-8'))
            result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
            logger.info(f"Scan resumed: {result_str}")
        
        self.status = ScanStatus.RUNNING
        self._notify_state_change()
        
        if self.scan_session:
            self.scan_session.status = 'running'
            self.scan_session.save(update_fields=['status'])
    
    def adjust_rate_limit(self, new_rate_limit: int):
        """
        Adjust rate limit on-the-fly.
        
        Args:
            new_rate_limit: New requests per second
        """
        if self.bridge:
            result = self.bridge.AdjustRateLimit(
                self.engine_id.encode('utf-8'),
                ctypes.c_int(new_rate_limit)
            )
            result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
            logger.info(f"Rate limit adjusted: {result_str}")
        
        self.config.rate_limit = new_rate_limit
        
        # Record adaptation
        if self.scan_session:
            self.scan_session.apply_adaptation(
                'adjust_rate_limit',
                f"Rate limit changed to {new_rate_limit} req/s",
                {'rate_limit': new_rate_limit}
            )
    
    def get_state(self) -> Dict[str, Any]:
        """Get current scan state"""
        if self.bridge:
            result = self.bridge.GetScanState(self.engine_id.encode('utf-8'))
            result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
            return json.loads(result_str)
        
        return {
            "engine_id": self.engine_id,
            "status": self.status.value,
            "config": self.config.to_dict(),
        }
    
    def close(self):
        """Close engine and cleanup"""
        if self.bridge:
            result = self.bridge.CloseEngine(self.engine_id.encode('utf-8'))
            result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
            logger.info(f"Engine closed: {result_str}")
        
        if self.scan_session:
            self.scan_session.status = 'completed'
            self.scan_session.end_time = timezone.now()
            if self.scan_session.start_time:
                duration = (self.scan_session.end_time - self.scan_session.start_time).total_seconds()
                self.scan_session.duration_seconds = duration
            self.scan_session.save(update_fields=['status', 'end_time', 'duration_seconds'])
    
    def _notify_state_change(self):
        """Notify state change callbacks"""
        for callback in self.on_state_change:
            try:
                callback(self.status)
            except Exception as e:
                logger.error(f"Error in state change callback: {e}")


class AdaptiveNucleiEngine(NucleiEngine):
    """
    Enhanced Nuclei engine with adaptive learning capabilities.
    Automatically adjusts scan parameters based on real-time feedback.
    
    Integrates:
    - Template Scoring: Prioritizes effective templates
    - Rule Engine: Applies adaptation rules based on real-time metrics
    - Learning System: Updates template usage statistics
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Import learning system components
        try:
            from .learning.template_scorer import TemplateScorer
            from .learning.rule_engine import AdaptationRuleEngine
            self.template_scorer = TemplateScorer()
            self.rule_engine = AdaptationRuleEngine()
        except ImportError as e:
            logger.warning(f"Could not import learning system: {e}")
            self.template_scorer = None
            self.rule_engine = None
        
        # Set up adaptive progress monitoring
        def adaptive_progress_handler(progress: ScanProgress):
            self._evaluate_adaptation_rules(progress)
        
        self.on_progress.append(adaptive_progress_handler)
        
        # Track adaptations applied during this scan
        self._adaptations_applied = []
    
    def scan(self, targets: List[str], egg_record_id: Optional[str] = None) -> str:
        """
        Execute scan with adaptive learning integration.
        
        If adaptive_mode is enabled:
        1. Prioritizes templates using TemplateScorer
        2. Applies initial configuration adaptations
        3. Monitors progress for real-time adaptations
        """
        # Apply template prioritization if scorer is available
        if self.config.adaptive_mode and self.template_scorer and self.config.template_ids:
            try:
                prioritized = self.template_scorer.get_prioritized_templates(self.config.template_ids)
                # Update config with prioritized templates
                self.config.template_ids = prioritized
                logger.info(f"🎯 Prioritized {len(prioritized)} templates using learning system")
            except Exception as e:
                logger.warning(f"Template prioritization failed: {e}")
        
        # Apply initial rule-based adaptations before scan starts
        if self.config.adaptive_mode and self.rule_engine and self.scan_session:
            try:
                # Create a mock session for initial adaptation (or use previous session data)
                adapted_config = self.rule_engine.apply_rules(
                    self.config,
                    self.scan_session if self.scan_session else {},
                    target=targets[0] if targets else None
                )
                # Update config with adaptations
                self.config = adapted_config
                logger.info("✅ Applied initial adaptation rules")
            except Exception as e:
                logger.warning(f"Initial rule application failed: {e}")
        
        # Call parent scan method
        return super().scan(targets, egg_record_id)
    
    def _evaluate_adaptation_rules(self, progress: ScanProgress):
        """Evaluate adaptation rules based on real-time progress"""
        if not self.config.adaptive_mode:
            return
        
        if not self.rule_engine or not self.scan_session:
            return
        
        try:
            # Apply rules based on current progress
            adapted_config = self.rule_engine.apply_rules(
                self.config,
                self.scan_session,
                target=self.scan_session.target if self.scan_session else None
            )
            
            # Check if any adaptations were made
            if adapted_config != self.config:
                # Apply rate limit changes immediately (can be done on-the-fly)
                if adapted_config.rate_limit != self.config.rate_limit:
                    self.adjust_rate_limit(int(adapted_config.rate_limit))
                    self._adaptations_applied.append({
                        'type': 'adjust_rate_limit',
                        'old_value': self.config.rate_limit,
                        'new_value': adapted_config.rate_limit,
                        'timestamp': timezone.now().isoformat(),
                    })
                
                # Update config
                self.config = adapted_config
                
        except Exception as e:
            logger.error(f"Error evaluating adaptation rules: {e}")
    
    def get_adaptations_applied(self) -> List[Dict[str, Any]]:
        """Get list of adaptations applied during this scan"""
        return self._adaptations_applied.copy()
