#!/usr/bin/env python3
"""
Surge Memory-Integrated Nuclei Bridge
=====================================

Real-time, memory-based Nuclei scanning with full AI awareness.
No subprocess calls, no file parsing - instant vulnerability access.

Author: EGO Revolution Team
Version: 1.0.0 - Memory Integration
"""

import ctypes
import json
import logging
from typing import Dict, List, Callable, Optional, Iterable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from sqlalchemy import or_

# Try to import database components (optional EgoLlama dependency)
try:
    from database import SessionLocal
    from vulnerability_models import NucleiTemplate
except ImportError:
    # Fallback for standalone mode
    SessionLocal = None
    NucleiTemplate = None

logger = logging.getLogger(__name__)

# Try to load Go bridge library
NUCLEI_BRIDGE_AVAILABLE = False
NUCLEI_BRIDGE = None

try:
    # Try to find the Go bridge library
    bridge_paths = [
        Path(__file__).parent / 'bridge' / 'libnuclei_bridge.so',
        Path(__file__).parent.parent.parent / 'surge' / 'nuclei' / 'bridge' / 'libnuclei_bridge.so',
        Path('/mnt/webapps-nvme/artificial_intelligence/personalities/security/surge/surge_nuclei_memory_bridge/libnuclei_bridge.so'),
    ]
    
    for bridge_path in bridge_paths:
        if bridge_path.exists():
            NUCLEI_BRIDGE = ctypes.CDLL(str(bridge_path))
            NUCLEI_BRIDGE_AVAILABLE = True
            logger.info(f"✅ Loaded Nuclei bridge from {bridge_path}")
            
            # Set up C function signatures for Go exports
            NUCLEI_BRIDGE.InitializeBridge.restype = ctypes.c_char_p
            NUCLEI_BRIDGE.StartScan.restype = ctypes.c_char_p
            NUCLEI_BRIDGE.GetScanState.restype = ctypes.c_char_p
            NUCLEI_BRIDGE.ControlScan.restype = ctypes.c_char_p
            NUCLEI_BRIDGE.CleanupBridge.restype = ctypes.c_char_p
            
            break
    
    if not NUCLEI_BRIDGE_AVAILABLE:
        logger.warning("⚠️  Nuclei bridge library not found - running in fallback mode")
        logger.warning("   Bridge will be available when Go library is compiled")
        
except Exception as e:
    logger.warning(f"⚠️  Could not load Nuclei bridge library: {e}")
    logger.warning("   Running in fallback mode without Go bridge")


class ScanControl(Enum):
    """AI-driven scan control actions"""
    PAUSE = "pause"
    RESUME = "resume"
    PRIORITIZE = "prioritize"
    SKIP_TARGET = "skip_target"
    ADJUST_RATE = "adjust_rate"
    SWITCH_TEMPLATE = "switch_template"


@dataclass
class NucleiEvent:
    """Real-time vulnerability event from Nuclei engine"""
    timestamp: str
    event_type: str  # "VULNERABILITY", "PROGRESS", "STATE_CHANGE"
    template_id: str
    severity: str
    target: str
    matched_at: str
    request: str
    response: str
    info: Dict = field(default_factory=dict)


@dataclass
class ScanState:
    """Current Nuclei scanning state"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    active_templates: List[str] = field(default_factory=list)
    current_target: str = ""
    progress_percent: float = 0.0
    vulns_found: List[NucleiEvent] = field(default_factory=list)
    queue_length: int = 0
    is_running: bool = True
    is_paused: bool = False
    scan_id: str = ""


class SurgeMemoryNucleiIntegration:
    """
    Memory-based Nuclei integration for Surge AI personality.
    
    ADVANTAGES over subprocess:
    - ⚡ Instant vulnerability streaming (<10ms latency vs 60s+)
    - 🧠 Full AI awareness of scan progress
    - 🎯 AI-driven scan control (pause/resume/prioritize)
    - 🔥 No file I/O overhead
    - 💾 Direct access to Nuclei's internal state
    - 🤖 AI can adapt scanning strategy in real-time
    """
    
    def __init__(self, surge_personality):
        """
        Initialize memory-based Nuclei integration
        
        Args:
            surge_personality: Surge AI personality instance
        """
        self.surge = surge_personality
        self.logger = logging.getLogger(__name__)
        
        # Current scan state (updated in real-time)
        self.scan_state: Optional[ScanState] = None
        
        # Event handlers
        self.on_vuln_found: List[Callable] = []
        self.on_scan_progress: List[Callable] = []
        self.on_state_change: List[Callable] = []
        
        # Register Go bridge callbacks if available
        if NUCLEI_BRIDGE_AVAILABLE:
            # Initialize the Go bridge first
            try:
                if hasattr(NUCLEI_BRIDGE, 'InitializeBridge'):
                    init_result = NUCLEI_BRIDGE.InitializeBridge()
                    if init_result:
                        init_str = init_result.decode('utf-8') if isinstance(init_result, bytes) else str(init_result)
                        self.logger.debug(f"Bridge init result: {init_str}")
                self._setup_callbacks()
                self.logger.info("⚡ Surge Memory Nuclei Bridge initialized with Go bridge")
            except Exception as e:
                self.logger.error(f"Failed to initialize Go bridge: {e}")
                self.logger.info("⚡ Surge Memory Nuclei Bridge initialized (fallback mode - Go bridge not available)")
        else:
            self.logger.info("⚡ Surge Memory Nuclei Bridge initialized (fallback mode - Go bridge not available)")
    
    def bridge_available(self) -> bool:
        """Check if Go bridge is available"""
        return NUCLEI_BRIDGE_AVAILABLE
    
    def _setup_callbacks(self):
        """Register Python callbacks with Go bridge"""
        if not NUCLEI_BRIDGE_AVAILABLE:
            self.logger.warning("Cannot setup callbacks - Go bridge not available")
            return
        
        try:
            # Callback signature for vulnerability found
            VULN_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
            
            def _on_vuln_found_callback(event_json: bytes):
                """Invoked instantly when Nuclei finds a vulnerability"""
                try:
                    event_dict = json.loads(event_json.decode('utf-8'))
                    event = NucleiEvent(**event_dict)
                    
                    # Immediate AI processing - no file parsing!
                    if hasattr(self.surge, 'process_vulnerability_instantly'):
                        self.surge.process_vulnerability_instantly(event)
                    
                    # Notify registered handlers
                    for handler in self.on_vuln_found:
                        try:
                            handler(event)
                        except Exception as e:
                            self.logger.error(f"Error in vulnerability handler: {e}")
                    
                except Exception as e:
                    self.logger.error(f"Error in vuln callback: {e}")
            
            # Register callback with Go bridge
            if hasattr(NUCLEI_BRIDGE, 'RegisterVulnCallback'):
                NUCLEI_BRIDGE.RegisterVulnCallback(VULN_CALLBACK(_on_vuln_found_callback))
                self.logger.debug("✅ Registered vulnerability callback")
            else:
                self.logger.warning("Go bridge does not have RegisterVulnCallback function")
        
        except Exception as e:
            self.logger.error(f"Failed to setup callbacks: {e}")
    
    def _load_templates_from_database(
        self,
        template_identifiers: Iterable[str],
        max_templates: int,
    ) -> Tuple[List[str], List[Dict[str, str]]]:
        """
        Resolve template identifiers into raw YAML content from the database.
        
        Args:
            template_identifiers: Iterable of template IDs or directory-style hints.
            max_templates: Maximum number of templates to return.
        
        Returns:
            List of dictionaries containing template metadata and raw YAML.
        """
        try:
            session = SessionLocal()
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error(f"❌ Unable to open database session for template retrieval: {exc}")
            return [], []
        
        results: List[Dict[str, str]] = []
        seen_ids: set[str] = set()
        remaining = max_templates if isinstance(max_templates, int) and max_templates > 0 else 200
        identifiers = [identifier.strip() for identifier in (template_identifiers or []) if identifier]
        
        def add_record(record: NucleiTemplate) -> None:
            if not record or not record.raw_content:
                return
            template_key = record.template_id or record.template_path
            if not template_key or template_key in seen_ids:
                return
            results.append(
                {
                    'template_id': record.template_id,
                    'template_path': record.template_path,
                    'severity': record.severity.value if hasattr(record.severity, 'value') else str(record.severity),
                    'content': record.raw_content,
                }
            )
            seen_ids.add(template_key)
        
        try:
            for identifier in identifiers:
                if len(results) >= remaining:
                    break
                
                normalized = identifier.strip()
                if not normalized:
                    continue
                
                query = session.query(NucleiTemplate).filter(NucleiTemplate.is_active.is_(True))
                limit_count = max(remaining - len(results), 1)
                
                if normalized.endswith('.yaml') or normalized.upper().startswith('CVE-'):
                    query = query.filter(
                        or_(
                            NucleiTemplate.template_id == normalized,
                            NucleiTemplate.template_path == normalized,
                        )
                    )
                else:
                    prefix = normalized.rstrip('/')
                    like_patterns = {f"{prefix}%", f"{prefix}/%", f"{normalized}%", f"{normalized}/%"}
                    filters = []
                    for pattern in like_patterns:
                        filters.append(NucleiTemplate.template_path.ilike(pattern))
                        filters.append(NucleiTemplate.template_id.ilike(pattern))
                    query = query.filter(or_(*filters))
                
                query = query.order_by(
                    NucleiTemplate.success_rate.desc(),
                    NucleiTemplate.usage_count.desc(),
                    NucleiTemplate.template_id.asc(),
                ).limit(limit_count)
                
                for record in query.all():
                    add_record(record)
                    if len(results) >= remaining:
                        break
            
            if not results:
                fallback_limit = remaining
                fallback_query = (
                    session.query(NucleiTemplate)
                    .filter(NucleiTemplate.is_active.is_(True), NucleiTemplate.raw_content.isnot(None))
                    .order_by(
                        NucleiTemplate.success_rate.desc(),
                        NucleiTemplate.usage_count.desc(),
                        NucleiTemplate.template_id.asc(),
                    )
                    .limit(fallback_limit)
                )
                for record in fallback_query.all():
                    add_record(record)
                    if len(results) >= remaining:
                        break
            
            if results:
                self.logger.info(f"📦 Prepared {len(results)} templates for in-memory scan (requested: {len(identifiers)})")
            else:
                self.logger.warning("⚠️ No templates retrieved from database for in-memory scan")
            raw_payloads: List[str] = []
            for item in results:
                content = item.get('content')
                if isinstance(content, bytes):
                    try:
                        content = content.decode('utf-8')
                    except UnicodeDecodeError:
                        content = content.decode('utf-8', errors='ignore')
                if isinstance(content, str):
                    trimmed = content.strip()
                    if trimmed:
                        raw_payloads.append(trimmed)
            metadata = [
                {k: v for k, v in item.items() if k != 'content'}
                for item in results
            ]
            return raw_payloads, metadata
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error(f"❌ Error loading templates from database: {exc}")
            return [], []
        finally:
            session.close()
    
    async def scan_domain_memory(self, domain: str, config: Dict = None) -> Dict:
        """
        Scan domain with instant memory access - NO subprocess!
        
        Args:
            domain: Target domain (will be converted to URL with scheme if needed)
            config: Scan configuration dict
            
        Returns:
            Scan results with real-time event streaming
        """
        # Ensure domain has scheme (Go bridge requires http:// or https://)
        target_url = domain
        if not domain.startswith(('http://', 'https://')):
            # Default to https:// for security
            target_url = f"https://{domain}"
            self.logger.debug(f"🔧 Added https:// scheme to domain: {domain} -> {target_url}")
        
        self.logger.info(f"🧠 Memory scan: {target_url}")
        
        if not NUCLEI_BRIDGE_AVAILABLE:
            self.logger.warning("Go bridge not available - falling back to subprocess")
            # Fallback to existing subprocess method if available
            if hasattr(self.surge, 'scan_domain'):
                return await self.surge.scan_domain(domain, config)
            else:
                return {
                    'domain': domain,
                    'memory_based': False,
                    'error': 'Go bridge not available and no fallback method',
                    'status': 'failed'
                }
        
        try:
            # Prepare configuration payload with sensible defaults
            config_payload = dict(config or {})
            scan_type = config_payload.get('scan_type', 'comprehensive')
            config_payload['scan_type'] = scan_type

            if 'templates' not in config_payload:
                if scan_type == 'critical_only':
                    config_payload['templates'] = ['http/cves/', 'http/vulnerabilities/']
                elif scan_type == 'web_only':
                    config_payload['templates'] = ['http/vulnerabilities/', 'http/exposures/', 'http/technologies/']
                elif scan_type == 'quick':
                    config_payload['templates'] = ['http/vulnerabilities/', 'http/exposures/']
                else:
                    config_payload['templates'] = ['http/cves/', 'http/vulnerabilities/', 'http/exposures/']

            if 'severities' not in config_payload:
                if scan_type == 'critical_only':
                    config_payload['severities'] = ['critical', 'high']
                else:
                    config_payload['severities'] = ['critical', 'high', 'medium', 'low', 'info']

            if 'max_templates' not in config_payload:
                if scan_type == 'critical_only':
                    config_payload['max_templates'] = 150
                elif scan_type == 'quick':
                    config_payload['max_templates'] = 120
                elif scan_type == 'web_only':
                    config_payload['max_templates'] = 180
                else:
                    config_payload['max_templates'] = 220
            
            template_identifiers = config_payload.get('templates', [])
            max_templates = config_payload.get('max_templates', 220)
            raw_templates, template_metadata = self._load_templates_from_database(template_identifiers, max_templates)
            config_payload['requested_templates'] = template_identifiers
            config_payload['raw_templates'] = raw_templates
            config_payload['template_metadata'] = template_metadata
            config_payload['template_count'] = len(raw_templates)
            config_payload.pop('templates', None)
            
            if not raw_templates:
                return {
                    'domain': domain,
                    'memory_based': True,
                    'status': 'failed',
                    'error': 'No templates available for memory scan',
                }

            # Start scan via Go bridge (no subprocess)
            if hasattr(NUCLEI_BRIDGE, 'StartScan'):
                # Prepare parameters - Go expects null-terminated C strings
                # Use target_url which has scheme (required by Go bridge)
                domain_cstr = ctypes.c_char_p(target_url.encode('utf-8'))
                config_json = json.dumps(config_payload)
                config_cstr = ctypes.c_char_p(config_json.encode('utf-8'))
                
                self.logger.info(f"🚀 Calling Go bridge StartScan for {target_url} with {len(raw_templates)} templates")
                
                # Call Go function
                result_ptr = NUCLEI_BRIDGE.StartScan(domain_cstr, config_cstr)
                
                # Parse result (assuming JSON string returned)
                if result_ptr:
                    result_str = result_ptr.decode('utf-8') if isinstance(result_ptr, bytes) else str(result_ptr)
                    try:
                        result_dict = json.loads(result_str)
                        if result_dict.get('success'):
                            self.logger.info(f"✅ StartScan returned: {result_dict.get('message', 'unknown')}")
                        else:
                            error_msg = result_dict.get('error', 'unknown error')
                            self.logger.error(f"❌ StartScan failed: {error_msg}")
                            return {
                                'domain': domain,
                                'memory_based': True,
                                'status': 'failed',
                                'error': error_msg,
                                'vulnerabilities': [],
                            }
                    except json.JSONDecodeError as e:
                        self.logger.error(f"❌ Failed to parse StartScan result: {e}, raw: {result_str[:200]}")
                        result_dict = {}
                else:
                    self.logger.warning("⚠️ StartScan returned NULL/0")
                    result_dict = {}
                
                # Scan runs in background goroutine - wait for it to complete
                # Poll scan state until scan completes to collect all vulnerabilities
                vulnerabilities = []
                max_wait_time = config_payload.get('timeout', 300)  # Default 5 minutes
                poll_interval = 0.5  # Poll every 500ms
                max_iterations = int(max_wait_time / poll_interval)
                scan_completed = False
                
                try:
                    import asyncio
                    # Give scan a moment to start
                    await asyncio.sleep(0.2)
                    
                    # Poll until scan completes or timeout
                    self.logger.debug(f"🔍 Starting poll loop for {domain} (max_iterations: {max_iterations}, poll_interval: {poll_interval}s)")
                    for iteration in range(max_iterations):
                        state = self.get_scan_state()
                        
                        if state:
                            # Check if scan is still running
                            is_running = getattr(state, 'is_running', True)
                            progress = getattr(state, 'progress_percent', 0.0)
                            total_reqs = getattr(state, 'total_requests', 0)
                            successful_reqs = getattr(state, 'successful_requests', 0)
                            
                            # Log scan state periodically
                            if iteration == 0 or iteration % 10 == 0:
                                self.logger.debug(f"   Poll {iteration}: is_running={is_running}, progress={progress}%, requests={successful_reqs}/{total_reqs}")
                            
                            # Scan is complete when is_running is False (set by Go bridge on completion)
                            is_complete = not is_running
                            
                            # Collect vulnerabilities as they're found
                            if hasattr(state, 'vulns_found'):
                                raw_vulns = state.vulns_found if hasattr(state, 'vulns_found') else []
                                raw_vulns = raw_vulns or []
                                
                                # Log vulnerability count if changed
                                if len(raw_vulns) != len(vulnerabilities):
                                    self.logger.info(f"   Found {len(raw_vulns)} vulnerabilities so far (iteration {iteration})")
                                
                                # Convert to vulnerability dict format
                                for v in raw_vulns:
                                    if isinstance(v, dict):
                                        vuln_dict = {
                                            'template-id': v.get('template_id', v.get('TemplateID', '')),
                                            'info': {
                                                'severity': v.get('severity', v.get('Severity', 'info')),
                                                'name': (v.get('info', {}) or {}).get('name', (v.get('Info', {}) or {}).get('name', '')),
                                                'description': (v.get('info', {}) or {}).get('description', (v.get('Info', {}) or {}).get('description', '')),
                                                'tags': (v.get('info', {}) or {}).get('tags', (v.get('Info', {}) or {}).get('tags', [])),
                                                'reference': (v.get('info', {}) or {}).get('reference', (v.get('Info', {}) or {}).get('reference', [])),
                                            },
                                            'matched-at': v.get('matched_at', v.get('MatchedAt', '')),
                                            'request': v.get('request', v.get('Request', '')),
                                            'response': v.get('response', v.get('Response', '')),
                                        }
                                        # Avoid duplicates
                                        if vuln_dict not in vulnerabilities:
                                            vulnerabilities.append(vuln_dict)
                                    else:
                                        # Handle NucleiEvent object
                                        vuln_dict = {
                                            'template-id': getattr(v, 'template_id', getattr(v, 'TemplateID', '')),
                                            'info': {
                                                'severity': getattr(v, 'severity', getattr(v, 'Severity', 'info')),
                                                'name': (getattr(v, 'info', {}) or {}).get('name', (getattr(v, 'Info', {}) or {}).get('name', '')),
                                                'description': (getattr(v, 'info', {}) or {}).get('description', (getattr(v, 'Info', {}) or {}).get('description', '')),
                                                'tags': (getattr(v, 'info', {}) or {}).get('tags', (getattr(v, 'Info', {}) or {}).get('tags', [])),
                                                'reference': (getattr(v, 'info', {}) or {}).get('reference', (getattr(v, 'Info', {}) or {}).get('reference', [])),
                                            },
                                            'matched-at': getattr(v, 'matched_at', getattr(v, 'MatchedAt', '')),
                                            'request': getattr(v, 'request', getattr(v, 'Request', '')),
                                            'response': getattr(v, 'response', getattr(v, 'Response', '')),
                                        }
                                        # Avoid duplicates
                                        if vuln_dict not in vulnerabilities:
                                            vulnerabilities.append(vuln_dict)
                            
                            # Check if scan completed
                            if is_complete:
                                scan_completed = True
                                elapsed_time = ((iteration + 1) * poll_interval) + 0.2  # Add initial sleep
                                self.logger.info(f"✅ Scan completed for {target_url}: found {len(vulnerabilities)} vulnerabilities (after {iteration+1} polls, {elapsed_time:.1f}s, {successful_reqs}/{total_reqs} requests)")
                                break
                        else:
                            self.logger.warning(f"   Poll {iteration}: No scan state returned")
                        
                        # Wait before next poll
                        await asyncio.sleep(poll_interval)
                    
                    if not scan_completed:
                        self.logger.warning(f"⚠️ Scan timeout for {target_url} after {max_wait_time}s (found {len(vulnerabilities)} vulnerabilities so far)")
                    
                except Exception as e:
                    self.logger.error(f"❌ Error polling scan state: {e}")
                    import traceback
                    self.logger.debug(traceback.format_exc())
                
                # Return results with collected vulnerabilities
                return {
                    'domain': domain,
                    'target_url': target_url,  # Include the URL that was actually scanned
                    'memory_based': True,
                    'real_time': True,
                    'status': 'completed' if scan_completed else 'timeout',
                    'vulnerabilities': vulnerabilities,
                    'template_metadata': template_metadata,  # Include template metadata
                    'template_count': len(template_metadata),
                    'vulnerability_count': len(vulnerabilities),
                    **result_dict
                }
            else:
                self.logger.error("Go bridge does not have StartScan function")
                return {
                    'domain': domain,
                    'memory_based': False,
                    'error': 'Go bridge missing required functions',
                    'status': 'failed'
                }
        
        except Exception as e:
            self.logger.error(f"Error in memory scan: {e}")
            return {
                'domain': domain,
                'memory_based': False,
                'error': str(e),
                'status': 'failed'
            }
    
    def get_scan_state(self) -> Optional[ScanState]:
        """Get current scan state instantly from Nuclei memory"""
        if not NUCLEI_BRIDGE_AVAILABLE:
            self.logger.warning("Cannot get scan state - Go bridge not available")
            return self.scan_state
        
        try:
            if hasattr(NUCLEI_BRIDGE, 'GetScanState'):
                # Call Go function
                result = NUCLEI_BRIDGE.GetScanState()
                
                if result:
                    # Parse JSON result
                    state_json = result.decode('utf-8') if isinstance(result, bytes) else str(result)
                    state_dict = json.loads(state_json)
                    
                    # Convert vulns to NucleiEvent objects
                    if 'vulns_found' in state_dict:
                        raw_vulns = state_dict.get('vulns_found') or []
                        state_dict['vulns_found'] = [
                            NucleiEvent(**v) if isinstance(v, dict) else v
                            for v in raw_vulns
                        ]
                    else:
                        state_dict['vulns_found'] = []
                    
                    if 'active_templates' not in state_dict or state_dict['active_templates'] is None:
                        state_dict['active_templates'] = []
                    
                    state_dict_clean = {
                        'total_requests': int(state_dict.get('total_requests') or 0),
                        'successful_requests': int(state_dict.get('successful_requests') or 0),
                        'failed_requests': int(state_dict.get('failed_requests') or 0),
                        'active_templates': state_dict.get('active_templates') or [],
                        'current_target': state_dict.get('current_target') or "",
                        'progress_percent': float(state_dict.get('progress_percent') or 0.0),
                        'vulns_found': state_dict.get('vulns_found') or [],
                        'queue_length': int(state_dict.get('queue_length') or 0),
                        'is_running': bool(state_dict.get('is_running', True)),
                        'is_paused': bool(state_dict.get('is_paused', False)),
                        'scan_id': str(state_dict.get('scan_id', '')),
                    }
                    
                    # Remove any unexpected fields that ScanState doesn't accept
                    state_dict_clean.pop('id', None)
                    
                    self.scan_state = ScanState(**state_dict_clean)
                    return self.scan_state
                else:
                    return self.scan_state
            
            else:
                self.logger.warning("Go bridge does not have GetScanState function")
                return self.scan_state
        
        except Exception as e:
            self.logger.error(f"Error getting scan state: {e}")
            return self.scan_state
    
    def control_scan(self, action: ScanControl, params: Dict = None) -> Dict:
        """
        AI-driven scan control - dynamically adjust scanning!
        
        Surge can now:
        - Pause scans when AI detects interesting vulnerabilities
        - Prioritize specific templates based on target analysis
        - Skip targets the AI determines are low-value
        - Adjust rate limits based on AI-driven strategy
        
        Args:
            action: ScanControl enum value
            params: Additional parameters for the action
            
        Returns:
            Result dictionary
        """
        if not NUCLEI_BRIDGE_AVAILABLE:
            self.logger.warning("Cannot control scan - Go bridge not available")
            return {'success': False, 'error': 'Go bridge not available'}
        
        try:
            if hasattr(NUCLEI_BRIDGE, 'ControlScan'):
                action_json = json.dumps({
                    'action': action.value,
                    'params': params or {}
                })
                action_bytes = action_json.encode('utf-8')
                
                result = NUCLEI_BRIDGE.ControlScan(action_bytes)
                
                if result:
                    result_json = result.decode('utf-8') if isinstance(result, bytes) else str(result)
                    return json.loads(result_json)
                else:
                    return {'success': False, 'error': 'No result from ControlScan'}
            
            else:
                self.logger.warning("Go bridge does not have ControlScan function")
                return {'success': False, 'error': 'Go bridge missing ControlScan function'}
        
        except Exception as e:
            self.logger.error(f"Error controlling scan: {e}")
            return {'success': False, 'error': str(e)}
    
    def subscribe_vulnerability(self, handler: Callable):
        """
        Subscribe to real-time vulnerability events
        
        Args:
            handler: Callable that receives NucleiEvent objects
        """
        if handler not in self.on_vuln_found:
            self.on_vuln_found.append(handler)
            self.logger.debug(f"Added vulnerability handler: {handler}")
    
    def ai_driven_template_selection(self, domain: str) -> List[str]:
        """
        Surge AI analyzes domain and selects optimal templates in real-time
        
        Uses Nuclei's template metadata for intelligent selection.
        
        Args:
            domain: Target domain to analyze
            
        Returns:
            List of recommended template IDs/paths
        """
        if not hasattr(self.surge, 'analyze_target'):
            self.logger.warning("Surge personality does not have analyze_target method")
            return []
        
        try:
            # Surge's AI logic
            analysis = self.surge.analyze_target(domain)
            
            # Intelligent template selection based on:
            # - Technology stack detection
            # - Historical vulnerability patterns
            # - Target criticality
            # - Current security landscape
            
            if hasattr(self.surge, 'recommend_templates'):
                return self.surge.recommend_templates(analysis)
            else:
                # Fallback: return empty list or default templates
                self.logger.warning("Surge personality does not have recommend_templates method")
                return []
        
        except Exception as e:
            self.logger.error(f"Error in AI-driven template selection: {e}")
            return []

