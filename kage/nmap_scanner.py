#!/usr/bin/env python3
"""
Kage Fast Port Scanner - Creates Nmap Entries
=============================================

Migrated from EgoWebs1 enhanced_kage_service.py
Refactored for webApps ego system with parallel threading

Kage specializes in:
- Fast socket-based port scanning  
- Service detection and version extraction
- Creating Nmap model entries for Bugsy to process
- Parallel threading (32 workers) for faster scanning

Note: Uses CPU threading (ThreadPoolExecutor), not GPU compute.
Network I/O operations cannot utilize GPU - threading is appropriate here.

Author: EGO Revolution - Kage (Shadow Scout)
Version: 2.0.0 - Parallel Threading
"""

import socket
import logging
import time
import json
import warnings
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Suppress urllib3 SSL warnings - we'll detect and report SSL issues separately
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

from artificial_intelligence.personalities.reconnaissance import EGOQT_SRC  # noqa: F401

try:
    from ai_system.error_reporting_to_l import KageErrorReporter
except ImportError:
    # Optional error reporting - create dummy class if not available
    class KageErrorReporter:
        @staticmethod
        def report_error(error, context=None):
            logger.error(f"Error (no reporter): {error}")
import sys
import os

# Setup logging first (before Django setup)
import logging
logger = logging.getLogger(__name__)

# Setup logging first (before Django setup)
logger = logging.getLogger(__name__)

# Setup Django (optional - only if Django is available)
try:
    # Try kage-pro Django settings first
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
    import django
    django.setup()
    DJANGO_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    # Fallback to EgoQT settings if available
    try:
        sys.path.insert(0, '/mnt/webapps-nvme')
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EgoQT.src.django_bridge.settings')
        import django
        django.setup()
        DJANGO_AVAILABLE = True
    except (ImportError, ModuleNotFoundError):
        DJANGO_AVAILABLE = False
        logger.warning("Django not available - some features will be disabled")

from django.apps import apps
from django.db import connections
from django.utils import timezone

logger = logging.getLogger(__name__)


class KageNmapScanner:
    """
    Kage's fast port scanning service.
    Creates real Nmap entries in the database for Bugsy to fingerprint.
    """
    
    def __init__(self, parallel_enabled: bool = True):
        """
        Initialize Kage's port scanner.
        
        Args:
            parallel_enabled: Use parallel threading (32 workers vs 10)
        """
        self.parallel_enabled = parallel_enabled
        
        # Kage's fast scanning configuration
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        self.socket_timeout = 3.0
        self.max_workers = 32 if self.parallel_enabled else 10
        
        # DNS validation helper
        self._dns_timeout = 3.0
        
        # IP ownership validation (will be set during scan)
        self._last_ip_ownership = None
        
        # Store last Nmap results for database storage
        self._last_nmap_results = None
        
        # Service detection patterns
        self.service_patterns = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            445: 'smb',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            8080: 'http-proxy',
            8443: 'https-alt'
        }
        
        # Initialize Tor proxy support (optional)
        self.tor_enabled = False
        try:
            from artificial_intelligence.personalities.reconnaissance.tor_proxy import get_tor_proxy
            self.tor_proxy = get_tor_proxy(enabled=True)
            self.tor_enabled = self.tor_proxy.is_available()
            if self.tor_enabled:
                logger.info("🔒 Tor proxy enabled for anonymous scanning")
        except Exception as e:
            logger.debug(f"Tor proxy not available: {e}")
            self.tor_proxy = None
        
        # Load Nmap knowledge base
        self.nmap_knowledge = self._load_nmap_knowledge()
        
        # Initialize Nmap argument inference engine
        try:
            from artificial_intelligence.personalities.reconnaissance.kage.nmap_argument_inference import (
                NmapArgumentInference, ScanScenario
            )
            self.argument_inference = NmapArgumentInference(knowledge_base=self.nmap_knowledge)
            logger.info(f"🧠 Nmap argument inference engine initialized ({len(self.argument_inference.arguments)} arguments available)")
        except Exception as e:
            logger.warning(f"⚠️  Argument inference not available: {e}")
            self.argument_inference = None
        
        # Initialize WAF fingerprinting and learning
        try:
            from artificial_intelligence.personalities.reconnaissance.kage.waf_fingerprinting import WAFFingerprinter
            from artificial_intelligence.personalities.reconnaissance.kage.scan_learning_service import ScanLearningService
            from artificial_intelligence.personalities.reconnaissance.kage.advanced_host_discovery import AdvancedHostDiscovery
            
            self.waf_fingerprinter = WAFFingerprinter()
            self.learning_db = ScanLearningService(
                redis_host='localhost',  # TODO: Get from config
                redis_port=6379,
                redis_db=0
            )
            self.host_discovery = AdvancedHostDiscovery(timeout=self.socket_timeout)
            logger.info("🛡️  WAF fingerprinting and learning enabled")
        except Exception as e:
            logger.warning(f"⚠️  WAF fingerprinting not available: {e}")
            self.waf_fingerprinter = None
            self.learning_db = None
            self.host_discovery = None
        
        # Initialize SSL certificate analyzer
        try:
            from artificial_intelligence.personalities.reconnaissance.kage.ssl_certificate_analyzer import SSLCertificateAnalyzer
            self.ssl_analyzer = SSLCertificateAnalyzer()
            logger.info("🔒 SSL certificate analysis enabled")
        except Exception as e:
            logger.warning(f"⚠️  SSL analyzer not available: {e}")
            self.ssl_analyzer = None
        
        # Performance optimization: DNS resolution cache
        self._dns_cache = {}
        self._dns_cache_ttl = 300  # 5 minutes
        self._dns_cache_timestamps = {}
        
        # Performance optimization: Port scan result cache (short-lived)
        self._port_scan_cache = {}
        self._port_scan_cache_ttl = 60  # 1 minute
        self._port_scan_cache_timestamps = {}
        
        # Initialize LLM enhancer for intelligent strategy selection
        self.llm_enabled = False
        try:
            from artificial_intelligence.personalities.reconnaissance.llm_enhancer import get_llm_enhancer
            self.llm_enhancer = get_llm_enhancer(enabled=True)
            self.llm_enabled = self.llm_enhancer.is_available()
            if self.llm_enabled:
                logger.info("🧠 LLM enhancer enabled for intelligent scan strategy")
        except Exception as e:
            logger.debug(f"LLM enhancer not available: {e}")
            self.llm_enhancer = None
        
        logger.info(f"⚡ Kage scanner initialized ({'Parallel' if self.parallel_enabled else 'Sequential'} mode, {self.max_workers} workers, Tor: {'enabled' if self.tor_enabled else 'disabled'}, LLM: {'enabled' if self.llm_enabled else 'disabled'})")
        if self.nmap_knowledge:
            logger.info(f"📚 Loaded Nmap knowledge base ({self.nmap_knowledge.get('total_pages', 0)} pages)")
    
    def scan_egg_record(self, egg_record_id: str, ports: List[int] = None, scan_type: str = 'kage_port_scan', eggrecord_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan an EggRecord and create Nmap entries.
        
        Args:
            egg_record_id: EggRecord UUID string to scan
            ports: List of ports to scan (defaults to common ports)
            scan_type: Type of scan (default: 'kage_port_scan', use 'jade_port_scan' for Jade)
            eggrecord_data: Optional pre-fetched eggrecord data (avoids Django model lookup)
        
        Wrapped in try-except to catch and log the exact location of 'int has no len()' errors.
        """
        try:
            return self._scan_egg_record_impl(egg_record_id, ports, scan_type, eggrecord_data)
        except TypeError as e:
            if "'int' has no len()" in str(e) or "object of type 'int' has no len()" in str(e):
                import traceback
                logger.error(f"❌ CRITICAL: len() called on int in scan_egg_record")
                logger.error(f"   Error: {e}")
                logger.error(f"   Full traceback:\n{traceback.format_exc()}")
                return {
                    'success': False,
                    'error': f'TypeError: {e}',
                    'target': 'unknown',
                }
            raise
    
    def _scan_egg_record_impl(self, egg_record_id: str, ports: List[int] = None, scan_type: str = 'kage_port_scan', eggrecord_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Internal implementation of scan_egg_record.
        
        Args:
            egg_record_id: EggRecord UUID string to scan
            ports: List of ports to scan (defaults to common ports)
            scan_type: Type of scan (default: 'kage_port_scan', use 'jade_port_scan' for Jade)
            eggrecord_data: Optional pre-fetched eggrecord data (avoids Django model lookup)
            
        Returns:
            Scan results summary
        """
        # Get full EggRecord data using Django or raw SQL
        target = None
        egg_record_data_dict = {}  # Store full eggrecord data
        egg_record = None  # Initialize to avoid UnboundLocalError
        
        # If eggrecord_data is provided (from daemon API), use it directly
        if eggrecord_data:
            egg_record_data_dict = eggrecord_data
            target = eggrecord_data.get('subDomain') or eggrecord_data.get('domainname')
            logger.debug(f"Using provided eggrecord data for {target}")
        else:
            # Try to fetch from Django models or raw SQL
            try:
                EggRecord = apps.get_model('customer_eggs_eggrecords_general_models', 'EggRecord')
                try:
                    egg_record = EggRecord.objects.get(id=egg_record_id)
                    target = egg_record.subDomain or egg_record.domainname
                    # Store full eggrecord data
                    egg_record_data_dict = {
                        'id': str(egg_record.id),
                        'subDomain': egg_record.subDomain,
                        'domainname': egg_record.domainname,
                        'alive': egg_record.alive,
                        'created_at': egg_record.created_at,
                        'updated_at': egg_record.updated_at,
                    }
                except (AttributeError, Exception) as e:
                    # Django ORM not available, use raw SQL
                    logger.debug(f"Django ORM not available, using raw SQL: {e}")
                    try:
                        db = connections['customer_eggs']
                        with db.cursor() as cursor:
                            cursor.execute("""
                                SELECT id, "subDomain", domainname, alive, created_at, updated_at
                                FROM customer_eggs_eggrecords_general_models_eggrecord
                                WHERE id = %s
                                LIMIT 1
                            """, [egg_record_id])
                            row = cursor.fetchone()
                            if row:
                                columns = [col[0] for col in cursor.description]
                                egg_record_data_dict = dict(zip(columns, row))
                                target = egg_record_data_dict.get('subDomain') or egg_record_data_dict.get('domainname')
                            else:
                                logger.error(f"❌ EggRecord {egg_record_id} not found")
                                return {
                                    'success': False,
                                    'error': 'EggRecord not found',
                                    'target': egg_record_id
                                }
                    except Exception as db_error:
                        logger.error(f"Database error fetching eggrecord: {db_error}")
                        return {
                            'success': False,
                            'error': f'Database error: {db_error}',
                            'target': egg_record_id
                        }
            except (LookupError, ValueError):
                # Model not found, use raw SQL
                db = connections['customer_eggs']
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, "subDomain", domainname, alive, created_at, updated_at
                        FROM customer_eggs_eggrecords_general_models_eggrecord
                        WHERE id = %s
                        LIMIT 1
                    """, [egg_record_id])
                    row = cursor.fetchone()
                    if row:
                        columns = [col[0] for col in cursor.description]
                        egg_record_data_dict = dict(zip(columns, row))
                        target = egg_record_data_dict.get('subDomain') or egg_record_data_dict.get('domainname')
                    else:
                        logger.error(f"❌ EggRecord {egg_record_id} not found")
                        return {
                            'success': False,
                            'error': 'EggRecord not found',
                            'target': egg_record_id
                        }
        
        if not target:
            logger.error(f"❌ Could not determine target for EggRecord {egg_record_id}")
            return {
                'success': False,
                'error': 'Could not determine target',
                'target': egg_record_id
            }
        
        # Log full eggrecord context for debugging
        logger.debug(f"📋 Scanning eggrecord: {egg_record_data_dict}")
        # Ensure ports_to_scan is always a list
        if ports is None:
            ports_to_scan = self.default_ports
        elif isinstance(ports, list):
            ports_to_scan = ports
        elif isinstance(ports, (int, str)):
            # Single port passed as int or string - convert to list
            ports_to_scan = [int(ports)]
            logger.debug(f"Converted single port {ports} to list: {ports_to_scan}")
        else:
            # Fallback to default ports
            logger.warning(f"⚠️  Invalid ports type {type(ports)}, using default ports")
            ports_to_scan = self.default_ports
        
        # Advanced host discovery for WAF detection (before strategy selection)
        waf_detection = self._advanced_host_discovery_waf_detection(target)
        waf_detected = waf_detection.get('waf_detected', False)
        waf_type = waf_detection.get('waf_type')
        
        if waf_detected:
            logger.warning(f"🛡️  WAF detected: {waf_type or 'unknown'}")
        
        # Use knowledge base and inference engine to optimize scan strategy
        strategy = self.get_optimal_scan_strategy(
            target, 
            ports_to_scan,
            waf_detected=waf_detected,
            waf_type=waf_type,
            stealth_required=False,  # Can be made configurable
            speed_priority='normal'  # Can be made configurable
        )
        
        # Enhance strategy with LLM if available
        if self.llm_enabled and self.llm_enhancer:
            try:
                import asyncio
                # Build target info for LLM
                target_info = {
                    'domain_pattern': target,
                    'known_ports': ports_to_scan,
                    'waf_detected': waf_detected,
                    'waf_type': waf_type,
                    'ip_address': ip_address
                }
                
                # Try to get LLM recommendation (async, but we're in sync context)
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                llm_recommendation = loop.run_until_complete(
                    self.llm_enhancer.analyze_scan_strategy(target, target_info)
                )
                
                if llm_recommendation and llm_recommendation.confidence > 0.6:
                    # Merge LLM recommendations with existing strategy
                    if llm_recommendation.nmap_arguments:
                        # LLM provided arguments - use them if confidence is high
                        strategy['nmap_arguments'] = llm_recommendation.nmap_arguments
                        strategy['reasoning'] = f"LLM-enhanced: {llm_recommendation.reasoning}"
                        strategy['ml_used'] = True
                        logger.info(f"🧠 LLM recommended strategy (confidence: {llm_recommendation.confidence:.2f})")
                        logger.debug(f"   Reasoning: {llm_recommendation.reasoning[:200]}")
                elif llm_recommendation:
                    # Low confidence - use as supplement
                    logger.debug(f"🧠 LLM provided alternative strategy (confidence: {llm_recommendation.confidence:.2f})")
                    if 'alternatives' not in strategy:
                        strategy['alternatives'] = []
                    strategy['alternatives'].extend(llm_recommendation.alternative_strategies)
            except Exception as e:
                logger.debug(f"LLM strategy enhancement failed (non-fatal): {e}")
                # Continue with rule-based strategy
        
        if strategy.get('nmap_arguments'):
            # Ensure nmap_arguments is a list
            nmap_args = strategy['nmap_arguments']
            if isinstance(nmap_args, list):
                logger.info(f"🧠 Inference engine recommended {len(nmap_args)} Nmap arguments")
            else:
                logger.debug(f"🧠 Inference engine recommended arguments (non-list type: {type(nmap_args)})")
            if strategy.get('reasoning'):
                logger.debug(f"   Reasoning: {strategy['reasoning']}")
        
        if strategy.get('advice'):
            # Ensure advice is a list
            advice = strategy['advice']
            if isinstance(advice, list):
                logger.info(f"📚 Using Nmap knowledge: {len(advice)} techniques available")
            else:
                logger.debug(f"📚 Using Nmap knowledge (non-list type: {type(advice)})")
        
        # Adapt strategy for WAF evasion if needed
        if waf_detected:
            strategy = self._adapt_strategy_for_waf(strategy, waf_detection)
            # Ensure strategy['ports'] is still a list after adaptation
            if 'ports' in strategy and not isinstance(strategy['ports'], list):
                logger.warning(f"⚠️  Strategy ports is not a list after WAF adaptation (type: {type(strategy['ports'])}), using ports_to_scan")
                strategy['ports'] = ports_to_scan
        
        # Ensure ports_to_scan is still a list before using len()
        if not isinstance(ports_to_scan, list):
            logger.error(f"❌ ports_to_scan is not a list (type: {type(ports_to_scan)}), using default ports")
            ports_to_scan = self.default_ports
        
        logger.info(f"⚡ Kage scanning {target} ({len(ports_to_scan)} ports)")
        
        start_time = time.time()
        
        # DNS pre-validation with detailed error reporting
        dns_check = self._validate_dns(target)
        if dns_check and not dns_check.get('resolved', True):
            logger.warning(f"⚠️  DNS resolution failed for {target}: {dns_check.get('error', 'Unknown error')} - proceeding anyway")
            # Record DNS failure in learning database but continue scanning
            if self.learning_db:
                try:
                    self.learning_db.record_scan_result(
                        target=target,
                        technique_used='dns_check',
                        ports_scanned=[],
                        open_ports_found=0,
                        waf_detected=False,
                        scan_duration=0,
                        egg_record_id=egg_record_id,
                        scan_results={'dns_error': dns_check.get('error')}
                    )
                except Exception:
                    pass
            # Continue with scan even if DNS fails (might be IP address)
        
        # Get IP address for scanning (IPv4 and IPv6)
        ip_address = None
        ipv6_addresses = []
        
        try:
            # Try IPv4 first
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            # If DNS fails, try using target as IP directly
            try:
                # Check if it's already an IPv4 address
                ipaddress.IPv4Address(target)
                ip_address = target
            except ValueError:
                # Check if it's an IPv6 address
                try:
                    ipaddress.IPv6Address(target)
                    ip_address = target
                    logger.info(f"🌐 IPv6 address detected: {target}")
                except ValueError:
                    logger.warning(f"⚠️  Using target as-is (DNS resolution failed): {target}")
                    ip_address = target
        
        # Try to get IPv6 addresses for prediction
        try:
            # Get all address info (IPv4 and IPv6)
            # Note: socket is already imported at the top of the file
            addr_info = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for info in addr_info:
                addr = info[4][0]
                try:
                    ipaddress.IPv6Address(addr)
                    if addr not in ipv6_addresses:
                        ipv6_addresses.append(addr)
                except ValueError:
                    pass
        except Exception as e:
            logger.debug(f"IPv6 address discovery error: {e}")
        
        # IPv6 prediction: Generate candidate addresses if we have IPv6 addresses
        ipv6_candidates = []
        if ipv6_addresses:
            try:
                from artificial_intelligence.personalities.reconnaissance.kage.ipv6_prediction import get_ipv6_predictor
                
                predictor = get_ipv6_predictor()
                
                # Analyze patterns from known IPv6 addresses
                if len(ipv6_addresses) >= 2:
                    # We have multiple addresses - analyze patterns
                    pattern_analysis = predictor.analyze_patterns(ipv6_addresses)
                    
                    # Extract network prefix (assume /64)
                    if ipv6_addresses:
                        try:
                            network = ipaddress.IPv6Network(f"{ipv6_addresses[0]}/64", strict=False)
                            prefix = str(network.network_address) + "/64"
                            
                            # Generate candidate addresses
                            ipv6_candidates = predictor.generate_candidates(
                                prefix,
                                pattern_analysis,
                                max_candidates=50  # Limit to 50 candidates
                            )
                            
                            if ipv6_candidates:
                                logger.info(f"🔮 IPv6 prediction: Generated {len(ipv6_candidates)} candidate addresses from {len(ipv6_addresses)} seed addresses")
                        except Exception as e:
                            logger.debug(f"IPv6 candidate generation error: {e}")
                elif len(ipv6_addresses) == 1:
                    # Single address - try sequential prediction
                    ipv6_candidates = predictor.predict_sequential(ipv6_addresses[0], count=20)
                    if ipv6_candidates:
                        logger.info(f"🔮 IPv6 sequential prediction: Generated {len(ipv6_candidates)} candidate addresses")
            except ImportError:
                logger.debug("IPv6 predictor not available")
            except Exception as e:
                logger.debug(f"IPv6 prediction error: {e}")
        
        # Validate IP ownership BEFORE scanning to optimize port selection
        try:
            from artificial_intelligence.personalities.reconnaissance.kage.ip_ownership_validator import get_ip_validator
            
            ip_validator = get_ip_validator()
            ownership = ip_validator.validate_ip_ownership(ip_address)
            
            # Log ownership information
            if ownership.get('owned_by') != 'unknown':
                logger.info(f"🏢 IP Ownership: {ownership['owned_by']} (ASN: {ownership.get('asn', 'N/A')}, Type: {ownership.get('type', 'unknown')})")
                if ownership.get('note'):
                    logger.debug(f"   Note: {ownership['note']}")
            
            # Check if we should skip this scan
            should_skip, skip_reason = ip_validator.should_skip_scan(ip_address)
            if should_skip:
                logger.info(f"⏭️  Skipping scan: {skip_reason}")
                return {
                    'success': True,
                    'skipped': True,
                    'reason': skip_reason,
                    'ip_ownership': ownership,
                    'target': target,
                    'ip_address': ip_address,
                    'open_ports': [],
                    'scan_duration': 0
                }
            
            # Filter ports based on ownership expectations
            original_port_count = len(ports_to_scan)
            ports_to_scan = ip_validator.filter_ports_by_ownership(ip_address, ports_to_scan)
            
            if len(ports_to_scan) < original_port_count:
                logger.info(f"🔍 Port filtering: {original_port_count} → {len(ports_to_scan)} ports based on IP ownership")
            
            # Store ownership info for later use
            self._last_ip_ownership = ownership
            
        except ImportError:
            logger.debug("IP ownership validator not available - skipping ownership checks")
        except Exception as e:
            logger.warning(f"⚠️  IP ownership validation error: {e} - continuing with scan")
        
        # Final safety check before scanning
        if not isinstance(ports_to_scan, list):
            logger.error(f"❌ CRITICAL: ports_to_scan is not a list before scanning (type: {type(ports_to_scan)}, value: {ports_to_scan})")
            ports_to_scan = self.default_ports
        
        # Execute Nmap if WAF detected or if strategy recommends it
        nmap_used = False
        nmap_results = None
        if waf_detected and strategy.get('nmap_arguments'):
            logger.info(f"🛡️  WAF detected - executing Nmap with bypass arguments")
            nmap_results = self._execute_nmap_with_techniques(
                target, ip_address, ports_to_scan, strategy, waf_detection
            )
            if nmap_results and nmap_results.get('success'):
                nmap_used = True
                scan_results = nmap_results.get('scan_results', [])
                logger.info(f"✅ Nmap scan successful: {len([r for r in scan_results if r.get('status') == 'open'])} open ports")
                # Store nmap_results for later use in database storage
                self._last_nmap_results = nmap_results
            else:
                logger.warning(f"⚠️  Nmap scan failed or incomplete, falling back to socket scanning")
                self._last_nmap_results = None
        
        # Fallback to socket-based scanning if Nmap not used or failed
        if not nmap_used:
            if self.parallel_enabled:
                scan_results = self._parallel_scan(ip_address, ports_to_scan, target)
            else:
                scan_results = self._sequential_scan(ip_address, ports_to_scan, target)
        
        # Update egg record with scan results
        open_ports = []
        for result in scan_results:
            if result['status'] == 'open':
                open_ports.append(result)
        
        # Analyze SSL certificates for HTTPS ports (443, 8443)
        ssl_analysis = {}
        if self.ssl_analyzer:
            try:
                https_ports = [r for r in open_ports if r.get('port') in [443, 8443]]
                if https_ports:
                    # Analyze SSL for the first HTTPS port found
                    https_port = https_ports[0]
                    ssl_result = self.ssl_analyzer.analyze_certificate(target, https_port['port'])
                    ssl_analysis = {
                        'ssl_enabled': ssl_result.get('ssl_enabled', False),
                        'certificate_valid': ssl_result.get('certificate_valid', False),
                        'certificate_errors': ssl_result.get('certificate_errors', []),
                        'expired': ssl_result.get('expired', False),
                        'self_signed': ssl_result.get('self_signed', False),
                        'days_until_expiry': ssl_result.get('days_until_expiry'),
                        'tls_version': ssl_result.get('tls_version'),
                        'certificate_info': ssl_result.get('certificate_info', {})
                    }
                    
                    if ssl_analysis.get('certificate_errors'):
                        logger.info(f"🔒 SSL issues detected for {target}: {', '.join(ssl_analysis['certificate_errors'])}")
                    elif ssl_analysis.get('certificate_valid'):
                        logger.debug(f"🔒 SSL certificate valid for {target}")
            except Exception as e:
                logger.debug(f"SSL analysis error (non-fatal): {e}")
        
        # Create Nmap scan entries for Bugsy
        nmap_entries_created = 0
        nmap_scan_id = None
        if open_ports:
            # Create Nmap entries using raw SQL (table: customer_eggs_eggrecords_general_models_nmap)
            try:
                import uuid
                import hkagelib
                import json
                
                db = connections['customer_eggs']
                with db.cursor() as cursor:
                    # Create one Nmap entry with all open ports in open_ports JSONB field
                    # Table structure: id, md5, target, scan_type, scan_stage, scan_status, port, service_name, service_version, open_ports, scan_command, name, hostname, date, record_id_id
                    
                    # Generate MD5 hkage for this scan
                    scan_data = f"{target}:{ip_address}:{datetime.now().isoformat()}"
                    md5_hkage = hkagelib.md5(scan_data.encode()).hexdigest()
                    
                    # Get Nmap arguments and scan type from nmap_results if available
                    nmap_args_full = ''
                    scan_type_from_nmap = scan_type
                    # Check both nmap_results parameter and instance variable
                    nmap_data = nmap_results if nmap_results else getattr(self, '_last_nmap_results', None)
                    if nmap_data and nmap_data.get('nmap_xml_parsed'):
                        nmap_args_full = nmap_data.get('nmap_args', '')
                        scan_type_from_nmap = nmap_data.get('scan_type', scan_type)
                    
                    # Prepare open_ports JSONB data with COMPREHENSIVE Nmap data
                    ports_json = []
                    for result in open_ports:
                        port_data = {
                            'port': result['port'],
                            'protocol': result.get('protocol', 'tcp'),
                            'state': 'open',
                            'state_reason': result.get('state_reason'),  # NEW: Packet reason
                            'service': result.get('service_name', ''),
                            'version': result.get('service_version', ''),
                            'product': result.get('service_product', ''),  # NEW: Product name
                            'extrainfo': result.get('service_extrainfo', ''),  # NEW: Additional details
                            'devicetype': result.get('service_devicetype', ''),  # NEW: Device type
                            'cpe': result.get('service_cpe', []),  # NEW: CPE strings (CRITICAL)
                            'banner': result.get('service_info', ''),
                            'scripts': result.get('scripts', [])  # NEW: NSE script output
                        }
                        # Add SSL certificate info for HTTPS ports
                        if result.get('port') in [443, 8443] and ssl_analysis:
                            port_data['ssl_certificate'] = ssl_analysis
                        ports_json.append(port_data)
                    
                    # Generate Nmap scan UUID
                    nmap_scan_id = str(uuid.uuid4())
                    
                    # Create Nmap entry with extended data
                    scan_command = nmap_args_full if nmap_args_full else f'nmap -p {",".join(str(r["port"]) for r in open_ports)} {target}'
                    cursor.execute("""
                        INSERT INTO customer_eggs_eggrecords_general_models_nmap (
                            id, md5, target, scan_type, scan_stage, scan_status, 
                            port, service_name, service_version, open_ports, 
                            scan_command, name, hostname, date, record_id_id, created_at, updated_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                    """, [
                        nmap_scan_id,
                        md5_hkage,
                        target,
                        scan_type_from_nmap,  # Use actual scan type from Nmap
                        'completed',
                        'completed',
                        str(open_ports[0]['port']) if open_ports else '',  # First port as primary
                        open_ports[0].get('service_name', '') if open_ports else '',
                        open_ports[0].get('service_version', '') if open_ports else '',
                        json.dumps(ports_json),  # Now includes CPE, extrainfo, devicetype, scripts
                        scan_command,  # Store exact Nmap command for heuristics
                        target,
                        target,
                        timezone.now(),
                        str(egg_record_id),
                        timezone.now(),
                        timezone.now()
                    ])
                    db.commit()  # Commit the transaction to persist Nmap entries
                    nmap_entries_created = 1
                    
                    # Create TechnologyFingerprint records from CPE strings
                    fingerprint_count = 0
                    for result in open_ports:
                        cpe_list = result.get('service_cpe', [])
                        if cpe_list:
                            for cpe_string in cpe_list:
                                fingerprint_id = self._create_technology_fingerprint_from_cpe(
                                    str(egg_record_id),
                                    nmap_scan_id,
                                    cpe_string,
                                    result['port'],
                                    result.get('service_name', '')
                                )
                                if fingerprint_id:
                                    fingerprint_count += 1
                    
                    if fingerprint_count > 0:
                        logger.info(f"  ✅ Created {fingerprint_count} TechnologyFingerprint records from CPE")
                    
                    # Store Nmap arguments for heuristics learning
                    if nmap_args_full and self.learning_db:
                        try:
                            from ryu_app.eggrecords_models import CalculatedHeuristicsRule
                            
                            # Parse Nmap arguments into structured format
                            nmap_args_list = self._parse_nmap_args_to_list(nmap_args_full)
                            
                            # Create target pattern (domain or IP pattern)
                            target_pattern = target.split('.')[-2] + '.' + target.split('.')[-1] if '.' in target else target
                            
                            # Create or update heuristics rule
                            rule_pattern = f"{target_pattern}:{scan_type_from_nmap}"
                            rule, created = CalculatedHeuristicsRule.objects.using('eggrecords').update_or_create(
                                rule_pattern=rule_pattern,
                                defaults={
                                    'nmap_arguments': nmap_args_list,  # Store for learning
                                    'recommended_technique': scan_type_from_nmap,
                                    'confidence_score': 0.8,
                                    'sample_count': 1,
                                    'last_updated': timezone.now()
                                }
                            )
                            
                            if created:
                                logger.info(f"  ✅ Created heuristics rule: {rule_pattern}")
                            else:
                                # Update sample count
                                rule.sample_count += 1
                                rule.last_updated = timezone.now()
                                rule.save(using='eggrecords')
                                logger.debug(f"  📚 Updated heuristics rule: {rule_pattern} (samples: {rule.sample_count})")
                        except Exception as e:
                            logger.debug(f"Failed to store heuristics rule: {e}")
                
                if nmap_entries_created > 0:
                    logger.info(f"  ✅ Created {nmap_entries_created} Nmap entry with {len(open_ports)} ports for Bugsy")
            except Exception as e:
                logger.warning(f"Could not create Nmap entries: {e}, using fallback")
                import traceback
                logger.debug(f"Nmap entry creation traceback: {traceback.format_exc()}")
                import traceback
                traceback.print_exc()
                # Fallback: Store in open_ports JSON field on egg_record
                import json
                try:
                    db = connections['customer_eggs']
                    with db.cursor() as cursor:
                        cursor.execute("""
                            SELECT open_ports FROM customer_eggs_eggrecords_general_models_eggrecord
                            WHERE id = %s
                        """, [str(egg_record_id)])
                        row = cursor.fetchone()
                        current_ports = json.loads(row[0]) if row and row[0] else []
                        
                        new_ports = [{
                            'port': result['port'],
                            'protocol': result.get('protocol', 'tcp'),
                            'service': result.get('service_name', ''),
                            'version': result.get('service_version', ''),
                            'state': 'open',
                            'scanned_at': datetime.now().isoformat()
                        } for result in open_ports]
                        
                        # Merge with existing ports
                        existing_ports = {port.get('port', port.get('port')): port for port in current_ports if isinstance(port, dict)}
                        for new_port in new_ports:
                            existing_ports[new_port['port']] = new_port
                        
                        updated_ports = list(existing_ports.values())
                        
                        # Update
                        cursor.execute("""
                            UPDATE customer_eggs_eggrecords_general_models_eggrecord
                            SET open_ports = %s
                            WHERE id = %s
                        """, [json.dumps(updated_ports), str(egg_record_id)])
                        db.commit()  # Commit the fallback update
                    
                    logger.info(f"  ✅ Updated egg record with {len(open_ports)} open ports (JSON fallback)")
                except Exception as e2:
                    logger.error(f"Fallback also failed: {e2}")
        
        duration = time.time() - start_time
        
        # Use LLM to interpret scan results if available
        llm_analysis = None
        if self.llm_enabled and self.llm_enhancer:
            try:
                import asyncio
                # Build scan results summary for LLM
                scan_results_summary = {
                    'target': target,
                    'ip_address': ip_address,
                    'open_ports': open_ports,
                    'ports_scanned': len(ports_to_scan),
                    'waf_detected': waf_detected,
                    'waf_type': waf_type,
                    'ssl_analysis': ssl_analysis,
                    'scan_duration': duration
                }
                
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                llm_analysis = loop.run_until_complete(
                    self.llm_enhancer.interpret_scan_results(target, scan_results_summary)
                )
                
                if llm_analysis:
                    logger.info(f"🧠 LLM analysis: Risk level {llm_analysis.risk_level}")
                    if llm_analysis.security_concerns:
                        logger.info(f"   Security concerns: {len(llm_analysis.security_concerns)}")
                    if llm_analysis.interesting_findings:
                        logger.info(f"   Interesting findings: {len(llm_analysis.interesting_findings)}")
            except Exception as e:
                logger.debug(f"LLM result interpretation failed (non-fatal): {e}")
        
        # Record scan result for learning
        if self.learning_db:
            try:
                self.learning_db.record_scan_result(
                    target=target,
                    technique_used=waf_detection.get('bypass_technique', 'standard') if waf_detection else 'standard',
                    ports_scanned=ports_to_scan,
                    open_ports_found=len(open_ports),
                    waf_detected=waf_detection.get('waf_detected', False) if waf_detection else False,
                    waf_type=waf_detection.get('waf_type') if waf_detection else None,
                    bypass_successful=waf_detection.get('bypass_successful', False) if waf_detection else None,
                    scan_duration=duration,
                    egg_record_id=egg_record_id,
                    scan_results={
                        'open_ports': open_ports,
                        'scan_results': scan_results
                    }
                )
                logger.debug(f"✅ Learning: Recorded scan result for {target} ({len(open_ports)} ports)")
            except Exception as e:
                logger.warning(f"⚠️  Error recording scan result for learning: {e}")
                import traceback
                logger.debug(f"Learning error traceback: {traceback.format_exc()}")
        else:
            logger.debug("⚠️  Learning database not initialized - scan results not being recorded")
        
        # Final safety checks before returning
        if not isinstance(ports_to_scan, list):
            logger.error(f"❌ CRITICAL: ports_to_scan is not a list at return (type: {type(ports_to_scan)})")
            ports_to_scan = self.default_ports
        if not isinstance(open_ports, list):
            logger.error(f"❌ CRITICAL: open_ports is not a list at return (type: {type(open_ports)})")
            open_ports = []
        
        # Safe len() calls with fallback
        try:
            ports_count = len(ports_to_scan) if isinstance(ports_to_scan, list) else 0
            open_ports_count = len(open_ports) if isinstance(open_ports, list) else 0
            logger.info(f"⚡ Kage scan complete: {open_ports_count}/{ports_count} ports open in {duration:.2f}s")
        except (TypeError, AttributeError) as e:
            logger.error(f"❌ CRITICAL: Error calculating port counts: {e}")
            logger.error(f"   ports_to_scan: type={type(ports_to_scan)}, value={ports_to_scan}")
            logger.error(f"   open_ports: type={type(open_ports)}, value={open_ports}")
            ports_count = 0
            open_ports_count = 0
        
        result = {
            'success': True,
            'target': target,
            'ip_address': ip_address,
            'ports_scanned': ports_count,
            'open_ports': open_ports,  # Return the actual list, not the count
            'open_ports_count': open_ports_count,  # Also include count for convenience
            'scan_duration': duration,
            'results': scan_results,
            'waf_detection': waf_detection,
            'ssl_analysis': ssl_analysis,  # SSL certificate analysis results
            'strategy_used': strategy,
            'nmap_entries_created': nmap_entries_created
        }
        
        # Add LLM analysis if available
        if llm_analysis:
            result['llm_analysis'] = {
                'summary': llm_analysis.summary,
                'security_concerns': llm_analysis.security_concerns,
                'interesting_findings': llm_analysis.interesting_findings,
                'recommendations': llm_analysis.recommendations,
                'risk_level': llm_analysis.risk_level
            }
        
        return result
    
    def batch_scan(self, egg_record_ids: List[str], ports: List[int] = None) -> List[Dict]:
        """
        Batch scan multiple EggRecords.
        
        Args:
            egg_record_ids: List of EggRecord UUID strings
            ports: Ports to scan
            
        Returns:
            List of scan results
        """
        logger.info(f"⚡ Kage batch scanning {len(egg_record_ids)} targets")
        
        results = []
        for i, egg_record_id in enumerate(egg_record_ids, 1):
            logger.info(f"[{i}/{len(egg_record_ids)}] Scanning {egg_record_id}")
            result = self.scan_egg_record(egg_record_id, ports)
            results.append(result)
        
        successful = len([r for r in results if r['success']])
        total_ports = sum(r.get('open_ports', 0) for r in results)
        
        logger.info(f"⚡ Kage batch complete: {successful}/{len(egg_record_ids)} successful, {total_ports} total open ports found")
        
        return results
    
    def _parallel_scan(self, ip: str, ports: List[int], target: str) -> List[Dict]:
        """Parallel port scanning using ThreadPoolExecutor (CPU threading)."""
        # Defensive check: ensure ports is a list
        if not isinstance(ports, list):
            logger.error(f"❌ CRITICAL: _parallel_scan received non-list ports (type: {type(ports)}, value: {ports})")
            ports = self.default_ports if hasattr(self, 'default_ports') else [80, 443]
        logger.info(f"🚀 Kage parallel scan: {len(ports)} ports with {self.max_workers} workers")
        
        results = []
        
        # Check if we can use ThreadPoolExecutor (interpreter not shutting down)
        try:
            # Test if executor can be created
            test_executor = ThreadPoolExecutor(max_workers=1)
            test_executor.shutdown(wait=False)
            del test_executor
            use_parallel = True
        except (RuntimeError, AttributeError) as e:
            if "cannot schedule" in str(e) or "shutdown" in str(e).lower():
                logger.warning(f"⚠️  ThreadPoolExecutor unavailable, using sequential scan for {target}")
                use_parallel = False
            else:
                raise
        
        if use_parallel:
            try:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_port = {}
                    # Submit futures one at a time to catch errors early
                    for port in ports:
                        try:
                            future = executor.submit(self._scan_single_port, ip, port, target)
                            future_to_port[future] = port
                        except RuntimeError as e:
                            if "cannot schedule new futures" in str(e):
                                logger.debug(f"ThreadPoolExecutor shutdown during submission, falling back to sequential")
                                # Cancel remaining and use sequential
                                executor.shutdown(wait=False)
                                return self._sequential_scan(ip, ports, target)
                            raise
                    
                    for future in as_completed(future_to_port):
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                        except Exception as e:
                            port = future_to_port.get(future, 'unknown')
                            logger.error(f"❌ Port {port} scan failed: {e}")
                            results.append({
                                'port': port,
                                'status': 'error',
                                'error': str(e)
                            })
            except RuntimeError as e:
                if "cannot schedule new futures after interpreter shutdown" in str(e):
                    logger.debug(f"ThreadPoolExecutor shutdown detected, falling back to sequential scan for {target}")
                    return self._sequential_scan(ip, ports, target)
                else:
                    raise
        else:
            # Use sequential scanning
            return self._sequential_scan(ip, ports, target)
        
        return results
    
    def _sequential_scan(self, ip: str, ports: List[int], target: str) -> List[Dict]:
        """Sequential port scanning (no parallelization)."""
        # Defensive check: ensure ports is a list
        if not isinstance(ports, list):
            logger.error(f"❌ CRITICAL: _sequential_scan received non-list ports (type: {type(ports)}, value: {ports})")
            ports = self.default_ports if hasattr(self, 'default_ports') else [80, 443]
        logger.info(f"💻 Kage sequential scan: {len(ports)} ports")
        
        results = []
        for port in ports:
            result = self._scan_single_port(ip, port, target)
            results.append(result)
        
        return results
    
    def _scan_single_port(self, ip: str, port: int, target: str) -> Dict[str, Any]:
        """
        Core port scanning logic - extracted from EgoWebs1.
        Uses socket-based connection testing with optional Tor support.
        Includes short-lived caching for performance.
        """
        import time
        
        # Check cache first (very short TTL to avoid stale results)
        cache_key = f"{ip}:{port}"
        if cache_key in self._port_scan_cache:
            cache_time = self._port_scan_cache_timestamps.get(cache_key, 0)
            if time.time() - cache_time < self._port_scan_cache_ttl:
                cached_result = self._port_scan_cache[cache_key].copy()
                cached_result['cached'] = True
                logger.debug(f"📦 Port scan cache hit for {ip}:{port}")
                return cached_result
        
        start_time = time.time()
        
        try:
            # Create socket (use Tor if available)
            if self.tor_enabled and self.tor_proxy:
                sock = self.tor_proxy.create_socks_socket(socket.AF_INET, socket.SOCK_STREAM)
                if sock is None:
                    # Fallback to regular socket if Tor socket creation failed
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.settimeout(self.socket_timeout)
            
            # Attempt connection
            result = sock.connect_ex((ip, port))
            sock.close()
            
            scan_time = time.time() - start_time
            
            if result == 0:
                # Port is open - detect service
                service_info = self._quick_service_detection(ip, port)
                
                result_data = {
                    'port': port,
                    'status': 'open',
                    'protocol': 'tcp',
                    'service_name': service_info['service_name'],
                    'service_product': service_info.get('product', ''),
                    'service_version': service_info.get('version', ''),
                    'service_info': service_info.get('banner', ''),
                    'scan_time': scan_time,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Cache open ports (more valuable to cache)
                self._port_scan_cache[cache_key] = result_data.copy()
                self._port_scan_cache_timestamps[cache_key] = time.time()
                
                return result_data
            else:
                result_data = {
                    'port': port,
                    'status': 'closed',
                    'protocol': 'tcp',
                    'service_name': '',
                    'scan_time': scan_time,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Cache closed ports too (shorter TTL)
                self._port_scan_cache[cache_key] = result_data.copy()
                self._port_scan_cache_timestamps[cache_key] = time.time()
                
                return result_data
                
        except socket.timeout:
            return {
                'port': port,
                'status': 'filtered',
                'protocol': 'tcp',
                'service_name': '',
                'scan_time': time.time() - start_time,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'port': port,
                'status': 'error',
                'protocol': 'tcp',
                'error': str(e),
                'scan_time': time.time() - start_time,
                'timestamp': datetime.now().isoformat()
            }
    
    def _quick_service_detection(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Quick service detection for open ports.
        Extracted from EgoWebs1 service detection logic.
        """
        # Default service based on port
        service_name = self.service_patterns.get(port, f'unknown-{port}')
        
        service_info = {
            'service_name': service_name,
            'product': '',
            'version': '',
            'banner': ''
        }
        
        # Try to grab banner for version detection
        if port in [21, 22, 25, 110, 143]:  # Ports that typically send banners
            try:
                # Use Tor if available
                if self.tor_enabled and self.tor_proxy:
                    sock = self.tor_proxy.create_socks_socket(socket.AF_INET, socket.SOCK_STREAM)
                    if sock is None:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((ip, port))
                
                # Receive banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                if banner:
                    service_info['banner'] = banner
                    
                    # Extract version from banner
                    service_info['version'] = self._extract_version_from_banner(banner)
                    
            except Exception:
                pass  # Banner grab failed, use defaults
        
        # HTTP/HTTPS specific detection
        elif port in [80, 443, 8080, 8443]:
            try:
                import requests
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{ip}:{port}"
                
                # Use Tor session if available
                if self.tor_enabled and self.tor_proxy:
                    session = self.tor_proxy.get_requests_session()
                    if session:
                        response = session.get(url, timeout=3, verify=False)
                    else:
                        response = requests.get(url, timeout=3, verify=False)
                else:
                    response = requests.get(url, timeout=3, verify=False)
                
                # Get Server header
                if 'Server' in response.headers:
                    service_info['product'] = response.headers['Server']
                    service_info['version'] = self._extract_version_from_banner(response.headers['Server'])
                
            except Exception:
                pass
        
        return service_info
    
    def _extract_version_from_banner(self, banner: str) -> str:
        """Extract version number from banner string."""
        import re
        
        # Look for version patterns like "2.4.49", "1.20.0", etc.
        version_pattern = r'(\d+\.\d+(?:\.\d+)?)'
        match = re.search(version_pattern, banner)
        
        return match.group(1) if match else ''
    
    def _load_nmap_knowledge(self) -> Optional[Dict[str, Any]]:
        """Load Nmap knowledge base from scraped documentation."""
        knowledge_paths = [
            Path('/mnt/webapps-nvme/nmap_knowledge/kage_nmap_knowledge.json'),
            Path('/mnt/webapps-nvme/artificial_intelligence/personalities/reconnaissance/kage/nmap_knowledge.json'),
            Path('nmap_knowledge/kage_nmap_knowledge.json'),
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
        
        logger.debug("No Nmap knowledge base found - Kage will use default scanning techniques")
        return None
    
    def get_scanning_advice(self, scan_type: str = "port_scan", target: str = None) -> List[str]:
        """
        Get Nmap scanning advice based on knowledge base.
        
        Args:
            scan_type: Type of scan ('port_scan', 'service_detection', 'host_discovery', etc.)
            target: Optional target information
            
        Returns:
            List of advice strings
        """
        if not self.nmap_knowledge:
            return []
        
        advice = []
        categories = self.nmap_knowledge.get('categories', {})
        
        # Map scan types to knowledge categories
        category_mapping = {
            'port_scan': 'port_scanning',
            'service_detection': 'service_detection',
            'version_detection': 'version_detection',
            'host_discovery': 'host_discovery',
            'os_detection': 'os_detection',
            'performance': 'performance_optimization',
            'firewall_evasion': 'firewall_evasion',
        }
        
        category = category_mapping.get(scan_type, 'port_scanning')
        
        if category in categories:
            category_data = categories[category]
            # Ensure category_data is a list
            if not isinstance(category_data, list):
                logger.warning(f"⚠️  Category '{category}' data is not a list (type: {type(category_data)}), skipping")
                return []
            for entry in category_data[:3]:  # Top 3 entries
                if entry.get('examples'):
                    for example in entry['examples'][:2]:  # Top 2 examples
                        advice.append(f"Nmap technique: {example[:200]}")
                elif entry.get('text'):
                    # Extract key points from text
                    text = entry['text'][:300]
                    advice.append(f"Knowledge: {text}")
        
        return advice
    
    def _validate_dns(self, target: str) -> Dict[str, Any]:
        """
        Validate DNS resolution for a target with caching for performance.
        
        Args:
            target: Hostname or IP address to validate
            
        Returns:
            Dict with 'resolved' (bool) and optional 'error' (str)
        """
        import time
        
        # Check cache first
        cache_key = target.lower()
        if cache_key in self._dns_cache:
            cache_time = self._dns_cache_timestamps.get(cache_key, 0)
            if time.time() - cache_time < self._dns_cache_ttl:
                cached_result = self._dns_cache[cache_key]
                logger.debug(f"📦 DNS cache hit for {target}")
                return cached_result
        
        try:
            # Try to resolve the target
            ip_address = socket.gethostbyname(target)
            result = {'resolved': True, 'ip_address': ip_address}
            
            # Cache successful resolution
            self._dns_cache[cache_key] = result
            self._dns_cache_timestamps[cache_key] = time.time()
            
            return result
        except socket.gaierror as e:
            result = {
                'resolved': False,
                'error': f'DNS resolution failed: {str(e)}'
            }
            # Cache failures too (shorter TTL)
            self._dns_cache[cache_key] = result
            self._dns_cache_timestamps[cache_key] = time.time()
            return result
        except Exception as e:
            result = {
                'resolved': False,
                'error': f'DNS validation error: {str(e)}'
            }
            # Cache failures too
            self._dns_cache[cache_key] = result
            self._dns_cache_timestamps[cache_key] = time.time()
            return result
    
    def get_optimal_scan_strategy(self, target: str, ports: List[int] = None, 
                                  waf_detected: bool = False, waf_type: str = None,
                                  stealth_required: bool = False, 
                                  speed_priority: str = 'normal') -> Dict[str, Any]:
        """
        Get optimal scanning strategy using ML model (if available), inference engine, and knowledge base.
        
        Args:
            target: Target hostname or IP
            ports: List of ports to scan
            waf_detected: Whether WAF was detected
            waf_type: Type of WAF detected
            stealth_required: Whether stealth is required
            speed_priority: 'fast', 'normal', or 'thorough'
            
        Returns:
            Dictionary with recommended scan strategy including Nmap arguments
        """
        # Ensure ports is always a list
        if ports is None:
            ports_list = self.default_ports
        elif isinstance(ports, list):
            ports_list = ports
        elif isinstance(ports, (int, str)):
            # Single port passed as int or string - convert to list
            ports_list = [int(ports)]
        else:
            # Fallback to default ports
            ports_list = self.default_ports
        
        strategy = {
            'technique': 'tcp_syn',  # Default
            'timing': 'normal',
            'ports': ports_list,
            'advice': [],
            'nmap_arguments': [],
            'command': None,
            'reasoning': None,
            'ml_used': False,  # Track if ML model was used
            'reward_score': 0.0,  # Track reward-based optimization
            'learning_used': False  # Track if learning system was used
        }
        
        # Use reward-based optimization from learning system FIRST (highest priority)
        if self.learning_db:
            try:
                best_technique = self.learning_db.get_best_technique(target)
                if best_technique and best_technique.get('success_rate', 0) > 0.6:
                    # High success rate (reward) - use learned technique
                    strategy['technique'] = best_technique['technique']
                    strategy['reward_score'] = best_technique['success_rate']
                    strategy['learning_used'] = True
                    strategy['reasoning'] = f"Reward-based: {best_technique['technique']} has {best_technique['success_rate']:.1%} success rate"
                    logger.info(f"🎯 Using high-reward technique: {best_technique['technique']} (reward: {best_technique['success_rate']:.2%})")
                    
                    # Map technique to Nmap arguments
                    if best_technique['technique'] == 'tcp_syn':
                        strategy['nmap_arguments'].append({'flag': '-sS', 'value': None})
                    elif best_technique['technique'] == 'tcp_connect':
                        strategy['nmap_arguments'].append({'flag': '-sT', 'value': None})
                    elif best_technique['technique'] == 'tcp_ack':
                        strategy['nmap_arguments'].append({'flag': '-sA', 'value': None})
                    elif best_technique['technique'] == 'udp':
                        strategy['nmap_arguments'].append({'flag': '-sU', 'value': None})
            except Exception as e:
                logger.debug(f"Reward-based optimization failed (non-fatal): {e}")
        
        # Try ML model next (if available)
        try:
            from artificial_intelligence.personalities.reconnaissance.kage.kage_volkner_bridge import KageVolknerBridge
            
            # Get or create bridge instance
            if not hasattr(self, '_volkner_bridge') or self._volkner_bridge is None:
                self._volkner_bridge = KageVolknerBridge()
                # Try to load model if it exists
                self._volkner_bridge.load_model()
            
            if self._volkner_bridge.model_trained:
                # Build scenario for ML prediction
                scenario = {
                    'waf_detected': waf_detected,
                    'waf_type': waf_type or 'none',
                    'stealth_required': stealth_required,
                    'firewall_detected': waf_detected,  # Assume WAF implies firewall
                    'ids_detected': False,  # Could be enhanced
                    'speed_priority': speed_priority,
                    'ports_to_scan': ports_list,
                    'target_type': 'single_host',
                    'previous_scan_failed': False  # Could track this
                }
                
                # Get ML predictions
                ml_arguments = self._volkner_bridge.predict_nmap_arguments(scenario)
                
                if ml_arguments:
                    strategy['nmap_arguments'] = ml_arguments
                    strategy['ml_used'] = True
                    strategy['reasoning'] = 'ML model prediction'
                    logger.info(f"🧠 Using ML model for Nmap argument prediction ({len(ml_arguments)} arguments)")
                    
                    # Build command from ML arguments
                    command_parts = ['nmap']
                    for arg in ml_arguments:
                        flag = arg.get('flag', '')
                        value = arg.get('value')
                        if value:
                            command_parts.append(f"{flag} {value}")
                        else:
                            command_parts.append(flag)
                    strategy['command'] = ' '.join(command_parts)
                    
                    # Map arguments to technique
                    for arg in ml_arguments:
                        flag = arg.get('flag', '')
                        if flag == '-sS':
                            strategy['technique'] = 'tcp_syn'
                        elif flag == '-sT':
                            strategy['technique'] = 'tcp_connect'
                        elif flag == '-sU':
                            strategy['technique'] = 'udp'
                    
                    # Return early if ML provided good predictions
                    if len(ml_arguments) >= 3:  # If ML provided substantial recommendations
                        return strategy
        except Exception as e:
            logger.debug(f"ML model not available or error: {e}")
            # Fall through to rule-based inference
        
        # Use inference engine if available (fallback or supplement)
        if self.argument_inference:
            from artificial_intelligence.personalities.reconnaissance.kage.nmap_argument_inference import ScanScenario
            
            scenario = ScanScenario(
                target_type='single_host',
                waf_detected=waf_detected,
                waf_type=waf_type,
                stealth_required=stealth_required,
                speed_priority=speed_priority,
                ports_to_scan=ports
            )
            
            inference_result = self.argument_inference.infer_arguments(scenario)
            
            # Extract arguments from inference - ensure it's always a list
            recommendations = inference_result.get('recommendations', [])
            if not isinstance(recommendations, list):
                logger.warning(f"⚠️  Inference recommendations is not a list (type: {type(recommendations)}), converting to list")
                recommendations = [] if recommendations is None else [recommendations] if not isinstance(recommendations, (list, tuple)) else list(recommendations)
            strategy['nmap_arguments'] = recommendations
            strategy['command'] = inference_result.get('command')
            strategy['reasoning'] = inference_result.get('reasoning')
            
            # Map arguments to technique
            for arg in strategy['nmap_arguments']:
                flag = arg.get('flag', '')
                if flag == '-sS':
                    strategy['technique'] = 'tcp_syn'
                elif flag == '-sT':
                    strategy['technique'] = 'tcp_connect'
                elif flag == '-sU':
                    strategy['technique'] = 'udp'
                elif flag == '-sA':
                    strategy['technique'] = 'tcp_ack'
                elif flag.startswith('-T'):
                    strategy['timing'] = flag.replace('-T', '')
        
        # Fallback to knowledge base if inference not available
        if not self.nmap_knowledge:
            return strategy
        
        # Get performance optimization advice
        perf_advice = self.get_scanning_advice('performance', target)
        if perf_advice and isinstance(perf_advice, list):
            strategy['advice'].extend(perf_advice)
        elif perf_advice:
            logger.warning(f"⚠️  Performance advice is not a list (type: {type(perf_advice)})")
        
        # Get port scanning advice
        port_advice = self.get_scanning_advice('port_scan', target)
        if port_advice and isinstance(port_advice, list):
            strategy['advice'].extend(port_advice)
        elif port_advice:
            logger.warning(f"⚠️  Port advice is not a list (type: {type(port_advice)})")
        
        # Extract recommended techniques from knowledge (if not set by inference)
        if strategy['technique'] == 'tcp_syn':
            categories = self.nmap_knowledge.get('categories', {})
            if 'scanning_techniques' in categories:
                scanning_tech = categories['scanning_techniques']
                # Ensure it's a list
                if not isinstance(scanning_tech, list):
                    logger.warning(f"⚠️  scanning_techniques is not a list (type: {type(scanning_tech)})")
                    scanning_tech = []
                for entry in scanning_tech[:2]:
                    if entry.get('examples'):
                        # Look for scan type flags in examples
                        for example in entry['examples']:
                            if '-sS' in example:
                                strategy['technique'] = 'tcp_syn'
                            elif '-sT' in example:
                                strategy['technique'] = 'tcp_connect'
                            elif '-sU' in example:
                                strategy['technique'] = 'udp'
        
        return strategy
    
    def _advanced_host_discovery_waf_detection(self, target: str) -> Dict[str, Any]:
        """
        Advanced host discovery with WAF detection and bypass.
        Uses learning database and Nmap knowledge base.
        """
        result = {
            'waf_detected': False,
            'waf_type': None,
            'confidence': 0.0,
            'bypass_technique': None,
            'bypass_successful': False,
            'recommendations': []
        }
        
        if not self.host_discovery or not self.learning_db:
            return result
        
        # Check learning database for known good technique
        best_technique = self.learning_db.get_best_technique(target)
        
        # Try techniques in order of effectiveness
        techniques_to_try = []
        
        if best_technique:
            # Use learned technique first
            techniques_to_try.append(best_technique['technique'])
            logger.info(f"📚 Using learned technique: {best_technique['technique']} (success rate: {best_technique['success_rate']:.2%})")
        
        # Add techniques from Nmap knowledge base
        if self.nmap_knowledge:
            host_discovery_advice = self.get_scanning_advice('host_discovery', target)
            if host_discovery_advice:
                # Extract techniques from advice
                for advice in host_discovery_advice:
                    if 'tcp syn' in advice.lower() and 'tcp_syn_nonhttp' not in techniques_to_try:
                        techniques_to_try.append('tcp_syn_nonhttp')
                    elif 'tcp ack' in advice.lower() and 'tcp_ack' not in techniques_to_try:
                        techniques_to_try.append('tcp_ack')
                    elif 'udp' in advice.lower() and 'udp_dns' not in techniques_to_try:
                        techniques_to_try.append('udp_dns')
                    elif 'icmp' in advice.lower() and 'icmp' not in techniques_to_try:
                        techniques_to_try.append('icmp')
        
        # Default techniques if none found
        if not techniques_to_try:
            techniques_to_try = ['tcp_syn_nonhttp', 'tcp_ack', 'udp_dns', 'icmp']
        
        # Try host discovery
        discovery_result = self.host_discovery.multi_probe_discovery(target, techniques_to_try)
        
        if discovery_result['success']:
            result['bypass_technique'] = discovery_result['technique']
            result['bypass_successful'] = True
            
            # Try to detect WAF via HTTP probe
            try:
                import requests
                http_response = requests.get(f"http://{target}", timeout=3, verify=False, allow_redirects=True)
                waf_info = self.waf_fingerprinter.fingerprint_waf(target, http_response, discovery_result['probe_result'])
                
                if waf_info['waf_detected']:
                    result['waf_detected'] = True
                    result['waf_type'] = waf_info['waf_type']
                    result['confidence'] = waf_info.get('confidence', 0.0)
                    result['recommendations'] = waf_info['bypass_recommendations']
                    
                    # Record WAF detection
                    self.learning_db.record_waf_detection(
                        target, waf_info, 
                        discovery_result['technique'], 
                        True,
                        response_headers=dict(http_response.headers),
                        response_body_sample=http_response.text[:1000]
                    )
            except Exception as e:
                logger.debug(f"HTTP probe for WAF detection failed: {e}")
            
            # Record successful technique
            self.learning_db.record_technique_result(
                target, result.get('waf_type'), 
                discovery_result['technique'], 
                True
            )
        else:
            # All techniques failed - record failures
            for probe in discovery_result['all_results']:
                self.learning_db.record_technique_result(
                    target, None,
                    probe['technique'],
                    False
                )
        
        return result
    
    def _adapt_strategy_for_waf(self, strategy: Dict[str, Any], waf_info: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt scanning strategy based on WAF detection."""
        waf_type = waf_info.get('waf_type')
        
        if not waf_type:
            return strategy
        
        # Get WAF-specific recommendations
        recommendations = waf_info.get('bypass_recommendations', [])
        
        # Adapt timing
        if 'slow' in ' '.join(recommendations).lower():
            strategy['timing'] = 'slow'
        
        # Adapt ports based on recommendations
        if 'non-http' in ' '.join(recommendations).lower() or 'non-standard' in ' '.join(recommendations).lower():
            # Ensure strategy['ports'] is a list before extending
            if 'ports' not in strategy or not isinstance(strategy['ports'], list):
                strategy['ports'] = strategy.get('ports', [])
                if not isinstance(strategy['ports'], list):
                    # Convert to list if it's not already
                    strategy['ports'] = [strategy['ports']] if strategy['ports'] else []
            # Add non-HTTP ports
            strategy['ports'].extend([22, 25, 53, 3306, 5432])
            strategy['ports'] = list(set(strategy['ports']))  # Remove duplicates
        
        # Add recommendations to strategy
        strategy['waf_bypass_recommendations'] = recommendations
        
        return strategy
    
    def _execute_nmap_with_techniques(self, target: str, ip_address: str, 
                                     ports: List[int], strategy: Dict[str, Any],
                                     waf_detection: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute Nmap with specific techniques and parse XML output comprehensively.
        
        Uses Nmap XML output to extract:
        - CPE strings (for CVE correlation)
        - Service extrainfo, devicetype
        - NSE script output
        - Nmap arguments (for heuristics learning)
        - State reasons (for WAF detection)
        - OS detection
        
        Args:
            target: Target hostname
            ip_address: Target IP address
            ports: List of ports to scan
            strategy: Scan strategy with nmap_arguments
            waf_detection: WAF detection info (optional)
            
        Returns:
            Dictionary with comprehensive scan results
        """
        import tempfile
        import os
        
        # Build Nmap command with XML output and version detection
        ports_str = ','.join(map(str, ports))
        nmap_cmd = ['nmap', '-sV', '--version-intensity', '5', '-p', ports_str, '-oX', '-', ip_address or target]
        
        # Add custom arguments from strategy
        if strategy.get('nmap_arguments'):
            for arg in strategy['nmap_arguments']:
                if isinstance(arg, dict):
                    flag = arg.get('flag', '')
                    value = arg.get('value')
                    if value:
                        nmap_cmd.extend([flag, str(value)])
                    else:
                        nmap_cmd.append(flag)
                else:
                    nmap_cmd.append(str(arg))
        
        # Add NSE scripts for additional intelligence
        # -sC enables default scripts, http-waf-detect for WAF detection
        if '-sC' not in nmap_cmd and '--script' not in ' '.join(nmap_cmd):
            nmap_cmd.append('-sC')  # Enable default scripts
        
        try:
            # Execute Nmap and capture XML output
            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                check=False
            )
            
            if result.returncode != 0:
                logger.warning(f"Nmap scan failed: {result.stderr}")
                return {'success': False, 'error': result.stderr}
            
            # Parse comprehensive XML output
            xml_output = result.stdout
            parsed_results = self._parse_nmap_xml_comprehensive(xml_output, target)
            
            if not parsed_results.get('success'):
                return parsed_results
            
            # Convert parsed results to format expected by rest of code
            scan_results = []
            for result_data in parsed_results.get('scan_results', []):
                scan_results.append({
                    'port': result_data['port'],
                    'status': result_data['status'],
                    'protocol': result_data.get('protocol', 'tcp'),
                    'service_name': result_data.get('service_name', ''),
                    'service_version': result_data.get('service_version', ''),
                    'service_product': result_data.get('service_product', ''),
                    'service_extrainfo': result_data.get('service_extrainfo', ''),
                    'service_devicetype': result_data.get('service_devicetype', ''),
                    'service_cpe': result_data.get('service_cpe', []),
                    'state_reason': result_data.get('state_reason', ''),
                    'service_info': result_data.get('service_info', ''),
                    'scripts': result_data.get('scripts', [])
                })
            
            return {
                'success': True,
                'scan_results': scan_results,
                'nmap_xml_parsed': True,
                'nmap_args': parsed_results.get('nmap_args', ''),
                'scan_type': parsed_results.get('scan_type', ''),
                'target': target,
                'ip_address': ip_address,
                'hosts': parsed_results.get('hosts', [])
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timed out for {target}")
            return {'success': False, 'error': 'Nmap scan timed out'}
        except Exception as e:
            logger.error(f"Nmap execution error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_nmap_xml_comprehensive(self, xml_output: str, target: str) -> Dict[str, Any]:
        """
        Comprehensive Nmap XML parser that extracts ALL relevant data.
        
        Captures:
        - Host-level: nmaprun args, scaninfo, osmatch, status reason
        - Port-level: state reason, service extrainfo, CPE, devicetype
        - NSE scripts: All script output for actionable intelligence
        
        Args:
            xml_output: Nmap XML output string
            target: Target hostname/IP
            
        Returns:
            Dictionary with complete Nmap scan data
        """
        try:
            root = ET.fromstring(xml_output)
            results = {
                'success': True,
                'target': target,
                'nmap_args': None,  # Exact Nmap command used
                'scan_type': None,  # Type of scan (Syn Scan, UDP Scan, etc.)
                'hosts': [],
                'scan_results': []
            }
            
            # Extract nmaprun-level metadata
            nmaprun = root
            results['nmap_args'] = nmaprun.get('args', '')  # For heuristics learning
            results['nmap_version'] = nmaprun.get('version', '')
            results['scan_start'] = nmaprun.get('startstr', '')
            
            # Extract scaninfo (scan type)
            scaninfo = nmaprun.find('scaninfo')
            if scaninfo is not None:
                results['scan_type'] = scaninfo.get('type', '')  # For technique effectiveness
                results['scan_protocol'] = scaninfo.get('protocol', '')
                results['num_services'] = scaninfo.get('numservices', '')
            
            # Parse each host
            for host in nmaprun.findall('host'):
                host_info = {
                    'status': 'up',
                    'status_reason': None,  # Why host is up/down
                    'addresses': {},
                    'os_detection': {},  # OS detection results
                    'ports': []
                }
                
                # Get host status and reason
                status_elem = host.find('status')
                if status_elem is not None:
                    host_info['status'] = status_elem.get('state', 'unknown')
                    host_info['status_reason'] = status_elem.get('reason', '')
                    host_info['status_reason_ttl'] = status_elem.get('reason_ttl', '')
                
                # Get addresses (IPv4, IPv6)
                for address in host.findall('address'):
                    addr_type = address.get('addrtype', '')
                    addr_value = address.get('addr', '')
                    if addr_type in ['ipv4', 'ipv6']:
                        host_info['addresses'][addr_type] = addr_value
                
                # Extract OS detection (osmatch)
                os_elem = host.find('os')
                if os_elem is not None:
                    os_matches = []
                    for osmatch in os_elem.findall('osmatch'):
                        os_match = {
                            'name': osmatch.get('name', ''),
                            'accuracy': osmatch.get('accuracy', ''),
                            'line': osmatch.get('line', ''),
                            'cpe': []
                        }
                        # Extract CPE for OS
                        for cpe in osmatch.findall('cpe'):
                            cpe_text = cpe.text
                            if cpe_text:
                                os_match['cpe'].append(cpe_text.strip())
                        os_matches.append(os_match)
                    host_info['os_detection'] = {
                        'matches': os_matches,
                        'used_fingerprints': os_elem.get('used', '')
                    }
                
                # Parse ports and services (COMPREHENSIVE)
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        port_info = {
                            'port': int(port_elem.get('portid', 0)),
                            'protocol': port_elem.get('protocol', 'tcp'),
                            'state': 'closed',
                            'state_reason': None,  # Packet reason
                            'state_reason_ttl': None,
                            'service_name': None,
                            'service_version': None,
                            'service_product': None,
                            'service_extrainfo': None,  # Additional details
                            'service_devicetype': None,  # Device type
                            'service_cpe': [],  # CPE strings (CRITICAL)
                            'service_banner': None,
                            'scripts': []  # NSE script output
                        }
                        
                        # Get port state and reason
                        state_elem = port_elem.find('state')
                        if state_elem is not None:
                            port_info['state'] = state_elem.get('state', 'closed')
                            port_info['state_reason'] = state_elem.get('reason', '')
                            port_info['state_reason_ttl'] = state_elem.get('reason_ttl', '')
                        
                        # Get service information (COMPREHENSIVE)
                        service_elem = port_elem.find('service')
                        if service_elem is not None:
                            # Extract all service fields
                            port_info['service_name'] = service_elem.get('name', '').strip() or None
                            port_info['service_version'] = service_elem.get('version', '').strip() or None
                            port_info['service_product'] = service_elem.get('product', '').strip() or None
                            port_info['service_extrainfo'] = service_elem.get('extrainfo', '').strip() or None
                            port_info['service_devicetype'] = service_elem.get('devicetype', '').strip() or None
                            port_info['service_banner'] = service_elem.get('banner', '').strip() or None
                            
                            # Extract CPE strings (CRITICAL for CVE correlation)
                            for cpe_elem in service_elem.findall('cpe'):
                                cpe_text = cpe_elem.text
                                if cpe_text:
                                    port_info['service_cpe'].append(cpe_text.strip())
                        
                        # Extract NSE script output (ACTIONABLE INTELLIGENCE)
                        for script_elem in port_elem.findall('script'):
                            script_info = {
                                'id': script_elem.get('id', ''),
                                'output': script_elem.get('output', ''),
                                'tables': []  # For structured script data
                            }
                            
                            # Parse script tables if present
                            for table in script_elem.findall('table'):
                                table_data = self._parse_script_table(table)
                                script_info['tables'].append(table_data)
                            
                            port_info['scripts'].append(script_info)
                        
                        host_info['ports'].append(port_info)
                        
                        # Add to scan_results for compatibility (only open ports)
                        if port_info['state'] == 'open':
                            scan_result = {
                                'port': port_info['port'],
                                'status': 'open',
                                'protocol': port_info['protocol'],
                                'state_reason': port_info['state_reason'],
                                'service_name': port_info['service_name'] or '',
                                'service_version': port_info['service_version'] or '',
                                'service_product': port_info['service_product'] or '',
                                'service_extrainfo': port_info['service_extrainfo'] or '',
                                'service_devicetype': port_info['service_devicetype'] or '',
                                'service_cpe': port_info['service_cpe'],
                                'service_info': port_info['service_banner'] or '',
                                'scripts': port_info['scripts']
                            }
                            results['scan_results'].append(scan_result)
                
                results['hosts'].append(host_info)
            
            return results
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return {'success': False, 'error': f'XML parse error: {e}'}
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_script_table(self, table_elem) -> Dict[str, Any]:
        """Parse NSE script table structure recursively."""
        table_data = {}
        for elem in table_elem:
            if elem.tag == 'elem':
                key = elem.get('key', '')
                value = elem.text or ''
                table_data[key] = value
            elif elem.tag == 'table':
                # Recursive table parsing
                key = elem.get('key', '')
                table_data[key] = self._parse_script_table(elem)
        return table_data
    
    def _create_technology_fingerprint_from_cpe(self, egg_record_id: str, nmap_scan_id: str,
                                                cpe_string: str, port: int, 
                                                service_name: str = None) -> Optional[str]:
        """
        Create TechnologyFingerprint from CPE string.
        
        CPE format: cpe:/a:apache:http_server:2.4.41
        Parses: vendor=apache, product=http_server, version=2.4.41
        
        Args:
            egg_record_id: EggRecord UUID
            nmap_scan_id: Nmap scan UUID
            cpe_string: CPE string from Nmap
            port: Port number
            service_name: Service name (optional)
            
        Returns:
            TechnologyFingerprint ID if created, None otherwise
        """
        try:
            # Parse CPE string
            # Format: cpe:/[part]:[vendor]:[product]:[version]:[update]:[edition]:[language]
            cpe_parts = cpe_string.split(':')
            if len(cpe_parts) < 5:
                return None
            
            part = cpe_parts[1]  # 'a' for application, 'o' for OS, 'h' for hardware
            vendor = cpe_parts[2] if len(cpe_parts) > 2 else ''
            product = cpe_parts[3] if len(cpe_parts) > 3 else ''
            version = cpe_parts[4] if len(cpe_parts) > 4 else ''
            
            if not vendor or not product:
                return None
            
            # Determine technology category
            category_map = {
                'a': 'application',
                'o': 'operating_system',
                'h': 'hardware'
            }
            category = category_map.get(part, 'unknown')
            
            # Create technology name
            technology_name = f"{vendor} {product}".strip()
            
            # Create TechnologyFingerprint
            from artificial_intelligence.customer_eggs_eggrecords_general_models.models import TechnologyFingerprint
            
            fingerprint = TechnologyFingerprint.objects.using('customer_eggs').create(
                egg_record_id=egg_record_id,
                nmap_scan_id=nmap_scan_id,
                technology_name=technology_name,
                technology_version=version or None,
                technology_category=category,
                confidence_score=0.95,  # High confidence from CPE
                detection_method='nmap_cpe',
                raw_detection_data={
                    'cpe': cpe_string,
                    'port': port,
                    'service_name': service_name,
                    'parsed': {
                        'part': part,
                        'vendor': vendor,
                        'product': product,
                        'version': version
                    }
                }
            )
            
            logger.info(f"✅ Created TechnologyFingerprint from CPE: {technology_name} {version}")
            return str(fingerprint.id)
            
        except Exception as e:
            logger.warning(f"Failed to create TechnologyFingerprint from CPE {cpe_string}: {e}")
            return None
    
    def _parse_nmap_args_to_list(self, nmap_args: str) -> List[Dict[str, Any]]:
        """
        Parse Nmap command line arguments into structured list.
        
        Example: "nmap -sV -p 80,443 -T4 target.com"
        Returns: [{'flag': '-sV'}, {'flag': '-p', 'value': '80,443'}, {'flag': '-T4'}]
        """
        if not nmap_args:
            return []
        
        args_list = []
        parts = nmap_args.split()
        
        i = 0
        while i < len(parts):
            part = parts[i]
            if part.startswith('-'):
                # Check if next part is a value (not another flag)
                if i + 1 < len(parts) and not parts[i + 1].startswith('-'):
                    args_list.append({'flag': part, 'value': parts[i + 1]})
                    i += 2
                else:
                    args_list.append({'flag': part})
                    i += 1
            else:
                i += 1
        
        return args_list


# Singleton instance
_kage_scanner_instance = None

def get_kage_scanner(parallel_enabled: bool = True):
    """Get Kage scanner instance (singleton)."""
    global _kage_scanner_instance
    
    if _kage_scanner_instance is None:
        _kage_scanner_instance = KageNmapScanner(parallel_enabled=parallel_enabled)
    
    return _kage_scanner_instance


def scan_egg_record(egg_record_id: str) -> Dict[str, Any]:
    """
    Scan an EggRecord using Kage scanner.
    This function uses the main scan_egg_record method which stores results in the egg record.
    
    Args:
        egg_record_id: ID of the EggRecord to scan
        
    Returns:
        Dictionary containing scan results
    """
    try:
        # Get scanner instance
        scanner = get_kage_scanner()
        
        # Perform the scan (this stores results in the egg record)
        scan_results = scanner.scan_egg_record(egg_record_id)
        
        if not scan_results.get('success', False):
            logger.error(f"Scan failed for EggRecord {egg_record_id}")
            return scan_results
        
        logger.info(f"Scan completed for EggRecord {egg_record_id}")
        
        return {
            'target': scan_results.get('target', ''),
            'ports_found': scan_results.get('open_ports', 0),
            'scan_results': scan_results
        }
        
    except Exception as e:
        logger.error(f"Error scanning EggRecord {egg_record_id}: {e}")
        raise


# Backward compatibility alias
NmapScanner = KageNmapScanner

