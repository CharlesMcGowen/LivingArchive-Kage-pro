#!/usr/bin/env python3
"""
Suzu Directory Enumerator - Wordlist-Based Path Discovery
==========================================================

Suzu specializes in:
- Directory enumeration using wordlists (dirsearch, gobuster, ffuf)
- Learning from Kumo's spidered paths to prioritize wordlists
- Pattern-based wordlist generation
- Integration with seclist and custom wordlists
- Creating DirectoryEnumerationResult entries for Ryu to assess

Author: EGO Revolution - Suzu (Bell Enumerator)
Version: 1.0.0 - Smart Enumeration with Learning
"""

import os
import sys
import logging
import time
import json
import subprocess
import shutil
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse

# Setup Django
try:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
    import django
    django.setup()
except Exception:
    # Fallback to EgoQT settings
    sys.path.insert(0, '/mnt/webapps-nvme')
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EgoQT.src.django_bridge.settings')
    import django
    django.setup()

from django.apps import apps
from django.db import connections
from django.utils import timezone

logger = logging.getLogger(__name__)


class SuzuDirectoryEnumerator:
    """
    Suzu's directory enumeration service.
    Uses wordlists and learns from Kumo's spidering to discover hidden paths.
    """
    
    def __init__(self, parallel_enabled: bool = True):
        """
        Initialize Suzu's directory enumerator.
        
        Args:
            parallel_enabled: Use parallel processing (future: multiple tools simultaneously)
        """
        self.parallel_enabled = parallel_enabled
        
        # Suzu's enumeration configuration
        self.request_timeout = 10.0
        self.max_paths_per_domain = 1000
        self.enumeration_depth = 2
        
        # Tool paths (will be detected)
        self.dirsearch_path = None
        self.gobuster_path = None
        self.ffuf_path = None
        self.available_tools = []
        
        # Wordlist paths
        self.wordlist_paths = []
        self.seclist_base = Path('/mnt/webapps-nvme/wordlists')  # Default location
        self._init_tools()
        self._init_wordlists()
        
        # Pattern learner (learns from Kumo's data)
        try:
            from artificial_intelligence.personalities.reconnaissance.suzu.pattern_learner import PatternLearner
            self.pattern_learner = PatternLearner()
            logger.info("🧠 Pattern learner initialized - will learn from Kumo's spidering")
        except Exception as e:
            logger.warning(f"⚠️  Pattern learner not available: {e}")
            self.pattern_learner = None
        
        # Wordlist manager
        try:
            from artificial_intelligence.personalities.reconnaissance.suzu.wordlist_manager import WordlistManager
            self.wordlist_manager = WordlistManager(
                seclist_base=self.seclist_base,
                pattern_learner=self.pattern_learner
            )
            logger.info("📚 Wordlist manager initialized")
        except Exception as e:
            logger.warning(f"⚠️  Wordlist manager not available: {e}")
            self.wordlist_manager = None
        
        # CMS detector
        try:
            from suzu.cms_detector import CMSDetector
            self.cms_detector = CMSDetector()
            logger.info("🔍 CMS detector initialized")
        except Exception as e:
            logger.warning(f"⚠️  CMS detector not available: {e}")
            self.cms_detector = None
        
        # Priority scorer (will be initialized with CMS if detected)
        self.priority_scorer = None
        # Note: Priority scorer will be initialized later with detected CMS
        
        # Vector path store (for weighted path retrieval)
        try:
            from suzu.vector_path_store import VectorPathStore
            self.vector_store = VectorPathStore()
            logger.info("🔍 Vector path store initialized - will query weighted paths")
        except Exception as e:
            logger.warning(f"⚠️  Vector path store not available: {e}")
            self.vector_store = None
        
        # Enhanced dirsearch
        try:
            from suzu.enhanced_dirsearch import EnhancedDirsearch
            self.enhanced_dirsearch = EnhancedDirsearch(dirsearch_path=self.dirsearch_path)
            logger.info("⚡ Enhanced dirsearch initialized")
        except Exception as e:
            logger.warning(f"⚠️  Enhanced dirsearch not available: {e}")
            self.enhanced_dirsearch = None
        
        logger.info(f"🔔 Suzu enumerator initialized (Tools: {', '.join(self.available_tools) if self.available_tools else 'None'})")
    
    def _init_tools(self):
        """Detect and initialize directory enumeration tools"""
        # Check for dirsearch
        possible_dirsearch_paths = [
            '/usr/bin/dirsearch',
            '/usr/local/bin/dirsearch',
            '/opt/dirsearch/dirsearch.py',
            Path('/mnt/webapps-nvme/tools/dirsearch/dirsearch.py'),
            Path('/mnt/webapps-nvme/artificial_intelligence/personalities/reconnaissance/kage/tools/dirsearch/dirsearch.py'),
        ]
        
        for path in possible_dirsearch_paths:
            if isinstance(path, str):
                path = Path(path)
            if path.exists():
                self.dirsearch_path = path
                self.available_tools.append('dirsearch')
                logger.info(f"✅ Found dirsearch: {path}")
                break
        
        # Check for gobuster
        gobuster_path = shutil.which('gobuster')
        if gobuster_path:
            self.gobuster_path = gobuster_path
            self.available_tools.append('gobuster')
            logger.info(f"✅ Found gobuster: {gobuster_path}")
        
        # Check for ffuf
        ffuf_path = shutil.which('ffuf')
        if ffuf_path:
            self.ffuf_path = ffuf_path
            self.available_tools.append('ffuf')
            logger.info(f"✅ Found ffuf: {ffuf_path}")
        
        if not self.available_tools:
            logger.warning("⚠️  No directory enumeration tools found (dirsearch/gobuster/ffuf)")
            logger.info("💡 Suzu will use custom Python-based enumeration as fallback")
    
    def _init_wordlists(self):
        """Initialize wordlist paths from seclist and other sources"""
        # Common seclist wordlist locations
        seclist_paths = [
            Path('/mnt/webapps-nvme/wordlists/Seclists/Discovery/Web-Content'),
            Path('/mnt/webapps-nvme/wordlists/seclists/Discovery/Web-Content'),
            Path('/usr/share/seclists/Discovery/Web-Content'),
            Path('/opt/seclists/Discovery/Web-Content'),
        ]
        
        # Common wordlist files
        wordlist_files = [
            'common.txt',
            'big.txt',
            'directory-list-2.3-medium.txt',
            'directory-list-2.3-big.txt',
            'raft-medium-directories.txt',
            'raft-large-directories.txt',
        ]
        
        for seclist_base in seclist_paths:
            if seclist_base.exists():
                self.seclist_base = seclist_base
                logger.info(f"✅ Found seclist base: {seclist_base}")
                # Add common wordlists
                for wordlist_file in wordlist_files:
                    wordlist_path = seclist_base / wordlist_file
                    if wordlist_path.exists():
                        self.wordlist_paths.append(wordlist_path)
                        logger.debug(f"  Found wordlist: {wordlist_file}")
                break
        
        # Fallback: Check metasploit wordlists
        if not self.wordlist_paths:
            metasploit_wordlists = Path('/mnt/webapps-nvme/tools/metasploit-framework/data/wordlists')
            if metasploit_wordlists.exists():
                # Use any .txt files as potential wordlists
                for wordlist_file in metasploit_wordlists.glob('*.txt'):
                    if wordlist_file.stat().st_size > 100:  # At least 100 bytes
                        self.wordlist_paths.append(wordlist_file)
                        logger.debug(f"  Found metasploit wordlist: {wordlist_file.name}")
                if self.wordlist_paths:
                    logger.info(f"✅ Using {len(self.wordlist_paths)} metasploit wordlists")
        
        # Fallback: Check dirsearch wordlists
        if not self.wordlist_paths:
            dirsearch_wordlists = Path('/mnt/webapps-nvme/tools/dirsearch')
            for wordlist_file in dirsearch_wordlists.glob('*.txt'):
                if wordlist_file.stat().st_size > 100:
                    self.wordlist_paths.append(wordlist_file)
                    logger.debug(f"  Found dirsearch wordlist: {wordlist_file.name}")
                if self.wordlist_paths:
                    logger.info(f"✅ Using {len(self.wordlist_paths)} dirsearch wordlists")
        
        if not self.wordlist_paths:
            logger.warning("⚠️  No wordlists found - Suzu will generate wordlists from Kumo's data")
    
    def enumerate_egg_record(self, egg_record_id: str, write_to_db: bool = True, egg_record_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Enumerate directories for an EggRecord.
        
        Args:
            egg_record_id: EggRecord UUID string to enumerate
            write_to_db: If False, return results without writing to database (for REST API mode)
            egg_record_data: Optional dict with eggrecord data (subDomain, domainname, etc.)
        
        Returns:
            Enumeration results summary
        """
        # Get target from eggrecord data
        if egg_record_data:
            target = egg_record_data.get('subDomain') or egg_record_data.get('domainname')
        else:
            # Fetch from database if not provided
            try:
                db = connections['customer_eggs']
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, "subDomain", domainname, alive
                        FROM customer_eggs_eggrecords_general_models_eggrecord
                        WHERE id = %s
                        LIMIT 1
                    """, [egg_record_id])
                    row = cursor.fetchone()
                    if row:
                        columns = [col[0] for col in cursor.description]
                        egg_record_data = dict(zip(columns, row))
                        target = egg_record_data.get('subDomain') or egg_record_data.get('domainname')
                    else:
                        return {
                            'success': False,
                            'error': 'EggRecord not found',
                            'target': egg_record_id
                        }
            except Exception as e:
                logger.error(f"❌ Error fetching EggRecord: {e}")
                return {
                    'success': False,
                    'error': str(e),
                    'target': egg_record_id
                }
        
        if not target:
            return {
                'success': False,
                'error': 'Could not determine target',
                'target': egg_record_id
            }
        
        logger.info(f"🔔 Suzu enumerating {target} (EggRecord: {egg_record_id})")
        start_time = time.time()
        
        # Learn from Kumo's spidering data
        learned_patterns = None
        smart_wordlist = None
        if self.pattern_learner:
            try:
                learned_patterns = self.pattern_learner.analyze_kumo_findings(egg_record_id)
                if learned_patterns:
                    logger.info(f"🧠 Learned {len(learned_patterns.get('patterns', []))} patterns from Kumo's spidering")
                    # Generate smart wordlist based on patterns
                    if self.wordlist_manager:
                        smart_wordlist = self.wordlist_manager.generate_smart_wordlist(
                            learned_patterns,
                            base_wordlist=self.wordlist_paths[0] if self.wordlist_paths else None
                        )
                        logger.info(f"📚 Generated smart wordlist with {len(smart_wordlist) if smart_wordlist else 0} paths")
            except Exception as e:
                logger.warning(f"⚠️  Error learning from Kumo's data: {e}")
        
        # Detect CMS and get technology fingerprints for priority wordlist generation
        cms_detection = None
        technology_fingerprint = None
        priority_wordlist = None
        
        # Initialize priority scorer with detected CMS (if available)
        if not self.priority_scorer:
            try:
                from suzu.priority_scorer import DirectoryPriorityScorer
                # Will update with CMS after detection
                self.priority_scorer = DirectoryPriorityScorer()
            except Exception as e:
                logger.warning(f"⚠️  Priority scorer not available: {e}")
                self.priority_scorer = None
        
        if self.cms_detector:
            try:
                # Try to get CMS detection from Kumo's RequestMetaData
                db = connections['customer_eggs']
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, response_headers, response_body
                        FROM customer_eggs_eggrecords_general_models_requestmetadata
                        WHERE record_id_id = %s
                        AND response_status = 200
                        ORDER BY created_at DESC
                        LIMIT 1
                    """, [egg_record_id])
                    row = cursor.fetchone()
                    if row:
                        import json
                        response_headers = json.loads(row[1]) if row[1] else {}
                        response_body = row[2] or ''
                        cms_detection = self.cms_detector.detect_cms_from_request_metadata(
                            str(row[0]), response_headers, response_body
                        )
                        if cms_detection:
                            logger.info(f"🔍 CMS detected: {cms_detection.get('cms')} (confidence: {cms_detection.get('confidence', 0):.2f})")
                            # Reinitialize priority scorer with detected CMS for adaptive learning
                            if self.priority_scorer is None:
                                try:
                                    from suzu.priority_scorer import DirectoryPriorityScorer
                                    self.priority_scorer = DirectoryPriorityScorer(target_cms=cms_detection.get('cms'))
                                    logger.info(f"📊 Priority scorer reinitialized with CMS: {cms_detection.get('cms')}")
                                except Exception as e:
                                    logger.debug(f"Could not reinitialize priority scorer: {e}")
            except Exception as e:
                logger.debug(f"Error detecting CMS: {e}")
        
        # Get technology fingerprint
        try:
            db = connections['customer_eggs']
            with db.cursor() as cursor:
                cursor.execute("""
                    SELECT id, technology_name, technology_category, confidence_score
                    FROM enrichment_system_technologyfingerprint
                    WHERE egg_record_id = %s
                    AND technology_category = 'cms'
                    ORDER BY confidence_score DESC
                    LIMIT 1
                """, [egg_record_id])
                row = cursor.fetchone()
                if row:
                    technology_fingerprint = {
                        'id': str(row[0]),
                        'technology_name': row[1],
                        'technology_category': row[2],
                        'confidence_score': float(row[3]) if row[3] else 0.0,
                    }
        except Exception as e:
            logger.debug(f"Error getting technology fingerprint: {e}")
        
        # Generate priority wordlist
        priority_wordlist = None
        if self.priority_scorer:
            try:
                priority_wordlist = self.priority_scorer.get_priority_wordlist(
                    egg_record_id, cms_detection, technology_fingerprint
                )
                if priority_wordlist:
                    logger.info(f"📊 Generated priority wordlist with {len(priority_wordlist)} paths")
            except Exception as e:
                logger.debug(f"Error generating priority wordlist: {e}")
        
        # Query vector database for weighted paths (if CMS detected)
        vector_paths = []
        if self.vector_store and cms_detection and cms_detection.get('cms_name'):
            try:
                cms_name = cms_detection.get('cms_name')
                weighted_paths = self.vector_store.get_weighted_paths(
                    cms_name=cms_name,
                    limit=200,  # Get top 200 weighted paths
                    min_weight=0.2
                )
                
                if weighted_paths:
                    # Extract paths and sort by weight
                    vector_paths = [item['path'] for item in weighted_paths]
                    logger.info(f"🔍 Retrieved {len(vector_paths)} weighted paths from vector DB for CMS: {cms_name}")
                    
                    # Merge with priority wordlist (vector paths take precedence for same paths)
                    if priority_wordlist:
                        # Combine, removing duplicates (keep vector DB paths)
                        combined_paths = {path: None for path in vector_paths}
                        for path in priority_wordlist:
                            if path not in combined_paths:
                                combined_paths[path] = None
                        priority_wordlist = list(combined_paths.keys())
                    else:
                        priority_wordlist = vector_paths
            except Exception as e:
                logger.debug(f"Error querying vector DB for paths: {e}")
        
        # Try both HTTP and HTTPS
        urls_to_enumerate = [
            f"https://{target}",
            f"http://{target}"
        ]
        
        enumeration_results = []
        paths_discovered = []
        
        for base_url in urls_to_enumerate:
            try:
                # Use best available tool
                result = self._enumerate_url(
                    base_url,
                    egg_record_id,
                    wordlist=smart_wordlist or (self.wordlist_paths[0] if self.wordlist_paths else None),
                    learned_patterns=learned_patterns,
                    priority_wordlist=priority_wordlist
                )
                
                if result.get('success'):
                    enumeration_results.append(result)
                    paths_discovered.extend(result.get('paths', []))
                    
            except Exception as e:
                logger.error(f"❌ Failed to enumerate {base_url}: {e}")
        
        duration = time.time() - start_time
        
        # Calculate priority scores for all discovered paths (even if not storing to DB)
        # This ensures the daemon receives paths with heuristics
        paths_with_priority = []
        if paths_discovered and self.priority_scorer:
            try:
                # Get Nmap correlation once for all paths
                nmap_correlation = None
                if self.cms_detector:
                    ip_address = None
                    port = None
                    if target:
                        import re
                        port_match = re.search(r':(\d+)(?:/|$)', target)
                        if port_match:
                            port = int(port_match.group(1))
                        host_match = re.search(r'(?:https?://)?([^:/]+)', target)
                        if host_match:
                            ip_address = host_match.group(1)
                    
                    nmap_correlation = self.cms_detector.correlate_with_nmap(
                        egg_record_id=egg_record_id,
                        ip_address=ip_address,
                        port=port
                    )
                
                # Calculate priority for each path
                for path_data in paths_discovered:
                    if isinstance(path_data, dict):
                        path_dict = path_data.copy()
                    else:
                        # Convert string path to dict
                        path_dict = {'path': str(path_data), 'status': 200, 'size': 0, 'content_type': ''}
                    
                    # Calculate priority score
                    priority_data = self.priority_scorer.calculate_priority(
                        discovered_path=path_dict.get('path', ''),
                        status_code=path_dict.get('status', 0),
                        cms_detection=cms_detection,
                        nmap_correlation=nmap_correlation,
                        technology_fingerprint=technology_fingerprint,
                        content_length=path_dict.get('size', 0),
                    )
                    
                    # Add priority data to path dict
                    if priority_data:
                        path_dict['priority_score'] = priority_data.get('priority_score', 0.0)
                        path_dict['priority_factors'] = priority_data.get('priority_factors', [])
                    else:
                        path_dict['priority_score'] = 0.0
                        path_dict['priority_factors'] = []
                    
                    paths_with_priority.append(path_dict)
            except Exception as e:
                logger.warning(f"⚠️  Error calculating priority scores: {e}")
                # Fallback: use paths without priority scores
                paths_with_priority = paths_discovered
        else:
            paths_with_priority = paths_discovered
        
        # Store results in database if requested
        results_stored = 0
        if write_to_db and paths_with_priority:
            results_stored = self._store_enumeration_results(
                egg_record_id, 
                target, 
                paths_with_priority, 
                learned_patterns,
                cms_detection,
                technology_fingerprint
            )
        
        logger.info(f"🔔 Suzu enumeration complete: {len(paths_with_priority)} paths discovered in {duration:.2f}s")
        
        return {
            'success': True,
            'target': target,
            'paths_discovered': paths_with_priority,  # List of path dicts with priority scores
            'enumeration_results': enumeration_results,  # Full enumeration results from tools
            'duration': duration,
            'enumeration_duration': duration,
            'results_stored': results_stored,
            'cms_detection': cms_detection,  # Include CMS detection in return
            'enumeration_metadata': {
            'tool_used': enumeration_results[0].get('tool') if enumeration_results else None,
            'learned_patterns': learned_patterns,
                'smart_wordlist_size': len(smart_wordlist) if smart_wordlist else 0,
                'priority_wordlist_size': len(priority_wordlist) if priority_wordlist else 0,
                'vector_paths_used': len(vector_paths) if vector_paths else 0
            }
        }
    
    def _enumerate_url(self, url: str, egg_record_id: str, wordlist: Optional[Path] = None, learned_patterns: Optional[Dict] = None, priority_wordlist: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Enumerate a URL using available tools.
        
        Args:
            url: URL to enumerate
            egg_record_id: EggRecord UUID
            wordlist: Optional wordlist file path
            learned_patterns: Patterns learned from Kumo's data
            priority_wordlist: Optional priority wordlist (paths to check first)
        
        Returns:
            Enumeration results
        """
        # Use enhanced dirsearch if available (has metadata correlation)
        if self.enhanced_dirsearch and (self.dirsearch_path or priority_wordlist):
            return self._enumerate_with_enhanced_dirsearch(url, egg_record_id, wordlist, priority_wordlist)
        # Prefer ffuf > gobuster > dirsearch > custom Python
        elif self.ffuf_path and wordlist:
            return self._enumerate_with_ffuf(url, egg_record_id, wordlist)
        elif self.gobuster_path and wordlist:
            return self._enumerate_with_gobuster(url, egg_record_id, wordlist)
        elif self.dirsearch_path and wordlist:
            return self._enumerate_with_dirsearch(url, egg_record_id, wordlist)
        else:
            # Fallback to custom Python enumeration
            return self._enumerate_custom_python(url, egg_record_id, wordlist, learned_patterns)
    
    def _enumerate_with_enhanced_dirsearch(self, url: str, egg_record_id: str, wordlist: Optional[Path] = None, priority_wordlist: Optional[List[str]] = None) -> Dict[str, Any]:
        """Enumerate using enhanced dirsearch with metadata correlation"""
        try:
            results = self.enhanced_dirsearch.enumerate_with_metadata(
                egg_record_id=egg_record_id,
                target_url=url,
                priority_wordlist=priority_wordlist,
                wordlist_file=wordlist,
            )
            
            paths = []
            for result in results:
                paths.append({
                    'path': result.get('discovered_path', ''),
                    'status': result.get('status_code', 0),
                    'size': result.get('content_length', 0),
                    'content_type': result.get('content_type', ''),
                })
            
            return {
                'success': True,
                'tool': 'enhanced_dirsearch',
                'paths': paths,
                'count': len(paths)
            }
        except Exception as e:
            logger.error(f"❌ Enhanced dirsearch enumeration failed: {e}")
            return {'success': False, 'tool': 'enhanced_dirsearch', 'error': str(e), 'paths': []}
    
    def _enumerate_with_ffuf(self, url: str, egg_record_id: str, wordlist: Path) -> Dict[str, Any]:
        """Enumerate using ffuf"""
        try:
            output_file = Path(f'/tmp/suzu_ffuf_{egg_record_id}_{int(time.time())}.json')
            
            cmd = [
                self.ffuf_path,
                '-u', f'{url}/FUZZ',
                '-w', str(wordlist),
                '-o', str(output_file),
                '-of', 'json',
                '-t', '50',  # Threads
                '-mc', '200,204,301,302,307,401,403',  # Match codes
                '-timeout', '10',
                '-recursion', '-recursion-depth', '1',
                '-H', 'User-Agent: Suzu-Enumerator/1.0',
            ]
            
            logger.info(f"🔍 Running ffuf: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes max
            )
            
            paths = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        for item in data.get('results', []):
                            paths.append({
                                'path': item.get('url', ''),
                                'status': item.get('status', 0),
                                'size': item.get('length', 0),
                                'words': item.get('words', 0),
                            })
                except Exception as e:
                    logger.warning(f"Error parsing ffuf output: {e}")
            
            return {
                'success': result.returncode == 0,
                'tool': 'ffuf',
                'paths': paths,
                'count': len(paths)
            }
        except Exception as e:
            logger.error(f"❌ ffuf enumeration failed: {e}")
            return {'success': False, 'tool': 'ffuf', 'error': str(e), 'paths': []}
    
    def _enumerate_with_gobuster(self, url: str, egg_record_id: str, wordlist: Path) -> Dict[str, Any]:
        """Enumerate using gobuster"""
        try:
            cmd = [
                self.gobuster_path,
                'dir',
                '-u', url,
                '-w', str(wordlist),
                '-t', '50',
                '-q',  # Quiet mode
                '--timeout', '10s',
                '--status-codes', '200,204,301,302,307,401,403',
            ]
            
            logger.info(f"🔍 Running gobuster: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            paths = []
            for line in result.stdout.split('\n'):
                if line.strip() and ('Status:' in line or 'Found:' in line):
                    # Parse gobuster output
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[-1] if parts[-1].startswith('/') else f'/{parts[-1]}'
                        status = 200  # Default, gobuster shows status separately
                        paths.append({
                            'path': path,
                            'status': status,
                            'size': 0,
                        })
            
            return {
                'success': result.returncode == 0,
                'tool': 'gobuster',
                'paths': paths,
                'count': len(paths)
            }
        except Exception as e:
            logger.error(f"❌ gobuster enumeration failed: {e}")
            return {'success': False, 'tool': 'gobuster', 'error': str(e), 'paths': []}
    
    def _enumerate_with_dirsearch(self, url: str, egg_record_id: str, wordlist: Path) -> Dict[str, Any]:
        """Enumerate using dirsearch"""
        try:
            output_file = Path(f'/tmp/suzu_dirsearch_{egg_record_id}_{int(time.time())}.json')
            output_dir = output_file.parent
            
            cmd = [
                sys.executable,
                str(self.dirsearch_path),
                '-u', url,
                '-w', str(wordlist),
                '-o', str(output_file),
                '--format', 'json',
                '--threads', '20',
                '--timeout', '15',
                '--max-retries', '3',
                '--recursive', '1',
            ]
            
            logger.info(f"🔍 Running dirsearch: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(self.dirsearch_path.parent) if self.dirsearch_path.parent.exists() else None
            )
            
            paths = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                paths.append({
                                    'path': item.get('path', ''),
                                    'status': item.get('status', 0),
                                    'size': item.get('content-length', 0),
                                })
                except Exception as e:
                    logger.warning(f"Error parsing dirsearch output: {e}")
            
            return {
                'success': result.returncode == 0,
                'tool': 'dirsearch',
                'paths': paths,
                'count': len(paths)
            }
        except Exception as e:
            logger.error(f"❌ dirsearch enumeration failed: {e}")
            return {'success': False, 'tool': 'dirsearch', 'error': str(e), 'paths': []}
    
    def _enumerate_custom_python(self, url: str, egg_record_id: str, wordlist: Optional[Path] = None, learned_patterns: Optional[Dict] = None) -> Dict[str, Any]:
        """Fallback: Custom Python-based enumeration"""
        import requests
        
        logger.info("🔍 Using custom Python enumeration (no external tools available)")
        
        # Generate wordlist
        if learned_patterns and self.wordlist_manager:
            # Use smart wordlist from patterns
            wordlist_items = self.wordlist_manager.generate_smart_wordlist(learned_patterns)
        elif wordlist and wordlist.exists():
            # Use provided wordlist
            with open(wordlist, 'r') as f:
                wordlist_items = [line.strip() for line in f if line.strip()]
        else:
            # Use common paths
            wordlist_items = [
                'admin', 'api', 'backup', 'config', 'database', 'docs', 'files',
                'images', 'includes', 'js', 'login', 'panel', 'private', 'secure',
                'test', 'uploads', 'wp-admin', 'wp-content', '.git', '.env'
            ]
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Suzu-Enumerator/1.0',
            'Accept': '*/*',
        })
        
        paths = []
        for path_item in wordlist_items[:500]:  # Limit to 500 for custom enumeration
            try:
                test_url = urljoin(url, path_item)
                response = session.get(
                    test_url,
                    timeout=self.request_timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                    paths.append({
                        'path': path_item,
                        'status': response.status_code,
                        'size': len(response.content),
                    })
            except Exception:
                continue
        
        return {
            'success': True,
            'tool': 'custom_python',
            'paths': paths,
            'count': len(paths)
        }
    
    def _store_enumeration_results(
        self, 
        egg_record_id: str, 
        target: str, 
        paths: List[Dict], 
        learned_patterns: Optional[Dict] = None,
        cms_detection: Optional[Dict] = None,
        technology_fingerprint: Optional[Dict] = None
    ) -> int:
        """
        Store enumeration results in DirectoryEnumerationResult model with metadata correlation.
        """
        try:
            db = connections['customer_eggs']
            stored = 0
            
            # Get Nmap correlation data once
            # Try to get IP address and port from target for better correlation
            nmap_correlation = None
            if self.cms_detector:
                # Extract IP/port from target if available, otherwise use egg_record_id
                ip_address = None
                port = None
                if target:
                    # Try to extract port from target URL
                    import re
                    port_match = re.search(r':(\d+)(?:/|$)', target)
                    if port_match:
                        port = int(port_match.group(1))
                    # Extract hostname/IP (will be resolved by Nmap correlation)
                    host_match = re.search(r'(?:https?://)?([^:/]+)', target)
                    if host_match:
                        ip_address = host_match.group(1)
                
                # Use enhanced correlation with IP/port if available
                nmap_correlation = self.cms_detector.correlate_with_nmap(
                    egg_record_id=egg_record_id,
                    ip_address=ip_address,
                    port=port
                )
            
            with db.cursor() as cursor:
                for path_data in paths:
                    try:
                        import uuid
                        discovered_path = path_data.get('path', '')
                        status_code = path_data.get('status', 0)
                        content_length = path_data.get('size', 0)
                        content_type = path_data.get('content_type', '')
                        
                        # Detect CMS from path if not already detected
                        path_cms_detection = None
                        if self.cms_detector:
                            path_cms_detection = self.cms_detector.detect_cms_from_path(discovered_path)
                            # Use path detection if no previous CMS detection
                            if not cms_detection and path_cms_detection:
                                cms_detection = path_cms_detection
                        
                        # Calculate priority score
                        priority_data = None
                        if self.priority_scorer:
                            priority_data = self.priority_scorer.calculate_priority(
                                discovered_path=discovered_path,
                                status_code=status_code,
                                cms_detection=cms_detection or path_cms_detection,
                                nmap_correlation=nmap_correlation,
                                technology_fingerprint=technology_fingerprint,
                                content_length=content_length,
                            )
                        
                        # Extract Nmap data if available
                        nmap_scan_id = None
                        correlated_port = None
                        correlated_service_name = None
                        correlated_service_version = None
                        correlated_product = None
                        correlated_cpe = None
                        
                        if nmap_correlation:
                            nmap_scan_id = nmap_correlation.get('nmap_scan_id')
                            correlated_port = nmap_correlation.get('port')
                            correlated_service_name = nmap_correlation.get('service_name')
                            correlated_service_version = nmap_correlation.get('service_version')
                            correlated_product = nmap_correlation.get('product')
                            correlated_cpe = nmap_correlation.get('cpe', [])
                        
                        # Insert into DirectoryEnumerationResult
                        cursor.execute("""
                            INSERT INTO customer_eggs_eggrecords_general_models_directoryenumerationresult (
                                id, egg_record_id, discovered_path, path_status_code,
                                path_content_length, path_content_type, path_response_time_ms,
                                nmap_scan_id, correlated_port, correlated_service_name,
                                correlated_service_version, correlated_product, correlated_cpe,
                                technology_fingerprint_id, detected_cms, detected_cms_version,
                                detected_framework, detected_framework_version,
                                cms_detection_method, cms_detection_confidence, cms_detection_signatures,
                                priority_score, priority_factors,
                                enumeration_tool, wordlist_used, enumeration_depth,
                                discovered_at, created_at, updated_at
                            ) VALUES (
                                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                            )
                            ON CONFLICT (id) DO NOTHING
                        """, [
                            str(uuid.uuid4()),  # id
                            str(egg_record_id),  # egg_record_id
                            discovered_path,  # discovered_path
                            status_code,  # path_status_code
                            content_length,  # path_content_length
                            content_type,  # path_content_type
                            path_data.get('response_time_ms'),  # path_response_time_ms
                            nmap_scan_id,  # nmap_scan_id
                            correlated_port,  # correlated_port
                            correlated_service_name,  # correlated_service_name
                            correlated_service_version,  # correlated_service_version
                            correlated_product,  # correlated_product
                            json.dumps(correlated_cpe) if correlated_cpe else None,  # correlated_cpe
                            technology_fingerprint.get('id') if technology_fingerprint else None,  # technology_fingerprint_id
                            (cms_detection or path_cms_detection).get('cms') if (cms_detection or path_cms_detection) else None,  # detected_cms
                            (cms_detection or path_cms_detection).get('version') if (cms_detection or path_cms_detection) else None,  # detected_cms_version
                            None,  # detected_framework (can be extracted from technology_fingerprint)
                            None,  # detected_framework_version
                            (cms_detection or path_cms_detection).get('method') if (cms_detection or path_cms_detection) else None,  # cms_detection_method
                            (cms_detection or path_cms_detection).get('confidence', 0.0) if (cms_detection or path_cms_detection) else 0.0,  # cms_detection_confidence
                            json.dumps((cms_detection or path_cms_detection).get('signatures', [])) if (cms_detection or path_cms_detection) else None,  # cms_detection_signatures
                            priority_data.get('priority_score', 0.0) if priority_data else 0.0,  # priority_score
                            json.dumps(priority_data.get('priority_factors', [])) if priority_data else None,  # priority_factors
                            path_data.get('tool', 'suzu'),  # enumeration_tool
                            None,  # wordlist_used (can be added if tracked)
                            1,  # enumeration_depth
                            timezone.now(),  # discovered_at
                            timezone.now(),  # created_at
                            timezone.now(),  # updated_at
                        ])
                        stored += 1
                    except Exception as e:
                        logger.debug(f"Error storing path {path_data}: {e}")
                        import traceback
                        logger.debug(traceback.format_exc())
                        continue
            
            db.commit()
            logger.info(f"💾 Stored {stored} enumeration results with metadata correlation")
            return stored
            
        except Exception as e:
            logger.error(f"❌ Error storing enumeration results: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return 0


def get_suzu_enumerator(parallel_enabled: bool = True):
    """Get or create the singleton Suzu enumerator instance"""
    global _suzu_enumerator_instance
    if not hasattr(get_suzu_enumerator, '_suzu_enumerator_instance'):
        get_suzu_enumerator._suzu_enumerator_instance = SuzuDirectoryEnumerator(parallel_enabled=parallel_enabled)
    return get_suzu_enumerator._suzu_enumerator_instance


# Global instance
_suzu_enumerator_instance = None

