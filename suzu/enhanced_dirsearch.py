#!/usr/bin/env python3
"""
Enhanced Dirsearch Wrapper for Suzu
Provides metadata correlation and priority-based enumeration
Future: Golang acceleration support
"""

import subprocess
import logging
import json
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class EnhancedDirsearch:
    """
    Enhanced dirsearch wrapper with:
    - Metadata correlation
    - Priority-based enumeration
    - Golang acceleration (future)
    """
    
    def __init__(self, dirsearch_path: Optional[Path] = None):
        """
        Initialize enhanced dirsearch.
        
        Args:
            dirsearch_path: Path to dirsearch.py (auto-detected if None)
        """
        self.dirsearch_path = dirsearch_path or self._find_dirsearch()
        self.golang_available = self._check_golang_dirsearch()
        logger.info(f"🔍 Enhanced dirsearch initialized (Golang: {self.golang_available})")
    
    def _find_dirsearch(self) -> Optional[Path]:
        """Find dirsearch installation"""
        possible_paths = [
            Path('/usr/bin/dirsearch'),
            Path('/usr/local/bin/dirsearch'),
            Path('/opt/dirsearch/dirsearch.py'),
            Path('/mnt/webapps-nvme/tools/dirsearch/dirsearch.py'),
            Path('/mnt/webapps-nvme/artificial_intelligence/personalities/reconnaissance/kage/tools/dirsearch/dirsearch.py'),
        ]
        
        for path in possible_paths:
            if path.exists():
                return path
        
        return None
    
    def _check_golang_dirsearch(self) -> bool:
        """Check if Golang dirsearch is available (future implementation)"""
        # TODO: Check for compiled Go binary
        # For now, return False
        return False
    
    def enumerate_with_metadata(
        self,
        egg_record_id: str,
        target_url: str,
        priority_wordlist: Optional[List[str]] = None,
        wordlist_file: Optional[Path] = None,
        max_threads: int = 20,
        timeout: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Run dirsearch with metadata correlation.
        
        Args:
            egg_record_id: UUID of EggRecord
            target_url: Target URL to enumerate
            priority_wordlist: List of priority paths to check first
            wordlist_file: Path to wordlist file
            max_threads: Maximum threads for enumeration
            timeout: Request timeout in seconds
        
        Returns:
            List of enumeration results with metadata
        """
        if not self.dirsearch_path:
            logger.warning("⚠️  Dirsearch not found, using fallback enumeration")
            return self._fallback_enumeration(target_url, priority_wordlist)
        
        # Use Golang dirsearch if available (faster)
        if self.golang_available:
            results = self._run_golang_dirsearch(
                target_url, priority_wordlist, wordlist_file, max_threads, timeout
            )
        else:
            results = self._run_python_dirsearch(
                target_url, priority_wordlist, wordlist_file, max_threads, timeout
            )
        
        # Enrich results with metadata
        enriched_results = []
        for result in results:
            enriched = self._enrich_with_metadata(egg_record_id, result, target_url)
            enriched_results.append(enriched)
        
        return enriched_results
    
    def _run_python_dirsearch(
        self,
        target_url: str,
        priority_wordlist: Optional[List[str]],
        wordlist_file: Optional[Path],
        max_threads: int,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Run Python dirsearch"""
        if not self.dirsearch_path:
            return []
        
        # Create temporary wordlist if priority wordlist provided
        temp_wordlist = None
        if priority_wordlist:
            import tempfile
            temp_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            temp_wordlist.write('\n'.join(priority_wordlist))
            temp_wordlist.close()
            wordlist_file = Path(temp_wordlist.name)
        
        # Build dirsearch command
        cmd = [
            'python3',
            str(self.dirsearch_path),
            '-u', target_url,
            '-t', str(max_threads),
            '--timeout', str(timeout),
            '--json-report', '-',  # Output to stdout as JSON
        ]
        
        if wordlist_file:
            cmd.extend(['-w', str(wordlist_file)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute max
            )
            
            # Parse JSON output
            if result.returncode == 0 and result.stdout:
                try:
                    json_data = json.loads(result.stdout)
                    return self._parse_dirsearch_json(json_data, target_url)
                except json.JSONDecodeError:
                    # Fallback to text parsing
                    return self._parse_dirsearch_text(result.stdout, target_url)
        except subprocess.TimeoutExpired:
            logger.warning("Dirsearch timed out")
        except Exception as e:
            logger.error(f"Error running dirsearch: {e}")
        finally:
            # Clean up temp wordlist
            if temp_wordlist:
                try:
                    Path(temp_wordlist.name).unlink()
                except:
                    pass
        
        return []
    
    def _run_golang_dirsearch(
        self,
        target_url: str,
        priority_wordlist: Optional[List[str]],
        wordlist_file: Optional[Path],
        max_threads: int,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """
        Run Golang dirsearch (future implementation).
        This will be faster and more efficient than Python version.
        """
        # TODO: Implement Golang dirsearch integration
        logger.info("Golang dirsearch not yet implemented, falling back to Python")
        return self._run_python_dirsearch(
            target_url, priority_wordlist, wordlist_file, max_threads, timeout
        )
    
    def _parse_dirsearch_json(self, json_data: Dict, target_url: str) -> List[Dict[str, Any]]:
        """Parse dirsearch JSON output"""
        results = []
        
        # Dirsearch JSON format varies, handle common structures
        if isinstance(json_data, dict):
            for path, data in json_data.items():
                if isinstance(data, dict):
                    results.append({
                        'discovered_path': path,
                        'status_code': data.get('status', 0),
                        'content_length': data.get('content-length', 0),
                        'content_type': data.get('content-type', ''),
                    })
        
        return results
    
    def _parse_dirsearch_text(self, text_output: str, target_url: str) -> List[Dict[str, Any]]:
        """Parse dirsearch text output (fallback)"""
        results = []
        
        # Parse common dirsearch output formats
        # Format: [STATUS] PATH (SIZE) - TIME
        pattern = r'\[(\d{3})\]\s+([^\s]+)\s+\((\d+)\)'
        
        for line in text_output.split('\n'):
            match = re.search(pattern, line)
            if match:
                status_code = int(match.group(1))
                path = match.group(2)
                content_length = int(match.group(3))
                
                results.append({
                    'discovered_path': path,
                    'status_code': status_code,
                    'content_length': content_length,
                    'content_type': '',
                })
        
        return results
    
    def _enrich_with_metadata(
        self,
        egg_record_id: str,
        result: Dict[str, Any],
        target_url: str,
    ) -> Dict[str, Any]:
        """
        Enrich enumeration result with metadata.
        This will be called by directory_enumerator to add:
        - Nmap correlation
        - CMS detection
        - Technology fingerprints
        - Priority scoring
        """
        # Base enrichment - full enrichment happens in directory_enumerator
        result['egg_record_id'] = egg_record_id
        result['target_url'] = target_url
        result['enumeration_tool'] = 'dirsearch'
        
        return result
    
    def _fallback_enumeration(
        self,
        target_url: str,
        priority_wordlist: Optional[List[str]],
    ) -> List[Dict[str, Any]]:
        """
        Fallback enumeration using requests library.
        Used when dirsearch is not available.
        """
        import requests
        from urllib.parse import urljoin
        
        results = []
        wordlist = priority_wordlist or ['/admin', '/api', '/config', '/.env']
        
        for path in wordlist:
            try:
                full_url = urljoin(target_url, path)
                response = requests.get(full_url, timeout=5, allow_redirects=False)
                
                results.append({
                    'discovered_path': path,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('Content-Type', ''),
                })
            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")
        
        return results

