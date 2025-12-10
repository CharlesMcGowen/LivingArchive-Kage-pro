#!/usr/bin/env python3
"""
SSL/TLS Certificate Analyzer
=============================

Detects and analyzes SSL/TLS certificate issues:
- Certificate validation errors
- Expired certificates
- Self-signed certificates
- Certificate chain issues
- Weak cipher suites
- TLS version detection

Reports findings to database but doesn't block scanning.
"""

import socket
import ssl
import warnings
import urllib3
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from urllib.parse import urlparse
import logging

# Suppress warnings - we'll report issues in our models
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

logger = logging.getLogger(__name__)


class SSLCertificateAnalyzer:
    """Analyze SSL/TLS certificates and report issues."""
    
    def __init__(self):
        self.timeout = 5.0
    
    def analyze_certificate(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Analyze SSL/TLS certificate for a target.
        
        Args:
            target: Hostname or IP address
            port: Port number (default 443)
            
        Returns:
            Dictionary with certificate analysis results
        """
        result = {
            'target': target,
            'port': port,
            'ssl_enabled': False,
            'certificate_valid': False,
            'certificate_errors': [],
            'certificate_info': {},
            'tls_version': None,
            'cipher_suite': None,
            'expired': False,
            'self_signed': False,
            'days_until_expiry': None,
            'analyzed_at': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            # Parse target to get hostname
            if '://' in target:
                parsed = urlparse(target)
                hostname = parsed.hostname or target
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            else:
                hostname = target
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False  # We'll check manually
            context.verify_mode = ssl.CERT_NONE  # Don't fail on invalid certs
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result['ssl_enabled'] = True
                    result['tls_version'] = ssock.version()
                    result['cipher_suite'] = ssock.cipher()
                    
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    if cert:
                        result['certificate_info'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                        }
                        
                        # Check expiration
                        if cert.get('notAfter'):
                            try:
                                # Parse certificate date (format: "Dec 31 23:59:59 2024 GMT")
                                from email.utils import parsedate_to_datetime
                                expiry_str = cert['notAfter']
                                # Try multiple date parsing methods
                                try:
                                    expiry = parsedate_to_datetime(expiry_str)
                                except:
                                    # Fallback to manual parsing
                                    import re
                                    # Format: "Dec 31 23:59:59 2024 GMT"
                                    match = re.match(r'(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})', expiry_str)
                                    if match:
                                        from datetime import datetime
                                        month, day, hour, minute, second, year = match.groups()
                                        month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                                                    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                                        expiry = datetime(int(year), month_map[month], int(day), int(hour), int(minute), int(second), tzinfo=timezone.utc)
                                    else:
                                        raise ValueError("Could not parse date")
                                
                                now = datetime.now(timezone.utc)
                                
                                if expiry < now:
                                    result['expired'] = True
                                    result['certificate_errors'].append('certificate_expired')
                                else:
                                    result['days_until_expiry'] = (expiry - now).days
                            except Exception as e:
                                logger.debug(f"Could not parse certificate expiry: {e}")
                        
                        # Check if self-signed
                        subject = result['certificate_info'].get('subject', {})
                        issuer = result['certificate_info'].get('issuer', {})
                        if subject == issuer:
                            result['self_signed'] = True
                            result['certificate_errors'].append('self_signed_certificate')
                        
                        # Try to validate certificate properly
                        try:
                            context_valid = ssl.create_default_context()
                            context_valid.check_hostname = True
                            context_valid.verify_mode = ssl.CERT_REQUIRED
                            
                            with socket.create_connection((hostname, port), timeout=self.timeout) as sock2:
                                with context_valid.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                                    result['certificate_valid'] = True
                        except ssl.SSLError as e:
                            result['certificate_valid'] = False
                            error_msg = str(e).lower()
                            
                            if 'certificate verify failed' in error_msg:
                                result['certificate_errors'].append('certificate_verify_failed')
                            elif 'hostname' in error_msg:
                                result['certificate_errors'].append('hostname_mismatch')
                            elif 'expired' in error_msg:
                                result['certificate_errors'].append('certificate_expired')
                            else:
                                result['certificate_errors'].append('ssl_error')
                            
                            logger.debug(f"SSL validation failed for {hostname}:{port}: {e}")
                        except Exception as e:
                            result['certificate_errors'].append('validation_error')
                            logger.debug(f"Certificate validation error for {hostname}:{port}: {e}")
        
        except socket.timeout:
            result['certificate_errors'].append('connection_timeout')
            logger.debug(f"Connection timeout for {hostname}:{port}")
        except socket.gaierror as e:
            result['certificate_errors'].append('dns_error')
            logger.debug(f"DNS error for {hostname}:{port}: {e}")
        except ssl.SSLError as e:
            result['ssl_enabled'] = True  # SSL attempted but failed
            result['certificate_errors'].append('ssl_error')
            logger.debug(f"SSL error for {hostname}:{port}: {e}")
        except ConnectionRefusedError:
            result['certificate_errors'].append('connection_refused')
            logger.debug(f"Connection refused for {hostname}:{port}")
        except Exception as e:
            result['certificate_errors'].append('unknown_error')
            logger.debug(f"Unknown error analyzing certificate for {hostname}:{port}: {e}")
        
        # Set overall validity
        if not result['certificate_errors']:
            result['certificate_valid'] = True
        
        return result
    
    def analyze_http_response_ssl(self, url: str, response: Optional[Any] = None) -> Dict[str, Any]:
        """
        Analyze SSL from HTTP response (if available).
        
        Args:
            url: URL that was accessed
            response: requests.Response object (optional)
            
        Returns:
            SSL analysis results
        """
        result = {
            'url': url,
            'ssl_warning_suppressed': True,  # We suppress warnings
            'ssl_issues_detected': False,
            'ssl_issues': []
        }
        
        if response and hasattr(response, 'url'):
            parsed = urlparse(response.url)
            if parsed.scheme == 'https':
                # Analyze certificate if we have the response
                cert_analysis = self.analyze_certificate(parsed.hostname or url, parsed.port or 443)
                result.update(cert_analysis)
                result['ssl_issues_detected'] = len(cert_analysis.get('certificate_errors', [])) > 0
                result['ssl_issues'] = cert_analysis.get('certificate_errors', [])
        
        return result

