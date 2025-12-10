#!/usr/bin/env python3
"""
Tor Proxy Integration for Reconnaissance Services
================================================

Provides Tor SOCKS proxy support for anonymous scanning.
Supports both HTTP requests and socket connections.

Author: EGO Revolution
Version: 1.0.0
"""

import socket
import logging
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Try to import SOCKS proxy support
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    logger.warning("⚠️  PySocks not installed - install with: pip install pysocks")

# Try to import requests with SOCKS support
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.connection import create_connection
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("⚠️  Requests not available")


class TorProxy:
    """
    Tor SOCKS proxy manager for anonymous network connections.
    """
    
    def __init__(self, socks_host: str = '127.0.0.1', socks_port: int = 9050, enabled: bool = True):
        """
        Initialize Tor proxy manager.
        
        Args:
            socks_host: Tor SOCKS proxy host (default: 127.0.0.1)
            socks_port: Tor SOCKS proxy port (default: 9050)
            enabled: Whether to use Tor (default: True)
        """
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.enabled = enabled and SOCKS_AVAILABLE
        self._tor_available = None
        self._last_check = 0
        self._check_interval = 60  # Check every 60 seconds
        
        if self.enabled:
            self._check_tor_availability()
    
    def _check_tor_availability(self) -> bool:
        """
        Check if Tor SOCKS proxy is available.
        
        Returns:
            True if Tor is available, False otherwise
        """
        # Cache check result for 60 seconds
        current_time = time.time()
        if self._tor_available is not None and (current_time - self._last_check) < self._check_interval:
            return self._tor_available
        
        self._last_check = current_time
        
        if not SOCKS_AVAILABLE:
            self._tor_available = False
            logger.debug("Tor proxy unavailable: PySocks not installed")
            return False
        
        try:
            # Try to connect to Tor SOCKS port
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            result = test_sock.connect_ex((self.socks_host, self.socks_port))
            test_sock.close()
            
            if result == 0:
                self._tor_available = True
                logger.info(f"✅ Tor SOCKS proxy available at {self.socks_host}:{self.socks_port}")
                return True
            else:
                self._tor_available = False
                logger.debug(f"Tor SOCKS proxy not available at {self.socks_host}:{self.socks_port}")
                return False
        except Exception as e:
            self._tor_available = False
            logger.debug(f"Tor availability check failed: {e}")
            return False
    
    def is_available(self) -> bool:
        """
        Check if Tor is currently available.
        
        Returns:
            True if Tor is enabled and available
        """
        if not self.enabled:
            return False
        return self._check_tor_availability()
    
    def get_socks_proxy(self) -> Optional[Dict[str, Any]]:
        """
        Get SOCKS proxy configuration for requests library.
        
        Returns:
            Dict with proxy configuration or None if Tor unavailable
        """
        if not self.is_available():
            return None
        
        return {
            'http': f'socks5h://{self.socks_host}:{self.socks_port}',
            'https': f'socks5h://{self.socks_host}:{self.socks_port}'
        }
    
    def create_socks_socket(self, family: int = socket.AF_INET, 
                           socket_type: int = socket.SOCK_STREAM) -> Optional[socket.socket]:
        """
        Create a socket configured to use Tor SOCKS proxy.
        
        Args:
            family: Socket family (AF_INET, AF_INET6)
            socket_type: Socket type (SOCK_STREAM, SOCK_DGRAM)
            
        Returns:
            Configured socket or None if Tor unavailable
        """
        if not self.is_available():
            return None
        
        try:
            sock = socks.socksocket(family, socket_type)
            sock.set_proxy(socks.SOCKS5, self.socks_host, self.socks_port)
            return sock
        except Exception as e:
            logger.warning(f"Failed to create SOCKS socket: {e}")
            return None
    
    def get_requests_session(self) -> Optional[Any]:
        """
        Get a requests Session configured to use Tor.
        
        Returns:
            requests.Session with Tor proxy or None if unavailable
        """
        if not self.is_available() or not REQUESTS_AVAILABLE:
            return None
        
        try:
            session = requests.Session()
            proxies = self.get_socks_proxy()
            if proxies:
                session.proxies.update(proxies)
                logger.debug("Created requests session with Tor proxy")
            return session
        except Exception as e:
            logger.warning(f"Failed to create Tor requests session: {e}")
            return None
    
    def rotate_identity(self) -> bool:
        """
        Request new Tor circuit (new IP address).
        Requires Tor Control Port (default: 9051).
        
        Returns:
            True if rotation successful, False otherwise
        """
        if not self.is_available():
            return False
        
        try:
            import stem
            from stem import Signal
            from stem.control import Controller
            
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                logger.info("🔄 Tor identity rotated (new IP address)")
                # Wait for circuit to be established
                time.sleep(5)
                return True
        except ImportError:
            logger.debug("Stem library not available - cannot rotate Tor identity")
            return False
        except Exception as e:
            logger.warning(f"Failed to rotate Tor identity: {e}")
            return False
    
    def get_current_ip(self) -> Optional[str]:
        """
        Get current public IP address through Tor.
        
        Returns:
            IP address string or None if unavailable
        """
        if not self.is_available():
            return None
        
        try:
            session = self.get_requests_session()
            if not session:
                return None
            
            # Use a service that shows IP
            response = session.get('https://api.ipify.org?format=json', timeout=10)
            if response.status_code == 200:
                ip_data = response.json()
                return ip_data.get('ip')
        except Exception as e:
            logger.debug(f"Failed to get current IP through Tor: {e}")
            return None


# Global Tor proxy instance
_tor_proxy_instance = None

def get_tor_proxy(enabled: bool = True, socks_host: str = '127.0.0.1', 
                  socks_port: int = 9050) -> TorProxy:
    """
    Get or create global Tor proxy instance.
    
    Args:
        enabled: Whether to enable Tor
        socks_host: Tor SOCKS host
        socks_port: Tor SOCKS port
        
    Returns:
        TorProxy instance
    """
    global _tor_proxy_instance
    
    if _tor_proxy_instance is None:
        _tor_proxy_instance = TorProxy(
            enabled=enabled,
            socks_host=socks_host,
            socks_port=socks_port
        )
    
    return _tor_proxy_instance


