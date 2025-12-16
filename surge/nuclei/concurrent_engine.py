#!/usr/bin/env python3
"""
Concurrent Nuclei Engine Manager
=================================

Manages multiple ThreadSafeNucleiEngine instances for concurrent scanning.
Provides engine pooling, session management, and resource optimization.

Author: EGO Revolution Team
Version: 2.0.0 - Concurrent Scanning Support
"""

import logging
import threading
import uuid
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from queue import Queue, Empty

from .class_based_api import NucleiEngine, ScanConfig, ScanStatus, VulnerabilityFinding, ScanProgress

logger = logging.getLogger(__name__)


@dataclass
class EnginePoolConfig:
    """Configuration for engine pool"""
    max_engines: int = 5  # Maximum concurrent engines
    engine_reuse: bool = True  # Reuse engines across scans
    idle_timeout_seconds: int = 300  # Close idle engines after this time
    max_scans_per_engine: int = 100  # Maximum scans per engine before recreation


class ConcurrentNucleiManager:
    """
    Manages multiple ThreadSafeNucleiEngine instances for concurrent scanning.
    Provides engine pooling and automatic resource management.
    """
    
    def __init__(self, base_config: Optional[ScanConfig] = None, pool_config: Optional[EnginePoolConfig] = None):
        """
        Initialize concurrent manager.
        
        Args:
            base_config: Base configuration for all engines
            pool_config: Engine pool configuration
        """
        self.base_config = base_config or ScanConfig(use_thread_safe=True)
        self.pool_config = pool_config or EnginePoolConfig()
        
        # Ensure thread-safe mode is enabled
        self.base_config.use_thread_safe = True
        
        # Engine pool
        self._available_engines: Queue = Queue()
        self._active_engines: Dict[str, NucleiEngine] = {}
        self._engine_scan_counts: Dict[str, int] = {}
        self._engine_lock = threading.RLock()
        
        # Scan session tracking
        self._scan_sessions: Dict[str, str] = {}  # scan_id -> engine_id
        self._session_lock = threading.RLock()
        
        # Statistics
        self._total_scans = 0
        self._active_scans = 0
        
        logger.info(f"✅ ConcurrentNucleiManager initialized (max_engines={self.pool_config.max_engines})")
    
    def _create_engine(self) -> NucleiEngine:
        """Create a new ThreadSafeNucleiEngine instance"""
        engine_id = str(uuid.uuid4())
        config = ScanConfig(**self.base_config.__dict__)
        config.use_thread_safe = True
        
        engine = NucleiEngine(engine_id=engine_id, config=config)
        
        with self._engine_lock:
            self._engine_scan_counts[engine_id] = 0
        
        logger.info(f"Created new ThreadSafeNucleiEngine: {engine_id}")
        return engine
    
    def _get_engine(self) -> NucleiEngine:
        """Get an available engine from pool or create new one"""
        # Try to get from pool
        try:
            engine = self._available_engines.get_nowait()
            logger.debug(f"Reusing engine from pool: {engine.engine_id}")
            return engine
        except Empty:
            pass
        
        # Check if we can create a new engine
        with self._engine_lock:
            total_engines = len(self._active_engines) + self._available_engines.qsize()
            if total_engines < self.pool_config.max_engines:
                return self._create_engine()
            else:
                # Wait for an engine to become available
                logger.warning(f"Engine pool exhausted, waiting for available engine...")
                return self._available_engines.get()  # Block until available
    
    def _return_engine(self, engine: NucleiEngine):
        """Return engine to pool or close if needed"""
        engine_id = engine.engine_id
        
        with self._engine_lock:
            scan_count = self._engine_scan_counts.get(engine_id, 0)
            
            # Check if engine should be closed
            if scan_count >= self.pool_config.max_scans_per_engine:
                logger.info(f"Closing engine {engine_id} (reached max scans: {scan_count})")
                engine.close()
                del self._engine_scan_counts[engine_id]
                if engine_id in self._active_engines:
                    del self._active_engines[engine_id]
                return
            
            # Return to pool if reuse is enabled
            if self.pool_config.engine_reuse:
                self._available_engines.put(engine)
                logger.debug(f"Returned engine {engine_id} to pool")
            else:
                engine.close()
                del self._engine_scan_counts[engine_id]
                if engine_id in self._active_engines:
                    del self._active_engines[engine_id]
    
    def scan(self, targets: List[str], 
             config: Optional[ScanConfig] = None,
             egg_record_id: Optional[str] = None,
             on_vulnerability: Optional[Callable[[VulnerabilityFinding], None]] = None,
             on_progress: Optional[Callable[[ScanProgress], None]] = None,
             on_state_change: Optional[Callable[[ScanStatus], None]] = None,
             on_error: Optional[Callable[[str], None]] = None) -> str:
        """
        Execute concurrent scan on targets.
        
        Args:
            targets: List of target URLs/IPs
            config: Optional scan configuration (merged with base config)
            egg_record_id: Optional EggRecord ID for tracking
            on_vulnerability: Optional callback for vulnerabilities
            on_progress: Optional callback for progress updates
            on_state_change: Optional callback for state changes
            on_error: Optional callback for errors
            
        Returns:
            Scan session ID
        """
        # Get or create engine
        engine = self._get_engine()
        engine_id = engine.engine_id
        
        # Merge configs
        if config:
            merged_config = ScanConfig(**self.base_config.__dict__)
            for key, value in config.__dict__.items():
                if value is not None and value != merged_config.__dict__.get(key):
                    setattr(merged_config, key, value)
            merged_config.use_thread_safe = True  # Force thread-safe
            engine.config = merged_config
        
        # Register callbacks
        if on_vulnerability:
            engine.on_vulnerability.append(on_vulnerability)
        if on_progress:
            engine.on_progress.append(on_progress)
        if on_state_change:
            engine.on_state_change.append(on_state_change)
        if on_error:
            engine.on_error.append(on_error)
        
        # Track engine as active
        with self._engine_lock:
            self._active_engines[engine_id] = engine
            self._engine_scan_counts[engine_id] = self._engine_scan_counts.get(engine_id, 0) + 1
        
        # Execute scan
        scan_id = engine.scan(targets, egg_record_id=egg_record_id)
        
        # Track scan session
        with self._session_lock:
            self._scan_sessions[scan_id] = engine_id
        
        # Update statistics
        with self._engine_lock:
            self._total_scans += 1
            self._active_scans += 1
        
        logger.info(f"Started concurrent scan {scan_id} on engine {engine_id}")
        
        # Set up cleanup callback
        def cleanup_on_complete(status: ScanStatus):
            if status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                with self._session_lock:
                    if scan_id in self._scan_sessions:
                        del self._scan_sessions[scan_id]
                
                with self._engine_lock:
                    self._active_scans -= 1
                
                # Return engine to pool
                self._return_engine(engine)
        
        engine.on_state_change.append(cleanup_on_complete)
        
        return scan_id
    
    def get_scan_state(self, scan_id: str) -> Optional[Dict]:
        """Get state of a specific scan"""
        with self._session_lock:
            engine_id = self._scan_sessions.get(scan_id)
            if not engine_id:
                return None
        
        with self._engine_lock:
            engine = self._active_engines.get(engine_id)
            if not engine:
                return None
        
        return engine.get_state()
    
    def pause_scan(self, scan_id: str) -> bool:
        """Pause a specific scan"""
        with self._session_lock:
            engine_id = self._scan_sessions.get(scan_id)
            if not engine_id:
                return False
        
        with self._engine_lock:
            engine = self._active_engines.get(engine_id)
            if not engine:
                return False
        
        engine.pause()
        return True
    
    def resume_scan(self, scan_id: str) -> bool:
        """Resume a specific scan"""
        with self._session_lock:
            engine_id = self._scan_sessions.get(scan_id)
            if not engine_id:
                return False
        
        with self._engine_lock:
            engine = self._active_engines.get(engine_id)
            if not engine:
                return False
        
        engine.resume()
        return True
    
    def get_statistics(self) -> Dict:
        """Get manager statistics"""
        with self._engine_lock:
            return {
                'total_scans': self._total_scans,
                'active_scans': self._active_scans,
                'active_engines': len(self._active_engines),
                'available_engines': self._available_engines.qsize(),
                'total_engines': len(self._active_engines) + self._available_engines.qsize(),
            }
    
    def close_all(self):
        """Close all engines and cleanup"""
        logger.info("Closing all engines...")
        
        with self._engine_lock:
            # Close active engines
            for engine in list(self._active_engines.values()):
                try:
                    engine.close()
                except Exception as e:
                    logger.error(f"Error closing engine {engine.engine_id}: {e}")
            
            # Close pooled engines
            while not self._available_engines.empty():
                try:
                    engine = self._available_engines.get_nowait()
                    engine.close()
                except Exception as e:
                    logger.error(f"Error closing pooled engine: {e}")
            
            self._active_engines.clear()
            self._engine_scan_counts.clear()
        
        logger.info("All engines closed")


class ThreadSafeNucleiEngine(NucleiEngine):
    """
    Convenience wrapper that ensures ThreadSafeNucleiEngine is always used.
    This is a simpler interface for single-engine concurrent scanning.
    """
    
    def __init__(self, engine_id: Optional[str] = None, config: Optional[ScanConfig] = None):
        """
        Initialize ThreadSafeNucleiEngine wrapper.
        
        Args:
            engine_id: Unique engine identifier (auto-generated if None)
            config: Scan configuration (defaults used if None)
        """
        config = config or ScanConfig()
        config.use_thread_safe = True  # Force thread-safe mode
        
        super().__init__(engine_id=engine_id, config=config)
        
        logger.info(f"✅ ThreadSafeNucleiEngine initialized: {self.engine_id}")
