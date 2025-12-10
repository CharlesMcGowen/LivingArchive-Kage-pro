#!/usr/bin/env python3
"""
Fallback Storage System for Reconnaissance Services
===================================================

Provides JSON file-based storage when Django/database is unavailable.
Services can continue working independently and sync data when DB comes back.

Author: EGO Revolution
Version: 1.0.0
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import threading
import time

logger = logging.getLogger(__name__)

# Storage directory for fallback data
STORAGE_DIR = Path('/mnt/webapps-nvme/artificial_intelligence/personalities/reconnaissance/fallback_storage')
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Lock for thread-safe file operations
_file_lock = threading.Lock()


class FallbackStorage:
    """JSON-based fallback storage for when database is unavailable"""
    
    def __init__(self, service_name: str):
        """
        Initialize fallback storage for a service.
        
        Args:
            service_name: Name of the service (kage, kumo, ryu)
        """
        self.service_name = service_name
        self.storage_dir = STORAGE_DIR / service_name
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # File paths
        self.scan_queue_file = self.storage_dir / 'scan_queue.json'
        self.completed_scans_file = self.storage_dir / 'completed_scans.json'
        self.pending_uploads_file = self.storage_dir / 'pending_uploads.json'
        
        # Initialize files if they don't exist
        self._init_files()
    
    def _init_files(self):
        """Initialize JSON files with empty structures"""
        with _file_lock:
            if not self.scan_queue_file.exists():
                self._write_json(self.scan_queue_file, [])
            if not self.completed_scans_file.exists():
                self._write_json(self.completed_scans_file, [])
            if not self.pending_uploads_file.exists():
                self._write_json(self.pending_uploads_file, [])
    
    def _read_json(self, file_path: Path) -> Any:
        """Read JSON file safely"""
        try:
            if not file_path.exists():
                return []
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")
            return []
    
    def _write_json(self, file_path: Path, data: Any):
        """Write JSON file safely"""
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error writing {file_path}: {e}")
    
    def queue_scan_result(self, scan_data: Dict[str, Any]):
        """
        Queue a scan result for later upload to database.
        
        Args:
            scan_data: Dictionary containing scan result data
        """
        scan_data['queued_at'] = datetime.now().isoformat()
        scan_data['service'] = self.service_name
        
        with _file_lock:
            pending = self._read_json(self.pending_uploads_file)
            pending.append(scan_data)
            self._write_json(self.pending_uploads_file, pending)
        
        logger.debug(f"📦 Queued scan result for {self.service_name}: {scan_data.get('target', 'unknown')}")
    
    def get_pending_uploads(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending uploads that need to be synced to database"""
        with _file_lock:
            pending = self._read_json(self.pending_uploads_file)
            return pending[:limit]
    
    def mark_uploaded(self, upload_ids: List[str]):
        """Mark uploads as successfully uploaded to database"""
        with _file_lock:
            pending = self._read_json(self.pending_uploads_file)
            # Remove uploaded items
            pending = [p for p in pending if p.get('upload_id') not in upload_ids]
            self._write_json(self.pending_uploads_file, pending)
            logger.info(f"✅ Marked {len(upload_ids)} items as uploaded for {self.service_name}")
    
    def queue_eggrecord(self, eggrecord_data: Dict[str, Any]):
        """Queue an eggrecord for scanning when DB is unavailable"""
        eggrecord_data['queued_at'] = datetime.now().isoformat()
        
        with _file_lock:
            queue = self._read_json(self.scan_queue_file)
            # Avoid duplicates
            existing_ids = {item.get('id') for item in queue}
            if eggrecord_data.get('id') not in existing_ids:
                queue.append(eggrecord_data)
                self._write_json(self.scan_queue_file, queue)
                logger.debug(f"📋 Queued eggrecord for {self.service_name}: {eggrecord_data.get('id', 'unknown')}")
    
    def get_queued_eggrecords(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get queued eggrecords for scanning"""
        with _file_lock:
            queue = self._read_json(self.scan_queue_file)
            return queue[:limit]
    
    def remove_queued_eggrecord(self, eggrecord_id: str):
        """Remove an eggrecord from the queue after processing"""
        with _file_lock:
            queue = self._read_json(self.scan_queue_file)
            queue = [item for item in queue if item.get('id') != eggrecord_id]
            self._write_json(self.scan_queue_file, queue)
    
    def save_completed_scan(self, scan_data: Dict[str, Any]):
        """Save a completed scan to local storage"""
        scan_data['completed_at'] = datetime.now().isoformat()
        
        with _file_lock:
            completed = self._read_json(self.completed_scans_file)
            completed.append(scan_data)
            # Keep only last 1000 completed scans
            if len(completed) > 1000:
                completed = completed[-1000:]
            self._write_json(self.completed_scans_file, completed)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about fallback storage"""
        with _file_lock:
            queue_count = len(self._read_json(self.scan_queue_file))
            pending_count = len(self._read_json(self.pending_uploads_file))
            completed_count = len(self._read_json(self.completed_scans_file))
            
            return {
                'queued_eggrecords': queue_count,
                'pending_uploads': pending_count,
                'completed_scans': completed_count,
                'storage_dir': str(self.storage_dir)
            }


class DatabaseConnectionManager:
    """Manages database connections with fallback support"""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.fallback_storage = FallbackStorage(service_name)
        self.db_available = True
        self.last_db_check = 0
        self.db_check_interval = 30  # Check every 30 seconds
    
    def is_database_available(self) -> bool:
        """Check if database is available"""
        current_time = time.time()
        if current_time - self.last_db_check < self.db_check_interval:
            return self.db_available
        
        self.last_db_check = current_time
        
        try:
            from django.db import connections
            conn = connections['customer_eggs']
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            self.db_available = True
            return True
        except Exception as e:
            logger.debug(f"Database unavailable for {self.service_name}: {e}")
            self.db_available = False
            return False
    
    def get_eggrecords(self, query_func) -> List[Dict[str, Any]]:
        """
        Get eggrecords from database, with fallback to JSON queue.
        
        Args:
            query_func: Function that queries database and returns eggrecords
        
        Returns:
            List of eggrecord dictionaries
        """
        if self.is_database_available():
            try:
                return query_func()
            except Exception as e:
                logger.warning(f"Database query failed for {self.service_name}, using fallback: {e}")
                self.db_available = False
        
        # Fallback to JSON queue
        logger.info(f"📦 {self.service_name} using fallback storage (DB unavailable)")
        return self.fallback_storage.get_queued_eggrecords()
    
    def save_scan_result(self, save_func, scan_data: Dict[str, Any]) -> bool:
        """
        Save scan result to database, with fallback to JSON queue.
        
        Args:
            save_func: Function that saves to database
            scan_data: Scan result data
        
        Returns:
            True if saved successfully, False if queued
        """
        if self.is_database_available():
            try:
                save_func(scan_data)
                return True
            except Exception as e:
                logger.warning(f"Database save failed for {self.service_name}, queuing: {e}")
                self.db_available = False
        
        # Fallback to JSON queue
        scan_data['upload_id'] = f"{self.service_name}_{datetime.now().timestamp()}"
        self.fallback_storage.queue_scan_result(scan_data)
        return False
    
    def sync_pending_uploads(self, upload_func) -> int:
        """
        Sync pending uploads to database when it becomes available.
        
        Args:
            upload_func: Function that uploads a single scan result to database
        
        Returns:
            Number of items successfully synced
        """
        if not self.is_database_available():
            return 0
        
        pending = self.fallback_storage.get_pending_uploads(limit=100)
        if not pending:
            return 0
        
        synced = 0
        uploaded_ids = []
        
        for item in pending:
            try:
                upload_func(item)
                uploaded_ids.append(item.get('upload_id'))
                synced += 1
            except Exception as e:
                logger.warning(f"Failed to sync item {item.get('upload_id')}: {e}")
                # Continue with next item
        
        if uploaded_ids:
            self.fallback_storage.mark_uploaded(uploaded_ids)
            logger.info(f"✅ {self.service_name} synced {synced} items to database")
        
        return synced

