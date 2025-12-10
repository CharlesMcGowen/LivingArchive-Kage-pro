#!/usr/bin/env python3
"""
Ash Scan Learning Models - SQLAlchemy
======================================

SQLAlchemy models for storing learned scanning techniques:
- Technique effectiveness per target/WAF
- WAF detection history
- Scan results for learning
"""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, Index, JSON
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

# Use existing Base from database module
try:
    from EgoQT.src.database.sqlalchemy_models import Base
except ImportError:
    try:
        from database.sqlalchemy_models import Base
    except ImportError:
        from sqlalchemy.ext.declarative import declarative_base
        Base = declarative_base()


class TechniqueEffectiveness(Base):
    """
    Stores effectiveness of scanning techniques per target pattern and WAF type.
    """
    __tablename__ = 'ash_technique_effectiveness'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    target_pattern = Column(String(255), nullable=False, index=True)  # Domain or IP range pattern
    waf_type = Column(String(50), nullable=True, index=True)  # WAF type or 'none'
    technique_name = Column(String(100), nullable=False)  # tcp_syn_nonhttp, tcp_ack, udp_dns, etc.
    
    success_count = Column(Integer, default=0, nullable=False)
    failure_count = Column(Integer, default=0, nullable=False)
    
    last_success = Column(DateTime(timezone=True), nullable=True)
    last_failure = Column(DateTime(timezone=True), nullable=True)
    last_updated = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, onupdate=datetime.utcnow)
    
    # Metadata
    technique_metadata = Column(JSONB, default=dict, nullable=True)  # Additional technique-specific data (renamed from 'metadata' to avoid SQLAlchemy reserved word)
    
    __table_args__ = (
        Index('idx_technique_target_waf', 'target_pattern', 'waf_type', 'technique_name', unique=True),
        Index('idx_technique_success_rate', 'target_pattern', 'waf_type'),
    )
    
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0


class WAFDetection(Base):
    """
    Stores WAF detection history.
    """
    __tablename__ = 'ash_waf_detections'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    target = Column(String(255), nullable=False, index=True)
    waf_type = Column(String(50), nullable=True, index=True)
    detection_method = Column(String(50), nullable=False)  # headers, response_body, timing, ttl
    confidence = Column(Float, nullable=False, default=0.0)
    
    # Detection details
    signatures = Column(JSONB, default=dict, nullable=True)  # Found signatures
    response_headers = Column(JSONB, default=dict, nullable=True)  # Response headers
    response_body_sample = Column(Text, nullable=True)  # Sample of response body
    
    # Bypass information
    bypass_technique = Column(String(100), nullable=True)
    bypass_successful = Column(Boolean, nullable=True)
    
    detected_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index('idx_waf_target_time', 'target', 'detected_at'),
        Index('idx_waf_type', 'waf_type'),
    )


class ScanResult(Base):
    """
    Stores scan results for learning and analysis.
    """
    __tablename__ = 'ash_scan_results'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    target = Column(String(255), nullable=False, index=True)
    egg_record_id = Column(UUID(as_uuid=True), nullable=True, index=True)  # Link to EggRecord
    
    # Scan details
    technique_used = Column(String(100), nullable=False)
    ports_scanned = Column(JSONB, default=list, nullable=True)  # List of ports
    open_ports_found = Column(Integer, default=0, nullable=False)
    
    # WAF information
    waf_detected = Column(Boolean, default=False, nullable=False)
    waf_type = Column(String(50), nullable=True)
    bypass_successful = Column(Boolean, nullable=True)
    
    # Results
    scan_duration = Column(Float, nullable=True)  # Duration in seconds
    scan_results = Column(JSONB, default=dict, nullable=True)  # Full scan results
    
    scanned_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index('idx_scan_target_time', 'target', 'scanned_at'),
        Index('idx_scan_technique', 'technique_used'),
        Index('idx_scan_waf', 'waf_detected', 'waf_type'),
    )

