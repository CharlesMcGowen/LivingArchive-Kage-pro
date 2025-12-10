#!/usr/bin/env python3
"""
Kage Scan Learning Service - SQLAlchemy + Redis
===============================================

Service for learning from scan results with Redis caching.
Uses PostgreSQL via SQLAlchemy and Redis for fast lookups.
"""

import json
import logging
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func, Float

# Initialize logger first
logger = logging.getLogger(__name__)

# Redis
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

# Database session - Use Django's eggrecords connection instead of ego_main
_learning_session_local = None
_learning_engine = None

def get_learning_session_local():
    """Get SessionLocal for learning database using Django's eggrecords connection."""
    global _learning_session_local, _learning_engine
    
    if _learning_session_local is not None:
        return _learning_session_local
    
    try:
        import django
        if not django.apps.apps.ready:
            django.setup()
        from django.conf import settings
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        
        # Get database config from Django settings (eggrecords connection)
        db_config = settings.DATABASES.get('eggrecords')
        if not db_config:
            db_config = settings.DATABASES.get('default')
        
        if db_config and db_config.get('ENGINE') == 'django.db.backends.postgresql':
            db_url = f"postgresql://{db_config['USER']}:{db_config['PASSWORD']}@{db_config['HOST']}:{db_config['PORT']}/{db_config['NAME']}"
            _learning_engine = create_engine(db_url, pool_pre_ping=True, echo=False)
            _learning_session_local = sessionmaker(bind=_learning_engine)
            logger.info(f"✅ Learning service using Django eggrecords database: {db_config['NAME']} on {db_config['HOST']}:{db_config['PORT']}")
            return _learning_session_local
    except Exception as e:
        logger.warning(f"Could not use Django connection for learning service: {e}, falling back to default")
    
    # Fallback to original method
    try:
        from EgoQT.src.database import SessionLocal, init_database
        init_database()
        return SessionLocal
    except ImportError:
        try:
            from database import SessionLocal, init_database
            return SessionLocal
        except ImportError:
            return None

# Initialize on import
try:
    SessionLocal = get_learning_session_local()
    init_database = lambda: True  # No-op since we're using Django connection
except Exception as e:
    logger.warning(f"Learning service initialization failed: {e}")
    SessionLocal = None
    init_database = None

from artificial_intelligence.personalities.reconnaissance.kage.scan_learning_models import (
    TechniqueEffectiveness,
    WAFDetection,
    ScanResult
)

logger = logging.getLogger(__name__)


class ScanLearningService:
    """Service for learning from scan results with Redis caching."""
    
    def __init__(self, redis_host: str = 'localhost', redis_port: int = 6379, 
                 redis_db: int = 0, cache_ttl: int = 3600):
        """
        Initialize learning service.
        
        Args:
            redis_host: Redis host
            redis_port: Redis port
            redis_db: Redis database number
            cache_ttl: Cache TTL in seconds (default 1 hour)
        """
        # Initialize database
        if init_database:
            init_database()
        
        # Initialize Redis
        self.redis_client = None
        self.cache_ttl = cache_ttl
        
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    decode_responses=True,
                    socket_connect_timeout=2
                )
                # Test connection
                self.redis_client.ping()
                logger.info(f"✅ Redis connected: {redis_host}:{redis_port}")
            except Exception as e:
                logger.warning(f"⚠️  Redis not available: {e} - continuing without cache")
                self.redis_client = None
        else:
            logger.warning("⚠️  Redis library not installed - continuing without cache")
    
    def _get_cache_key(self, key_type: str, *args) -> str:
        """Generate cache key."""
        return f"kage:learning:{key_type}:{':'.join(str(a) for a in args)}"
    
    def _get_from_cache(self, cache_key: str) -> Optional[Any]:
        """Get value from Redis cache."""
        if not self.redis_client:
            return None
        
        try:
            value = self.redis_client.get(cache_key)
            if value:
                return json.loads(value)
        except Exception as e:
            logger.debug(f"Cache get error: {e}")
        
        return None
    
    def _set_cache(self, cache_key: str, value: Any, ttl: Optional[int] = None):
        """Set value in Redis cache."""
        if not self.redis_client:
            return
        
        try:
            ttl = ttl or self.cache_ttl
            self.redis_client.setex(
                cache_key,
                ttl,
                json.dumps(value, default=str)
            )
        except Exception as e:
            logger.debug(f"Cache set error: {e}")
    
    def record_technique_result(self, target: str, waf_type: Optional[str],
                               technique_name: str, success: bool):
        """Record whether a technique worked."""
        target_pattern = self._extract_target_pattern(target)
        waf_type = waf_type or 'none'
        
        # Invalidate cache
        cache_key = self._get_cache_key('technique', target_pattern, waf_type)
        if self.redis_client:
            try:
                self.redis_client.delete(cache_key)
            except:
                pass
        
        # Store in database
        db: Session = SessionLocal()
        try:
            # Check if table exists
            from sqlalchemy import inspect, text
            try:
                inspector = inspect(db.bind)
                if 'kage_technique_effectiveness' not in inspector.get_table_names():
                    logger.warning("⚠️  Learning table kage_technique_effectiveness does not exist yet - run create_learning_tables.py")
                    # Try to create tables automatically
                    try:
                        from artificial_intelligence.personalities.reconnaissance.kage.scan_learning_models import Base
                        Base.metadata.create_all(db.bind)
                        logger.info("✅ Created learning tables automatically")
                    except Exception as create_error:
                        logger.warning(f"Could not auto-create tables: {create_error}")
                    return
            except Exception as check_error:
                logger.warning(f"Could not check table existence: {check_error}")
                # Try to continue anyway - might work if it's a connection issue
            
            existing = db.query(TechniqueEffectiveness).filter(
                and_(
                    TechniqueEffectiveness.target_pattern == target_pattern,
                    TechniqueEffectiveness.waf_type == waf_type,
                    TechniqueEffectiveness.technique_name == technique_name
                )
            ).first()
            
            if existing:
                if success:
                    existing.success_count += 1
                    existing.last_success = datetime.utcnow()
                else:
                    existing.failure_count += 1
                    existing.last_failure = datetime.utcnow()
                existing.last_updated = datetime.utcnow()
            else:
                new_record = TechniqueEffectiveness(
                    target_pattern=target_pattern,
                    waf_type=waf_type,
                    technique_name=technique_name,
                    success_count=1 if success else 0,
                    failure_count=0 if success else 1,
                    last_success=datetime.utcnow() if success else None,
                    last_failure=datetime.utcnow() if not success else None
                )
                db.add(new_record)
            
            db.commit()
            logger.debug(f"✅ Recorded technique result: {technique_name} for {target_pattern} (success={success})")
        except Exception as e:
            try:
                db.rollback()
            except:
                pass
            logger.warning(f"⚠️  Error recording technique result (non-fatal): {e}")
        finally:
            db.close()
    
    def get_best_technique(self, target: str, waf_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get best technique for target (with Redis cache)."""
        target_pattern = self._extract_target_pattern(target)
        waf_type = waf_type or 'none'
        
        # Try cache first
        cache_key = self._get_cache_key('technique', target_pattern, waf_type)
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
        
        # Query database
        db: Session = SessionLocal()
        try:
            # Check if table exists first
            try:
                from sqlalchemy import inspect
                inspector = inspect(db.bind)
                if 'kage_technique_effectiveness' not in inspector.get_table_names():
                    logger.debug("Learning table kage_technique_effectiveness does not exist yet")
                    # Try to create tables automatically
                    try:
                        from artificial_intelligence.personalities.reconnaissance.kage.scan_learning_models import Base
                        Base.metadata.create_all(db.bind)
                        logger.info("✅ Created learning tables automatically")
                    except Exception as create_error:
                        logger.debug(f"Could not auto-create tables: {create_error}")
                    return None
            except Exception as check_error:
                logger.debug(f"Could not check table existence: {check_error}")
                # Try to continue anyway
            
            query = db.query(TechniqueEffectiveness).filter(
                TechniqueEffectiveness.target_pattern == target_pattern
            )
            
            if waf_type != 'none':
                query = query.filter(TechniqueEffectiveness.waf_type == waf_type)
            
            # Use float division instead of Float type for better compatibility
            try:
                result = query.order_by(
                    desc(
                        (TechniqueEffectiveness.success_count * 1.0) /
                        (TechniqueEffectiveness.success_count + TechniqueEffectiveness.failure_count + 1)
                    ),
                    desc(TechniqueEffectiveness.success_count)
                ).first()
            except Exception as order_error:
                # Fallback if Float type causes issues
                logger.debug(f"Float ordering failed, using simple ordering: {order_error}")
                try:
                    db.rollback()  # Rollback any failed transaction
                except:
                    pass
                result = query.order_by(
                    desc(TechniqueEffectiveness.success_count)
                ).first()
            
            if result:
                data = {
                    'technique': result.technique_name,
                    'success_count': result.success_count,
                    'failure_count': result.failure_count,
                    'success_rate': result.success_rate(),
                    'last_success': result.last_success.isoformat() if result.last_success else None
                }
                
                # Cache result
                self._set_cache(cache_key, data)
                
                return data
        except Exception as e:
            logger.debug(f"Error getting best technique (non-fatal): {e}")
            try:
                db.rollback()  # Ensure transaction is rolled back
            except:
                pass
        finally:
            db.close()
        
        return None
    
    def record_waf_detection(self, target: str, waf_info: Dict[str, Any],
                           bypass_technique: Optional[str] = None,
                           bypass_successful: Optional[bool] = None,
                           response_headers: Optional[Dict] = None,
                           response_body_sample: Optional[str] = None):
        """Record WAF detection result."""
        db: Session = SessionLocal()
        try:
            # Check if table exists
            from sqlalchemy import inspect
            try:
                inspector = inspect(db.bind)
                if 'kage_waf_detections' not in inspector.get_table_names():
                    logger.warning("⚠️  Learning table kage_waf_detections does not exist yet - run create_learning_tables.py")
                    # Try to create tables automatically
                    try:
                        from artificial_intelligence.personalities.reconnaissance.kage.scan_learning_models import Base
                        Base.metadata.create_all(db.bind)
                        logger.info("✅ Created learning tables automatically")
                    except Exception as create_error:
                        logger.warning(f"Could not auto-create tables: {create_error}")
                    return
            except Exception as check_error:
                logger.warning(f"Could not check table existence: {check_error}")
                # Try to continue anyway
            
            for method in waf_info.get('detection_methods', []):
                detection = WAFDetection(
                    target=target,
                    waf_type=waf_info.get('waf_type'),
                    detection_method=method,
                    confidence=waf_info.get('confidence', 0.0),
                    signatures=waf_info.get('signatures', {}),
                    response_headers=response_headers or {},
                    response_body_sample=response_body_sample[:1000] if response_body_sample else None,
                    bypass_technique=bypass_technique,
                    bypass_successful=bypass_successful
                )
                db.add(detection)
            
            db.commit()
            logger.debug(f"✅ Recorded WAF detection: {waf_info.get('waf_type', 'unknown')} for {target}")
            
            # Invalidate WAF cache for this target
            cache_key = self._get_cache_key('waf', target)
            if self.redis_client:
                try:
                    self.redis_client.delete(cache_key)
                except:
                    pass
                    
        except Exception as e:
            try:
                db.rollback()
            except:
                pass
            logger.warning(f"⚠️  Error recording WAF detection (non-fatal): {e}")
        finally:
            db.close()
    
    def record_scan_result(self, target: str, technique_used: str,
                          ports_scanned: List[int], open_ports_found: int,
                          waf_detected: bool, waf_type: Optional[str],
                          bypass_successful: bool, scan_duration: float,
                          egg_record_id: Optional[str] = None,
                          scan_results: Optional[Dict] = None):
        """Record complete scan result."""
        logger.debug(f"📚 Learning: Attempting to record scan result for {target} (technique={technique_used}, ports={open_ports_found})")
        db: Session = SessionLocal()
        try:
            # Check if table exists
            from sqlalchemy import inspect
            try:
                inspector = inspect(db.bind)
                if 'kage_scan_results' not in inspector.get_table_names():
                    logger.warning("⚠️  Learning table kage_scan_results does not exist yet - run create_learning_tables.py")
                    # Try to create tables automatically
                    try:
                        from artificial_intelligence.personalities.reconnaissance.kage.scan_learning_models import Base
                        Base.metadata.create_all(db.bind)
                        logger.info("✅ Created learning tables automatically")
                    except Exception as create_error:
                        logger.warning(f"Could not auto-create tables: {create_error}")
                        return
            except Exception as check_error:
                logger.warning(f"Could not check table existence: {check_error}")
                # Try to continue anyway
            
            result = ScanResult(
                target=target,
                egg_record_id=uuid.UUID(egg_record_id) if egg_record_id else None,
                technique_used=technique_used,
                ports_scanned=ports_scanned,
                open_ports_found=open_ports_found,
                waf_detected=waf_detected,
                waf_type=waf_type,
                bypass_successful=bypass_successful,
                scan_duration=scan_duration,
                scan_results=scan_results or {}
            )
            db.add(result)
            db.commit()
            logger.info(f"✅ Learning: Recorded scan result for {target} ({open_ports_found} ports, technique={technique_used})")
        except Exception as e:
            try:
                db.rollback()
            except:
                pass
            logger.warning(f"⚠️  Error recording scan result (non-fatal): {e}")
            import traceback
            logger.warning(f"Learning service error traceback: {traceback.format_exc()}")
        finally:
            db.close()
    
    def get_technique_stats(self, waf_type: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all techniques (with Redis cache)."""
        cache_key = self._get_cache_key('stats', waf_type or 'all')
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
        
        db: Session = SessionLocal()
        try:
            query = db.query(
                TechniqueEffectiveness.technique_name,
                func.sum(TechniqueEffectiveness.success_count).label('total_success'),
                func.sum(TechniqueEffectiveness.failure_count).label('total_failure'),
                func.count(TechniqueEffectiveness.id).label('usage_count')
            ).group_by(TechniqueEffectiveness.technique_name)
            
            if waf_type:
                query = query.filter(TechniqueEffectiveness.waf_type == waf_type)
            
            rows = query.all()
            
            stats = {}
            for row in rows:
                technique, success, failure, usage = row
                total = success + failure
                stats[technique] = {
                    'success_count': success,
                    'failure_count': failure,
                    'usage_count': usage,
                    'success_rate': success / total if total > 0 else 0.0
                }
            
            # Cache for shorter TTL (5 minutes)
            self._set_cache(cache_key, stats, ttl=300)
            
            return stats
        except Exception as e:
            logger.error(f"Error getting technique stats: {e}")
            return {}
        finally:
            db.close()
    
    def get_waf_history(self, target: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get WAF detection history for target."""
        cache_key = self._get_cache_key('waf_history', target, limit)
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
        
        db: Session = SessionLocal()
        try:
            detections = db.query(WAFDetection).filter(
                WAFDetection.target == target
            ).order_by(desc(WAFDetection.detected_at)).limit(limit).all()
            
            results = [{
                'waf_type': d.waf_type,
                'detection_method': d.detection_method,
                'confidence': d.confidence,
                'bypass_technique': d.bypass_technique,
                'bypass_successful': d.bypass_successful,
                'detected_at': d.detected_at.isoformat()
            } for d in detections]
            
            # Cache for 10 minutes
            self._set_cache(cache_key, results, ttl=600)
            
            return results
        except Exception as e:
            logger.error(f"Error getting WAF history: {e}")
            return []
        finally:
            db.close()
    
    def _extract_target_pattern(self, target: str) -> str:
        """Extract pattern from target (domain, IP range, etc.)."""
        if '.' in target and not target.replace('.', '').isdigit():
            # Domain - use base domain
            parts = target.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])  # example.com
        elif target.replace('.', '').isdigit():
            # IP - use class C
            parts = target.split('.')
            if len(parts) == 4:
                return '.'.join(parts[:3]) + '.0/24'  # 192.168.1.0/24
        
        return target

