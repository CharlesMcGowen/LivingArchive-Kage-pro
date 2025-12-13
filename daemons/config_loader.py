#!/usr/bin/env python3
"""
Agent Configuration Loader
==========================
Loads agent configuration from JSON files, with fallback to environment variables.
Supports distributed agent deployments on separate servers or networks.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class AgentConfig:
    """Configuration loader for agent daemons"""
    
    def __init__(self, agent_name: str, config_file: Optional[str] = None):
        """
        Initialize agent configuration.
        
        Args:
            agent_name: Name of the agent (kage, kaze, kumo, ryu, suzu)
            config_file: Optional path to config file. If not provided, 
                        will look for config/agents/{agent_name}.json
        """
        self.agent_name = agent_name
        self.project_root = Path(__file__).parent.parent
        
        # Determine config file path
        if config_file:
            self.config_file = Path(config_file)
        else:
            # Default location: config/agents/{agent_name}.json
            self.config_file = self.project_root / 'config' / 'agents' / f'{agent_name}.json'
        
        # Try alternative locations
        self.alternative_paths = [
            self.config_file,  # Primary location
            Path(f'/etc/agents/{agent_name}.json'),  # System-wide
            Path(f'~/.config/agents/{agent_name}.json').expanduser(),  # User config
            Path(f'./config/{agent_name}.json'),  # Current directory
        ]
        
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or environment variables"""
        config = {}
        
        # Try to load from config file
        config_file = None
        for path in self.alternative_paths:
            if path.exists():
                config_file = path
                break
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                logger.info(f"✅ Loaded config from {config_file}")
            except Exception as e:
                logger.warning(f"⚠️  Failed to load config from {config_file}: {e}")
                logger.info("   Falling back to environment variables")
        else:
            logger.info(f"📝 Config file not found at {self.config_file}")
            logger.info("   Using environment variables and defaults")
        
        # Merge with environment variables (env vars take precedence)
        config = self._merge_env_vars(config)
        
        return config
    
    def _merge_env_vars(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge environment variables into config (env vars override config file)"""
        # Server URL (highest priority)
        server_url = os.getenv('DJANGO_API_BASE') or config.get('server_url') or config.get('api_base_url')
        if server_url:
            config['server_url'] = server_url
        
        # Agent-specific settings
        agent_upper = self.agent_name.upper()
        
        # Scan/processing intervals
        if 'scan_interval' not in config or os.getenv(f'{agent_upper}_SCAN_INTERVAL'):
            interval = os.getenv(f'{agent_upper}_SCAN_INTERVAL')
            if interval:
                config['scan_interval'] = int(interval)
        
        if 'spider_interval' not in config or os.getenv(f'{agent_upper}_SPIDER_INTERVAL'):
            interval = os.getenv(f'{agent_upper}_SPIDER_INTERVAL')
            if interval:
                config['spider_interval'] = int(interval)
        
        if 'enum_interval' not in config or os.getenv(f'{agent_upper}_ENUM_INTERVAL'):
            interval = os.getenv(f'{agent_upper}_ENUM_INTERVAL')
            if interval:
                config['enum_interval'] = int(interval)
        
        if 'assessment_interval' not in config or os.getenv(f'{agent_upper}_ASSESSMENT_INTERVAL'):
            interval = os.getenv(f'{agent_upper}_ASSESSMENT_INTERVAL')
            if interval:
                config['assessment_interval'] = int(interval)
        
        # Max operations per cycle
        if 'max_scans_per_cycle' not in config or os.getenv(f'{agent_upper}_MAX_SCANS'):
            max_scans = os.getenv(f'{agent_upper}_MAX_SCANS')
            if max_scans:
                config['max_scans_per_cycle'] = int(max_scans)
        
        if 'max_spiders_per_cycle' not in config or os.getenv(f'{agent_upper}_MAX_SPIDERS'):
            max_spiders = os.getenv(f'{agent_upper}_MAX_SPIDERS')
            if max_spiders:
                config['max_spiders_per_cycle'] = int(max_spiders)
        
        if 'max_enums_per_cycle' not in config or os.getenv(f'{agent_upper}_MAX_ENUMS'):
            max_enums = os.getenv(f'{agent_upper}_MAX_ENUMS')
            if max_enums:
                config['max_enums_per_cycle'] = int(max_enums)
        
        if 'max_assessments_per_cycle' not in config or os.getenv(f'{agent_upper}_MAX_ASSESSMENTS'):
            max_assessments = os.getenv(f'{agent_upper}_MAX_ASSESSMENTS')
            if max_assessments:
                config['max_assessments_per_cycle'] = int(max_assessments)
        
        return config
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def get_server_url(self) -> str:
        """Get server API base URL"""
        return self.config.get('server_url') or self.config.get('api_base_url') or 'http://127.0.0.1:9000'
    
    def get_pid_file(self) -> Path:
        """Get PID file path"""
        pid_path = self.config.get('pid_file')
        if pid_path:
            return Path(pid_path)
        return Path(f'/tmp/{self.agent_name}_daemon.pid')
    
    def get_scan_interval(self, default: int = 30) -> int:
        """Get scan interval in seconds"""
        return self.config.get('scan_interval', default)
    
    def get_spider_interval(self, default: int = 45) -> int:
        """Get spider interval in seconds"""
        return self.config.get('spider_interval', default)
    
    def get_enum_interval(self, default: int = 60) -> int:
        """Get enumeration interval in seconds"""
        return self.config.get('enum_interval', default)
    
    def get_assessment_interval(self, default: int = 60) -> int:
        """Get assessment interval in seconds"""
        return self.config.get('assessment_interval', default)
    
    def get_max_scans_per_cycle(self, default: int = 5) -> int:
        """Get maximum scans per cycle"""
        return self.config.get('max_scans_per_cycle', default)
    
    def get_max_spiders_per_cycle(self, default: int = 3) -> int:
        """Get maximum spiders per cycle"""
        return self.config.get('max_spiders_per_cycle', default)
    
    def get_max_enums_per_cycle(self, default: int = 2) -> int:
        """Get maximum enumerations per cycle"""
        return self.config.get('max_enums_per_cycle', default)
    
    def get_max_assessments_per_cycle(self, default: int = 2) -> int:
        """Get maximum assessments per cycle"""
        return self.config.get('max_assessments_per_cycle', default)
    
    def get_retry_config(self) -> Dict[str, int]:
        """Get retry configuration"""
        return {
            'max_retries': self.config.get('max_retries', 5),
            'base_wait': self.config.get('retry_base_wait', 2),
            'max_wait': self.config.get('retry_max_wait', 60),
        }
    
    def get_timeout_config(self) -> Dict[str, int]:
        """Get timeout configuration"""
        return {
            'api_timeout': self.config.get('api_timeout', 10),
            'submit_timeout': self.config.get('submit_timeout', 30),
        }
