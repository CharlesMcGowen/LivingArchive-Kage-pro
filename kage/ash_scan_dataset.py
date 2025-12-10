#!/usr/bin/env python3
"""
Ash Scan Dataset for Transformer Training

Loads Nmap scan scenario data and prepares it for GPU training with Volkner OpenCL Trainer.
Converts scan scenarios (WAF type, stealth requirements, etc.) to feature vectors for
predicting optimal Nmap arguments.
"""

import sys
import logging
import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Iterator, Optional, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Add workspace root to path
ash_dir = Path(__file__).parent
workspace_root = ash_dir.parent.parent.parent.parent
if str(workspace_root) not in sys.path:
    sys.path.insert(0, str(workspace_root))


@dataclass
class AshScanSample:
    """A single Ash Nmap scan training sample"""
    scan_id: str
    scenario: Dict[str, Any]  # ScanScenario features (WAF type, stealth, speed, etc.)
    nmap_arguments: List[Dict[str, Any]]  # Recommended Nmap arguments with flags
    success: bool  # Whether scan was successful
    open_ports: Optional[List[int]] = None  # Ports discovered
    scan_time: Optional[float] = None  # Scan duration in seconds
    metadata: Optional[Dict] = None
    tokenized: Optional[List[int]] = None  # For compatibility with trainer interface


class AshScanDataset:
    """
    Dataset loader for Ash Nmap scan data.
    
    Converts scan scenarios (WAF detection, stealth requirements, speed priority)
    into dense feature vectors for predicting optimal Nmap arguments.
    """
    
    # Common Nmap argument flags (for classification output)
    NMAP_FLAGS = {
        # Scan types
        '-sS': 0, '-sT': 1, '-sU': 2, '-sA': 3, '-sF': 4, '-sN': 5, '-sX': 6,
        # Host discovery
        '-PS': 7, '-PA': 8, '-PU': 9, '-PE': 10, '-Pn': 11,
        # Timing (advanced)
        '--min-rate': 12, '--max-rate': 13, '--scan-delay': 14,
        '--max-retries': 15, '--max-rtt-timeout': 16,
        # Service/OS detection
        '-sV': 17, '-A': 18, '-O': 19,
        # Firewall evasion
        '-f': 20, '--mtu': 21, '-D': 22,
        # Output
        '-oN': 23, '-oX': 24, '-oG': 25,
    }
    
    # WAF types
    WAF_TYPES = [
        'none', 'cloudflare', 'akamai', 'aws_waf', 'imperva', 'f5', 'barracuda',
        'sucuri', 'wordfence', 'mod_security', 'unknown'
    ]
    
    # Speed priorities
    SPEED_PRIORITIES = ['fast', 'normal', 'thorough']
    
    def __init__(
        self,
        max_sequence_length: int = 128,
        feature_embedding_dim: int = 256,
    ):
        """
        Initialize Ash Scan Dataset
        
        Args:
            max_sequence_length: Maximum sequence length for training
            feature_embedding_dim: Dimension for feature embeddings (should match d_model)
        """
        self.max_sequence_length = max_sequence_length
        self.feature_embedding_dim = feature_embedding_dim
        self.samples: List[AshScanSample] = []
        self.papers: List[AshScanSample] = []  # Alias for compatibility with trainer
        
        # Build feature vocabulary
        self._build_feature_vocab()
    
    def _build_feature_vocab(self):
        """Build feature vocabulary from mappings"""
        self.feature_vocab = {}
        
        # WAF types (one-hot positions)
        base_idx = 0
        for idx, waf_type in enumerate(self.WAF_TYPES):
            self.feature_vocab[f'waf_{waf_type}'] = base_idx + idx
        
        # Speed priorities
        base_idx = len(self.WAF_TYPES)
        for idx, speed in enumerate(self.SPEED_PRIORITIES):
            self.feature_vocab[f'speed_{speed}'] = base_idx + idx
        
        # Boolean features
        base_idx = base_idx + len(self.SPEED_PRIORITIES)
        self.feature_vocab['waf_detected'] = base_idx
        self.feature_vocab['stealth_required'] = base_idx + 1
        self.feature_vocab['firewall_detected'] = base_idx + 2
        self.feature_vocab['ids_detected'] = base_idx + 3
        self.feature_vocab['previous_scan_failed'] = base_idx + 4
        
        # Port count (normalized)
        self.feature_vocab['port_count'] = base_idx + 5
        
        # Target type (categorical)
        self.feature_vocab['target_single_host'] = base_idx + 6
        self.feature_vocab['target_network'] = base_idx + 7
    
    def load_from_database(
        self,
        min_samples: int = 1
    ) -> int:
        """
        Load training data from Ash's scan history database
        
        Args:
            min_samples: Minimum samples required
            
        Returns:
            Number of scan samples loaded
        """
        logger.info("📊 Loading Ash scan data from database...")
        
        try:
            # Setup Django
            import os
            import django
            os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EgoQT.src.django_bridge.settings')
            django.setup()
            
            from django.db import connections
            
            conn = connections['customer_eggs']
            conn.ensure_connection()
            
            count = 0
            
            # Query Nmap scan results with scenario context
            with conn.cursor() as cursor:
                # Get scans with WAF detection info and success metrics
                cursor.execute("""
                    SELECT 
                        n.id,
                        n.record_id_id,
                        n.nmap_command,
                        n.open_ports,
                        n.scan_time,
                        n.created_at,
                        e."subDomain",
                        e.domainname
                    FROM customer_eggs_eggrecords_general_models_nmap n
                    INNER JOIN customer_eggs_eggrecords_general_models_eggrecord e ON n.record_id_id = e.id
                    WHERE n.nmap_command IS NOT NULL
                    AND n.created_at > NOW() - INTERVAL '30 days'
                    ORDER BY n.created_at DESC
                    LIMIT 1000
                """)
                
                columns = [col[0] for col in cursor.description]
                
                for row in cursor.fetchall():
                    row_dict = dict(zip(columns, row))
                    
                    # Parse nmap_command to extract arguments
                    nmap_command = row_dict.get('nmap_command', '')
                    if not nmap_command:
                        continue
                    
                    # Extract scenario from command and metadata
                    scenario = self._parse_scenario_from_command(nmap_command, row_dict)
                    
                    # Extract Nmap arguments from command
                    nmap_arguments = self._parse_arguments_from_command(nmap_command)
                    
                    # Determine success (has open ports)
                    open_ports = row_dict.get('open_ports')
                    if isinstance(open_ports, list):
                        success = len(open_ports) > 0
                    elif isinstance(open_ports, str):
                        try:
                            import json as json_lib
                            ports_list = json_lib.loads(open_ports)
                            success = len(ports_list) > 0 if isinstance(ports_list, list) else False
                        except:
                            success = False
                    else:
                        success = False
                    
                    sample = AshScanSample(
                        scan_id=str(row_dict.get('id', f"scan_{count}")),
                        scenario=scenario,
                        nmap_arguments=nmap_arguments,
                        success=success,
                        open_ports=open_ports if isinstance(open_ports, list) else None,
                        scan_time=row_dict.get('scan_time'),
                        metadata={
                            'target': row_dict.get('subDomain') or row_dict.get('domainname'),
                            'created_at': str(row_dict.get('created_at')),
                        }
                    )
                    
                    self.samples.append(sample)
                    self.papers.append(sample)
                    count += 1
            
            conn.close()
            
            logger.info(f"✅ Loaded {count} Ash scan samples from database")
            
            if count < min_samples:
                logger.warning(f"⚠️  Only {count} samples loaded (minimum recommended: {min_samples})")
            
            return count
            
        except Exception as e:
            logger.error(f"Error loading from database: {e}", exc_info=True)
            return 0
    
    def _parse_scenario_from_command(self, command: str, metadata: Dict) -> Dict[str, Any]:
        """Parse scan scenario from Nmap command string"""
        scenario = {
            'waf_detected': False,
            'waf_type': 'none',
            'stealth_required': False,
            'firewall_detected': False,
            'ids_detected': False,
            'speed_priority': 'normal',
            'target_type': 'single_host',
            'previous_scan_failed': False,
        }
        
        # Detect WAF evasion flags
        if '-f' in command or '--mtu' in command:
            scenario['firewall_detected'] = True
            scenario['waf_detected'] = True
            scenario['waf_type'] = 'unknown'
        
        # Detect stealth flags
        if '-sS' in command and '-sT' not in command:
            scenario['stealth_required'] = True
        
        # Detect speed priority from timing flags
        if '--min-rate' in command or '--max-rate' in command:
            scenario['speed_priority'] = 'fast'
        elif '--scan-delay' in command:
            scenario['speed_priority'] = 'thorough'
        else:
            scenario['speed_priority'] = 'normal'
        
        return scenario
    
    def _parse_arguments_from_command(self, command: str) -> List[Dict[str, Any]]:
        """Parse Nmap arguments from command string"""
        arguments = []
        
        # Split command into parts
        parts = command.split()
        
        i = 0
        while i < len(parts):
            part = parts[i]
            
            # Check if it's a flag
            if part.startswith('-'):
                arg_dict = {'flag': part}
                
                # Check if next part is a value (not a flag)
                if i + 1 < len(parts) and not parts[i + 1].startswith('-'):
                    arg_dict['value'] = parts[i + 1]
                    i += 2
                else:
                    i += 1
                
                arguments.append(arg_dict)
            else:
                i += 1
        
        return arguments
    
    def load_from_json_file(
        self,
        json_file: Path,
        min_samples: int = 1
    ) -> int:
        """Load scan data from exported JSON file"""
        if not json_file.exists():
            logger.error(f"JSON file not found: {json_file}")
            return 0
        
        logger.info(f"📊 Loading Ash scan data from: {json_file}")
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                logger.error("JSON file must contain a list of training data objects")
                return 0
            
            count = 0
            skipped = 0
            
            for item in data:
                if 'scenario' not in item or 'nmap_arguments' not in item:
                    skipped += 1
                    continue
                
                sample = AshScanSample(
                    scan_id=item.get('scan_id', f"scan_{count}"),
                    scenario=item['scenario'],
                    nmap_arguments=item['nmap_arguments'],
                    success=item.get('success', False),
                    open_ports=item.get('open_ports'),
                    scan_time=item.get('scan_time'),
                    metadata=item.get('metadata', {})
                )
                
                self.samples.append(sample)
                self.papers.append(sample)
                count += 1
            
            logger.info(f"✅ Loaded {count} scan samples from JSON (skipped {skipped} invalid)")
            return count
            
        except Exception as e:
            logger.error(f"Error loading JSON file: {e}")
            return 0
    
    def _extract_features_to_vector(
        self,
        scenario: Dict[str, Any]
    ) -> np.ndarray:
        """
        Convert scan scenario to dense feature vector
        
        Args:
            scenario: ScanScenario dictionary
            
        Returns:
            Dense feature vector [feature_embedding_dim]
        """
        # Initialize feature vector
        feature_vector = np.zeros(self.feature_embedding_dim, dtype=np.float32)
        
        # Map WAF type (one-hot)
        waf_type = scenario.get('waf_type', 'none')
        waf_key = f'waf_{waf_type}'
        if waf_key in self.feature_vocab:
            idx = self.feature_vocab[waf_key]
            if idx < self.feature_embedding_dim:
                feature_vector[idx] = 1.0
        
        # Map speed priority (one-hot)
        speed = scenario.get('speed_priority', 'normal')
        speed_key = f'speed_{speed}'
        if speed_key in self.feature_vocab:
            idx = self.feature_vocab[speed_key]
            if idx < self.feature_embedding_dim:
                feature_vector[idx] = 1.0
        
        # Map boolean features
        for feat_name in ['waf_detected', 'stealth_required', 'firewall_detected', 
                          'ids_detected', 'previous_scan_failed']:
            if feat_name in self.feature_vocab:
                idx = self.feature_vocab[feat_name]
                if idx < self.feature_embedding_dim:
                    feature_vector[idx] = 1.0 if scenario.get(feat_name, False) else 0.0
        
        # Map port count (normalized)
        ports = scenario.get('ports_to_scan', [])
        if ports and 'port_count' in self.feature_vocab:
            idx = self.feature_vocab['port_count']
            if idx < self.feature_embedding_dim:
                # Normalize to [0, 1] (assuming max 65535 ports)
                port_count = len(ports) if isinstance(ports, list) else 1
                feature_vector[idx] = min(port_count / 65535.0, 1.0)
        
        # Map target type
        target_type = scenario.get('target_type', 'single_host')
        if target_type == 'single_host' and 'target_single_host' in self.feature_vocab:
            idx = self.feature_vocab['target_single_host']
            if idx < self.feature_embedding_dim:
                feature_vector[idx] = 1.0
        elif target_type == 'network' and 'target_network' in self.feature_vocab:
            idx = self.feature_vocab['target_network']
            if idx < self.feature_embedding_dim:
                feature_vector[idx] = 1.0
        
        # Normalize to prevent overflow
        feature_vector = np.clip(feature_vector, 0.0, 1.0)
        
        return feature_vector
    
    def get_training_samples(
        self,
        batch_size: int = 1,
        sequence_length: Optional[int] = None,
        shuffle: bool = True
    ) -> Iterator[List[List[int]]]:
        """
        Generate training batches from scan samples.
        
        Compatible with VolknerOpenCLTrainer interface.
        
        Args:
            batch_size: Number of samples per batch
            sequence_length: Sequence length (uses max_sequence_length if None)
            shuffle: Shuffle samples before batching
            
        Yields:
            Batches of token sequences
        """
        seq_len = sequence_length or self.max_sequence_length
        
        if not self.samples:
            logger.warning("No scan samples available for training")
            return
        
        # Shuffle if requested
        samples_shuffled = self.samples.copy()
        if shuffle:
            import random
            random.shuffle(samples_shuffled)
        
        batch = []
        
        for sample in samples_shuffled:
            # Convert scenario to dense vector
            feature_vector = self._extract_features_to_vector(sample.scenario)
            
            # Convert to token-like sequence
            tokens = (feature_vector * 1000).astype(np.int32).clip(0, 1000).tolist()
            
            # Pad or truncate to exact sequence length
            if len(tokens) < seq_len:
                tokens = tokens + [0] * (seq_len - len(tokens))
            else:
                tokens = tokens[:seq_len]
            
            batch.append(tokens)
            
            if len(batch) >= batch_size:
                yield batch
                batch = []
        
        # Yield remaining batch
        if batch:
            if len(batch) < batch_size:
                last_seq = batch[-1] if batch else [0] * seq_len
                while len(batch) < batch_size:
                    batch.append(last_seq)
            yield batch
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get dataset statistics"""
        if not self.samples:
            return {
                'total_samples': 0,
                'success_rate': 0.0,
                'avg_scan_time': 0.0,
                'waf_distribution': {},
                'speed_distribution': {}
            }
        
        total = len(self.samples)
        successful = sum(1 for s in self.samples if s.success)
        scan_times = [s.scan_time for s in self.samples if s.scan_time is not None]
        
        waf_dist = {}
        speed_dist = {}
        
        for sample in self.samples:
            waf_type = sample.scenario.get('waf_type', 'none')
            waf_dist[waf_type] = waf_dist.get(waf_type, 0) + 1
            
            speed = sample.scenario.get('speed_priority', 'normal')
            speed_dist[speed] = speed_dist.get(speed, 0) + 1
        
        return {
            'total_samples': total,
            'success_rate': successful / total if total > 0 else 0.0,
            'avg_scan_time': sum(scan_times) / len(scan_times) if scan_times else 0.0,
            'waf_distribution': waf_dist,
            'speed_distribution': speed_dist
        }

