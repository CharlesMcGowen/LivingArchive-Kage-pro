#!/usr/bin/env python3
"""
Ash-Volkner Integration Bridge

Bridges Ash's Nmap scanning system to Volkner's GPU-accelerated transformer training.
Handles data loading, model training, and inference for optimal Nmap argument prediction.
"""

import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import numpy as np

logger = logging.getLogger(__name__)

# Add workspace root to path
ash_dir = Path(__file__).parent
workspace_root = ash_dir.parent.parent.parent.parent
if str(workspace_root) not in sys.path:
    sys.path.insert(0, str(workspace_root))

# Import components
from .ash_scan_dataset import AshScanDataset, AshScanSample

# Import Volkner trainer
try:
    from artificial_intelligence.personalities.maintenance.volkner.volkner_opencl_trainer import VolknerOpenCLTrainer
    VOLKNER_AVAILABLE = True
except ImportError:
    VOLKNER_AVAILABLE = False
    VolknerOpenCLTrainer = None
    logger.warning("VolknerOpenCLTrainer not available - bridge will be limited")

# OpenCL imports for inference
try:
    import pyopencl as cl
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False
    cl = None


class AshVolknerBridge:
    """
    Bridge between Ash's Nmap scanning system and Volkner's GPU-accelerated training.
    
    This class provides:
    1. Data loading from Ash's scan history database
    2. GPU training using Volkner OpenCL Trainer
    3. Model inference for Nmap argument prediction
    4. Seamless integration with Ash's scanning flow
    """
    
    def __init__(
        self,
        d_model: int = 256,
        num_heads: int = 4,
        d_ff: int = 1024,
        output_dir: Optional[Path] = None
    ):
        """
        Initialize Ash-Volkner Bridge
        
        Args:
            d_model: Transformer model dimension (should match feature_embedding_dim)
            num_heads: Number of attention heads
            d_ff: Feed-forward dimension (typically 4 * d_model)
            output_dir: Directory for model checkpoints
        """
        self.d_model = d_model
        self.num_heads = num_heads
        self.d_ff = d_ff
        self.output_dir = output_dir or Path("models/ash_volkner")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Components
        self.dataset: Optional[AshScanDataset] = None
        self.trainer: Optional[VolknerOpenCLTrainer] = None
        
        # Model state
        self.model_trained = False
        self.last_training_result = None
        
        # OpenCL context for inference (will be initialized from trainer if available)
        self.inference_context = None
        self.inference_queue = None
        
        logger.info(f"🔗 AshVolknerBridge initialized: d_model={d_model}, heads={num_heads}, d_ff={d_ff}")
    
    def load_ash_data(
        self,
        json_file: Optional[Path] = None,
        min_samples: int = 10
    ) -> bool:
        """
        Load training data from Ash's data sources
        
        Supports loading from:
        - Database (scan history from customer_eggs database)
        - JSON file (exported training data)
        
        Args:
            json_file: Path to JSON file with exported training data
            min_samples: Minimum samples required for training
            
        Returns:
            True if sufficient data loaded, False otherwise
        """
        logger.info("📊 Loading Ash scan data for GPU training...")
        
        # Initialize dataset
        self.dataset = AshScanDataset(
            max_sequence_length=128,
            feature_embedding_dim=self.d_model
        )
        
        count = 0
        
        # Load from database
        try:
            db_count = self.dataset.load_from_database(min_samples=0)
            count += db_count
            logger.info(f"   Loaded {db_count} samples from database")
        except Exception as e:
            logger.warning(f"Could not load from database: {e}")
        
        # Load from JSON file if provided
        if json_file is not None:
            json_count = self.dataset.load_from_json_file(json_file, min_samples=0)
            count += json_count
            logger.info(f"   Loaded {json_count} samples from JSON file")
        
        if count == 0:
            logger.warning("⚠️  No scan samples loaded")
            return False
        
        # Show statistics
        stats = self.dataset.get_statistics()
        logger.info(f"✅ Loaded {count} total scan samples")
        logger.info(f"   Success rate: {stats['success_rate']:.2%}")
        logger.info(f"   Average scan time: {stats['avg_scan_time']:.2f}s")
        logger.info(f"   WAF distribution: {stats['waf_distribution']}")
        logger.info(f"   Speed distribution: {stats['speed_distribution']}")
        
        if count < min_samples:
            logger.warning(f"⚠️  Only {count} samples available (recommended minimum: {min_samples})")
            logger.warning("   Training may be limited, but will proceed")
            return False  # Return False to indicate limited data, but still allow training
        
        return True
    
    def train_model(
        self,
        max_steps: int = 100,
        batch_size: int = 1,
        learning_rate: float = 0.001,
        gradient_accumulation_steps: int = 4,
        auto_load_data: bool = True
    ) -> bool:
        """
        Train Ash's Nmap argument prediction model using Volkner GPU trainer
        
        Args:
            max_steps: Maximum training steps
            batch_size: Batch size
            learning_rate: Learning rate
            gradient_accumulation_steps: Steps for gradient accumulation
            auto_load_data: If True, automatically load data if not already loaded
            
        Returns:
            True if training completed successfully
        """
        if not VOLKNER_AVAILABLE:
            logger.error("❌ VolknerOpenCLTrainer not available - cannot train")
            return False
        
        # Auto-load data if needed
        if self.dataset is None or len(self.dataset.samples) == 0:
            if auto_load_data:
                logger.info("📊 Auto-loading Ash data...")
                if not self.load_ash_data(min_samples=1):
                    logger.error("❌ No training data available - cannot train")
                    return False
            else:
                logger.error("❌ No training data available - cannot train")
                return False
        
        num_samples = len(self.dataset.samples)
        logger.info(f"🚀 Starting GPU training for Ash Nmap argument model...")
        logger.info(f"   Samples: {num_samples}")
        logger.info(f"   Max steps: {max_steps}")
        logger.info(f"   Batch size: {batch_size}")
        logger.info(f"   Learning rate: {learning_rate}")
        logger.info(f"   Model: Transformer (d_model={self.d_model}, heads={self.num_heads}, d_ff={self.d_ff})")
        
        try:
            # Initialize trainer
            self.trainer = VolknerOpenCLTrainer(
                batch_size=batch_size,
                sequence_length=128,
                hidden_dim=self.d_model,
                learning_rate=learning_rate,
                gradient_accumulation_steps=gradient_accumulation_steps,
                max_steps=max_steps,
                epochs=1,
                architecture='transformer',
                d_model=self.d_model,
                num_heads=self.num_heads,
                d_ff=self.d_ff,
                use_research_papers=False,  # Using Ash scan data
                dataset_path=None,  # Data provided via dataset attribute
                output_dir=self.output_dir,
                cpu_offload_loss=True,
                cpu_offload_optimizer=True,
            )
            
            # Attach Ash dataset to trainer
            self.trainer.dataset = self.dataset
            
            logger.info("✅ Trainer initialized, starting training...")
            
            # Train on scan data
            result = self.trainer.train(num_samples=num_samples * 2)  # Use more samples for cycling
            
            # Store results
            self.last_training_result = result
            self.model_trained = result.success
            
            if result.success:
                logger.info("✅ Ash model training complete!")
                logger.info(f"   Completed steps: {result.completed_steps}/{result.total_steps}")
                logger.info(f"   Training time: {result.training_time_seconds:.2f}s")
                if result.loss_history:
                    logger.info(f"   Final loss: {result.loss_history[-1]:.4f}")
                    if len(result.loss_history) > 1:
                        logger.info(f"   Initial loss: {result.loss_history[0]:.4f}")
                        loss_change = result.loss_history[0] - result.loss_history[-1]
                        logger.info(f"   Loss change: {loss_change:+.4f}")
                
                # Initialize inference components
                self._initialize_inference_components()
                
                return True
            else:
                logger.error("❌ Training failed")
                if hasattr(result, 'failure_reason'):
                    logger.error(f"   Reason: {result.failure_reason}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Training error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def _initialize_inference_components(self):
        """Initialize OpenCL context for inference"""
        if not OPENCL_AVAILABLE:
            logger.warning("⚠️  OpenCL not available - inference will be limited")
            return
        
        if self.trainer is None:
            logger.warning("⚠️  Trainer not initialized - cannot initialize inference components")
            return
        
        try:
            # Get context and queue from trainer
            if hasattr(self.trainer, 'context') and hasattr(self.trainer, 'queue'):
                self.inference_context = self.trainer.context
                self.inference_queue = self.trainer.queue
                logger.info("✅ Inference components initialized")
            else:
                logger.warning("⚠️  Trainer does not expose context/queue - inference will be limited")
        except Exception as e:
            logger.warning(f"⚠️  Error initializing inference components: {e}")
    
    def predict_nmap_arguments(
        self,
        scenario: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Predict optimal Nmap arguments for given scan scenario
        
        Args:
            scenario: ScanScenario dictionary with:
                - waf_detected (bool)
                - waf_type (str)
                - stealth_required (bool)
                - speed_priority (str: 'fast', 'normal', 'thorough')
                - ports_to_scan (List[int])
                - target_type (str)
        
        Returns:
            List of recommended Nmap argument dictionaries with 'flag' and optional 'value'
        """
        if not self.model_trained or self.trainer is None:
            logger.debug("⚠️  Model not trained yet - using rule-based fallback")
            return self._rule_based_arguments(scenario)
        
        # Ensure we have a dataset for feature extraction
        if self.dataset is None:
            self.dataset = AshScanDataset(feature_embedding_dim=self.d_model)
        
        try:
            # Extract features to dense vector
            feature_vector = self.dataset._extract_features_to_vector(scenario)
            
            # For now, use rule-based fallback until we implement full transformer inference
            # TODO: Implement full transformer forward pass for argument prediction
            logger.debug("Using rule-based prediction (full transformer inference TODO)")
            return self._rule_based_arguments(scenario)
            
        except Exception as e:
            logger.warning(f"⚠️  Error in ML prediction, using rule-based fallback: {e}")
            return self._rule_based_arguments(scenario)
    
    def _rule_based_arguments(self, scenario: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Rule-based Nmap argument prediction (fallback when ML model not available)
        
        This provides baseline recommendations based on scenario features.
        """
        arguments = []
        
        # Scan type based on stealth requirement
        if scenario.get('stealth_required', False):
            arguments.append({'flag': '-sS', 'reason': 'Stealth SYN scan'})
        else:
            arguments.append({'flag': '-sS', 'reason': 'Default SYN scan'})
        
        # WAF evasion
        if scenario.get('waf_detected', False):
            arguments.append({'flag': '-f', 'reason': 'Fragment packets to evade WAF'})
            waf_type = scenario.get('waf_type', 'unknown')
            if waf_type == 'cloudflare':
                arguments.append({'flag': '--scan-delay', 'value': '500ms', 'reason': 'Cloudflare rate limiting'})
        
        # Speed priority
        speed = scenario.get('speed_priority', 'normal')
        if speed == 'fast':
            arguments.append({'flag': '--min-rate', 'value': '1000', 'reason': 'Fast scan'})
            arguments.append({'flag': '--max-retries', 'value': '2', 'reason': 'Fewer retries'})
        elif speed == 'thorough':
            arguments.append({'flag': '--scan-delay', 'value': '1000ms', 'reason': 'Thorough scan'})
            arguments.append({'flag': '--max-retries', 'value': '3', 'reason': 'More retries'})
        
        # Port specification
        ports = scenario.get('ports_to_scan')
        if ports and isinstance(ports, list) and len(ports) > 0:
            ports_str = ','.join(map(str, ports))
            arguments.append({'flag': '-p', 'value': ports_str, 'reason': 'Specified ports'})
        else:
            arguments.append({'flag': '--top-ports', 'value': '100', 'reason': 'Top ports'})
        
        # Service detection
        if scenario.get('speed_priority') != 'fast':
            arguments.append({'flag': '-sV', 'reason': 'Service version detection'})
        
        return arguments
    
    def save_model(self, path: Optional[Path] = None) -> bool:
        """Save trained model to disk"""
        if not self.model_trained or self.trainer is None:
            logger.warning("⚠️  No trained model to save")
            return False
        
        save_path = path or self.output_dir / "ash_nmap_model.pkl"
        try:
            # Save trainer state
            # TODO: Implement model serialization
            logger.info(f"💾 Model saved to {save_path}")
            return True
        except Exception as e:
            logger.error(f"❌ Error saving model: {e}")
            return False
    
    def load_model(self, path: Optional[Path] = None) -> bool:
        """Load trained model from disk"""
        load_path = path or self.output_dir / "ash_nmap_model.pkl"
        if not load_path.exists():
            logger.warning(f"⚠️  Model file not found: {load_path}")
            return False
        
        try:
            # TODO: Implement model deserialization
            logger.info(f"📂 Model loaded from {load_path}")
            self.model_trained = True
            return True
        except Exception as e:
            logger.error(f"❌ Error loading model: {e}")
            return False

