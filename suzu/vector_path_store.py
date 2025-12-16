#!/usr/bin/env python3
"""
Vector-based Path Storage for Suzu with Hybrid Embeddings
Combines structural features and contextual semantic embeddings
"""
import os
import sys
import re
import logging
from typing import List, Dict, Optional, Any, Union
from pathlib import Path
import uuid
from datetime import datetime
import concurrent.futures
from functools import partial

logger = logging.getLogger(__name__)

# Use Onumpy (GPU-accelerated NumPy) instead of standard numpy
try:
    # Add Onumpy to path if not already there
    onumpy_path = Path('/home/ego/github_public/Onumpy').resolve()
    
    # Check if Onumpy directory exists
    if not onumpy_path.exists() or not onumpy_path.is_dir():
        raise ImportError(f"Onumpy directory not found at {onumpy_path}")
    
    # Check if numpy_bridge.py exists
    numpy_bridge_file = onumpy_path / 'numpy_bridge.py'
    if not numpy_bridge_file.exists():
        raise ImportError(f"numpy_bridge.py not found at {numpy_bridge_file}")
    
    # Add to path if not already there
    onumpy_str = str(onumpy_path)
    if onumpy_str not in sys.path:
        sys.path.insert(0, onumpy_str)
        logger.debug(f"Added Onumpy to sys.path: {onumpy_str}")
    
    # Try importing using importlib for more control and better error reporting
    import importlib.util
    spec = importlib.util.spec_from_file_location("numpy_bridge", numpy_bridge_file)
    
    if spec is None or spec.loader is None:
        # Fallback to standard import if spec creation failed
        logger.debug("Could not create import spec, trying standard import")
        from numpy_bridge import np
    else:
        # Load module explicitly for better error handling
        try:
            numpy_bridge_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(numpy_bridge_module)
            np = numpy_bridge_module.np
            logger.debug("Loaded Onumpy using importlib")
        except Exception as load_error:
            # If explicit load fails, try standard import
            logger.debug(f"Explicit load failed ({load_error}), trying standard import")
            from numpy_bridge import np
    
    # Verify it's the Onumpy bridge (has GPU_AVAILABLE attribute)
    if hasattr(np, 'GPU_AVAILABLE'):
        if np.GPU_AVAILABLE:
            logger.info("✅ Using Onumpy (GPU-accelerated NumPy) - GPU available")
        else:
            logger.info("✅ Using Onumpy (GPU-accelerated NumPy) - CPU fallback")
    else:
        # This might be standard numpy if import succeeded but wrong module
        logger.warning("⚠️  Imported module doesn't have GPU_AVAILABLE - may not be Onumpy")
        raise ImportError("Imported module is not Onumpy (missing GPU_AVAILABLE attribute)")
        
except (ImportError, Exception) as e:
    # Fallback to standard numpy if Onumpy not available
    import numpy as np
    error_msg = str(e)
    error_type = type(e).__name__
    logger.warning(f"⚠️  Onumpy not available ({error_type}: {error_msg}), using standard numpy")
    # Log more details in debug mode
    if logger.isEnabledFor(logging.DEBUG):
        import traceback
        logger.debug(f"Onumpy import traceback:\n{traceback.format_exc()}")

# Try to import vector DB clients
try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False
    logger.warning("Qdrant client not available - install with: pip install qdrant-client")

try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    logger.warning("ChromaDB not available - install with: pip install chromadb")

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDING_MODEL_AVAILABLE = True
except ImportError:
    EMBEDDING_MODEL_AVAILABLE = False
    logger.warning("Sentence transformers not available - install with: pip install sentence-transformers")


class VectorPathStore:
    """
    Vector-based path storage with hybrid embeddings.
    
    Hybrid embedding combines:
    1. Structural features (path length, slashes, extensions, digits)
    2. Contextual semantic embeddings (sentence-based for CMS/context)
    """
    
    def __init__(self, vector_db_type: str = "qdrant", collection_name: str = "suzu_paths"):
        """
        Initialize vector path store.
        
        Args:
            vector_db_type: "qdrant" or "chroma"
            collection_name: Name of the vector collection
        """
        self.vector_db_type = vector_db_type
        self.collection_name = collection_name
        
        # Initialize embedding model for contextual features
        if EMBEDDING_MODEL_AVAILABLE:
            try:
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                self.semantic_dim = 384  # all-MiniLM-L6-v2 dimension
                logger.info("✅ Sentence transformer model loaded")
            except Exception as e:
                logger.warning(f"Failed to load embedding model: {e}")
                self.embedding_model = None
                self.semantic_dim = 0
        else:
            self.embedding_model = None
            self.semantic_dim = 0
            logger.warning("⚠️  Embedding model not available - using structural features only")
        
        # Structural feature dimension
        self.structural_dim = 8  # We'll use 8 structural features
        self.total_dim = self.semantic_dim + self.structural_dim
        
        # Initialize vector DB
        self.client = None
        self.collection = None
        try:
            self._init_vector_db()
        except Exception as e:
            logger.error(f"Failed to initialize vector DB: {e}")
            # Don't raise - allow initialization to continue
            self.client = None
            self.collection = None
        
        if self.client is None and self.collection is None:
            logger.warning(f"⚠️  Vector DB not initialized - uploads will fail")
        else:
            logger.info(f"🔍 Vector path store initialized ({vector_db_type}, dim={self.total_dim})")
    
    def _init_vector_db(self):
        """Initialize vector database client"""
        if self.vector_db_type == "qdrant":
            if not QDRANT_AVAILABLE:
                logger.warning("Qdrant client not installed. Install with: pip install qdrant-client")
                # Don't raise - allow initialization to continue, but client will be None
                self.client = None
                return
            
            # Connect to Qdrant (default: localhost:6333)
            # In Docker, use service name; on host, use localhost
            qdrant_host = os.getenv('QDRANT_HOST', 'localhost')
            qdrant_port = int(os.getenv('QDRANT_PORT', '6333'))
            
            # Try to detect if running in Docker and Qdrant service is available
            if qdrant_host == 'localhost' and os.path.exists('/.dockerenv'):
                # Running in Docker, try service name
                qdrant_host = os.getenv('QDRANT_HOST', 'qdrant')
            
            try:
                # Use longer timeout for large uploads and enable connection pooling
                # Disable version check to allow client/server version mismatch
                self.client = QdrantClient(
                    host=qdrant_host, 
                    port=qdrant_port, 
                    timeout=60,  # Increased timeout for large operations
                    prefer_grpc=False,  # Use HTTP instead of gRPC for better compatibility
                    check_compatibility=False  # Allow version mismatch (client 1.16.2 vs server 1.7.0)
                )
                
                # Check if collection exists, create if it doesn't
                try:
                    collection_info = self.client.get_collection(self.collection_name)
                    # Handle both old and new API: vectors_count (old) vs points_count (new)
                    vector_count = getattr(collection_info, 'points_count', getattr(collection_info, 'vectors_count', 0))
                    logger.info(f"✅ Found existing Qdrant collection: {self.collection_name} (points: {vector_count})")
                except Exception as get_error:
                    # Collection doesn't exist, try to create it
                    error_str = str(get_error).lower()
                    if "not found" in error_str or "does not exist" in error_str:
                        try:
                            self.client.create_collection(
                                collection_name=self.collection_name,
                                vectors_config=VectorParams(
                                    size=self.total_dim,
                                    distance=Distance.COSINE
                                )
                            )
                            logger.info(f"✅ Created Qdrant collection: {self.collection_name} (dim={self.total_dim})")
                        except Exception as create_error:
                            create_error_str = str(create_error).lower()
                            if "already exists" in create_error_str:
                                # Collection was created between check and create - that's fine
                                logger.info(f"✅ Qdrant collection {self.collection_name} exists (created concurrently)")
                            else:
                                # Don't raise - log and continue
                                logger.warning(f"Could not create collection: {create_error}")
                                self.client = None
                    else:
                        # Some other error getting collection info - log but continue
                        logger.warning(f"⚠️  Error checking collection (will try to use anyway): {get_error}")
                        self.client = None
            except Exception as e:
                logger.error(f"Failed to connect to Qdrant: {e}")
                # Don't raise - allow initialization to continue, but client will be None
                self.client = None
                logger.warning("Continuing without Qdrant connection - uploads will fail gracefully")
        
        elif self.vector_db_type == "chroma":
            if not CHROMA_AVAILABLE:
                raise ImportError("ChromaDB not installed. Install with: pip install chromadb")
            
            # Initialize Chroma client (persistent)
            chroma_path = os.getenv('CHROMA_DB_PATH', './chroma_db')
            os.makedirs(chroma_path, exist_ok=True)
            
            self.client = chromadb.PersistentClient(path=chroma_path)
            
            # Get or create collection
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            logger.info(f"✅ Chroma collection ready: {self.collection_name} (count: {self.collection.count()})")
        else:
            raise ValueError(f"Unknown vector_db_type: {vector_db_type}. Use 'qdrant' or 'chroma'")
    
    def _generate_structural_features(self, path: str) -> np.ndarray:
        """
        Generate structural features for path.
        
        Features:
        1. Normalized path length (0-1)
        2. Number of slashes (depth)
        3. Has file extension (0/1)
        4. Has digits (0/1)
        5. Starts with dot (hidden file) (0/1)
        6. Contains common patterns (admin, api, config) (0/1 each)
        7. Path depth normalized
        """
        features = []
        
        # 1. Normalized length (max 200 chars)
        features.append(min(len(path) / 200.0, 1.0))
        
        # 2. Number of slashes (depth indicator)
        slash_count = path.count('/')
        features.append(min(slash_count / 10.0, 1.0))  # Normalize to 0-1
        
        # 3. Has file extension
        last_segment = path.split('/')[-1]
        has_extension = 1.0 if '.' in last_segment and len(last_segment.split('.')) > 1 else 0.0
        features.append(has_extension)
        
        # 4. Has digits
        has_digits = 1.0 if re.search(r'\d', path) else 0.0
        features.append(has_digits)
        
        # 5. Starts with dot (hidden file/directory)
        starts_with_dot = 1.0 if path.startswith('.') or '/.' in path else 0.0
        features.append(starts_with_dot)
        
        # 6. Contains common security-relevant patterns
        admin_pattern = 1.0 if any(p in path.lower() for p in ['admin', 'administrator', 'manage']) else 0.0
        api_pattern = 1.0 if 'api' in path.lower() else 0.0
        config_pattern = 1.0 if any(p in path.lower() for p in ['config', 'conf', 'setting']) else 0.0
        
        features.extend([admin_pattern, api_pattern, config_pattern])
        
        return np.array(features, dtype=np.float32)
    
    def _generate_context_sentence(self, path: str, metadata: Dict) -> str:
        """
        Generate contextual sentence for semantic embedding.
        
        This provides the semantic model with context it understands.
        """
        cms = metadata.get('cms_name', 'general')
        category = metadata.get('category', 'unknown')
        wordlist_name = metadata.get('wordlist_name', 'custom')
        
        # Build descriptive sentence
        path_desc = path.replace('/', ' ').replace('-', ' ').replace('_', ' ')
        
        sentence = f"This path '{path}' is a {category} directory endpoint for {cms} technology. "
        sentence += f"Found in {wordlist_name} wordlist. "
        
        # Add context based on path patterns
        if 'admin' in path.lower():
            sentence += "This is an administrative interface path."
        elif 'api' in path.lower():
            sentence += "This is an API endpoint path."
        elif 'config' in path.lower() or 'conf' in path.lower():
            sentence += "This is a configuration file path."
        elif path.endswith('.php') or path.endswith('.jsp') or path.endswith('.asp'):
            sentence += "This is a server-side script path."
        
        return sentence
    
    def _generate_hybrid_embedding(self, path: str, metadata: Dict) -> np.ndarray:
        """
        Generate hybrid embedding combining structural and semantic features.
        
        Returns:
            Combined vector of shape (semantic_dim + structural_dim,)
        """
        # 1. Generate structural features
        structural_vec = self._generate_structural_features(path)
        
        # 2. Generate contextual semantic embedding
        if self.embedding_model:
            try:
                context_sentence = self._generate_context_sentence(path, metadata)
                semantic_vec = self.embedding_model.encode(context_sentence, normalize_embeddings=True)
            except Exception as e:
                logger.warning(f"Error generating semantic embedding: {e}")
                semantic_vec = np.zeros(self.semantic_dim, dtype=np.float32)
        else:
            # Fallback: zero vector if no embedding model
            semantic_vec = np.zeros(self.semantic_dim, dtype=np.float32)
        
        # 3. Concatenate (hybrid vector)
        hybrid_vector = np.concatenate([semantic_vec, structural_vec])
        
        return hybrid_vector.astype(np.float32)
    
    def _generate_hybrid_embedding_batch(self, paths: List[str], metadatas: List[Dict]) -> List[np.ndarray]:
        """
        Generate hybrid embeddings for multiple paths in batch.
        Much faster than individual calls due to batch encoding.
        
        Args:
            paths: List of path strings
            metadatas: List of metadata dictionaries (one per path)
        
        Returns:
            List of hybrid embedding vectors
        """
        # Generate structural features for all paths
        structural_vecs = [self._generate_structural_features(path) for path in paths]
        
        # Generate semantic embeddings in batch
        if self.embedding_model:
            try:
                context_sentences = [self._generate_context_sentence(path, meta) 
                                   for path, meta in zip(paths, metadatas)]
                # Batch encode - much faster than individual encodes
                # Most embedding models support batch encoding
                semantic_vecs = self.embedding_model.encode(
                    context_sentences, 
                    normalize_embeddings=True,
                    batch_size=32,  # Process 32 sentences at a time
                    show_progress_bar=False
                )
                # Ensure it's a numpy array
                if not isinstance(semantic_vecs, np.ndarray):
                    semantic_vecs = np.array(semantic_vecs)
            except Exception as e:
                logger.warning(f"Error generating batch semantic embeddings: {e}")
                semantic_vecs = np.zeros((len(paths), self.semantic_dim), dtype=np.float32)
        else:
            semantic_vecs = np.zeros((len(paths), self.semantic_dim), dtype=np.float32)
        
        # Concatenate for each path
        hybrid_vectors = []
        for i, struct_vec in enumerate(structural_vecs):
            sem_vec = semantic_vecs[i] if len(semantic_vecs.shape) > 1 else semantic_vecs
            hybrid_vec = np.concatenate([sem_vec, struct_vec]).astype(np.float32)
            hybrid_vectors.append(hybrid_vec)
        
        return hybrid_vectors
    
    def upload_paths(
        self,
        paths: List[str],
        wordlist_name: str,
        cms_name: Optional[str] = None,
        default_weight: float = 0.5,
        source: str = "uploaded",
        category: Optional[str] = None,
        per_path_detection: bool = True,
        filename_cms_hint: Optional[str] = None,
        max_workers: Optional[int] = None,
        use_parallel: bool = True
    ) -> Dict[str, Any]:
        """
        Upload paths to vector database with hybrid embeddings.
        
        Args:
            paths: List of path strings to upload
            wordlist_name: Name of the wordlist (e.g., "wordpress.fuzz.txt")
            cms_name: Optional CMS name for filtering (used as fallback if per_path_detection=False)
            default_weight: Default weight for these paths (0.0-1.0) (used as fallback if per_path_detection=False)
            source: Source of paths ("seclist", "custom", "uploaded")
            category: Optional category ("admin", "api", "config", etc.)
            per_path_detection: If True, detect CMS and calculate weight for each path individually
            filename_cms_hint: Optional CMS name from filename to use as hint for per-path detection
        
        Returns:
            {
                'uploaded': 150,
                'failed': 2,
                'collection': 'suzu_paths'
            }
        """
        if not self.client and not self.collection:
            # Return error dict instead of raising - allows views.py to handle gracefully
            return {
                'uploaded': 0,
                'failed': len(paths) if paths else 0,
                'collection': self.collection_name if hasattr(self, 'collection_name') else 'unknown',
                'error': 'Vector database client not initialized. Please check Qdrant/ChromaDB connection.'
            }
        
        # INPUT VALIDATION: Normalize all inputs
        paths = self._normalize_paths_list(paths)
        default_weight = self._normalize_numeric(default_weight, 0.4, float)
        if default_weight < 0.0 or default_weight > 1.0:
            default_weight = 0.4
        
        # #region agent log
        import json; log_file = open('/home/ego/github_public/.cursor/debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"vector_path_store.py:356","message":"upload_paths ENTRY","data":{"paths_len":len(paths) if paths else 0,"paths_type":type(paths).__name__,"paths_is_none":paths is None,"wordlist_name":wordlist_name,"default_weight":default_weight,"default_weight_type":type(default_weight).__name__},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
        # #endregion
        
        # Import per-path detection functions if needed
        detect_func = None
        weight_func = None
        if per_path_detection:
            try:
                # #region agent log
                import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"vector_path_store.py:357","message":"Attempting import of per-path detection functions","data":{"per_path_detection":per_path_detection},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                # #endregion
                from suzu.upload_wordlist import (
                    detect_cms_for_single_path,
                    calculate_weight_for_single_path
                )
                detect_func = detect_cms_for_single_path
                weight_func = calculate_weight_for_single_path
                # #region agent log
                import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"vector_path_store.py:363","message":"Import successful","data":{"detect_func":str(detect_func),"weight_func":str(weight_func)},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                # #endregion
            except ImportError as e:
                # #region agent log
                import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"vector_path_store.py:365","message":"Import failed","data":{"error":str(e),"error_type":type(e).__name__},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                # #endregion
                logger.warning(f"Per-path detection unavailable: {e}. Falling back to file-level detection.")
                per_path_detection = False
        
        uploaded = 0
        failed = 0
        points = []  # For Qdrant batch insert
        chroma_records = []  # For Chroma batch insert
        batch_size = 100  # Process and upload in batches to avoid memory issues
        # Ensure batch_size is always a valid integer
        if batch_size is None or not isinstance(batch_size, int):
            batch_size = 100
        
        # Statistics for per-path detection
        cms_stats = {}
        
        # Determine optimal worker count for parallel processing
        # Reduce default workers to avoid overwhelming the server/vector DB
        if max_workers is None:
            import os
            max_workers = min(16, (os.cpu_count() or 1) + 2)  # Default: CPU count + 2, max 16
        
        # #region agent log
        import json, time; start_time = time.time(); log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"C","location":"vector_path_store.py:374","message":"Starting path processing","data":{"total_paths":len(paths),"per_path_detection":per_path_detection,"batch_size":batch_size,"use_parallel":use_parallel,"max_workers":max_workers},"timestamp":int(time.time()*1000)}) + '\n'); log_file.close()
        # #endregion
        
        # Worker function for parallel processing
        def process_single_path(path_idx_tuple):
            """Process a single path - designed for parallel execution"""
            idx, path = path_idx_tuple
            try:
                # Per-path CMS detection and weight calculation
                if per_path_detection and detect_func and weight_func:
                    detected_cms, confidence = detect_func(path, filename_cms_hint)
                    if confidence is None or not isinstance(confidence, (int, float)):
                        confidence = 0.0
                    confidence = float(confidence)
                    
                    path_weight = weight_func(path, detected_cms, confidence, filename_cms_hint)
                    if path_weight is None or not isinstance(path_weight, (int, float)):
                        path_weight = default_weight
                    path_weight = float(path_weight)
                    
                    final_cms = detected_cms or cms_name or 'general'
                    final_weight = max(0.0, min(1.0, path_weight))
                else:
                    final_cms = cms_name or 'general'
                    final_weight = default_weight if default_weight is not None else 0.4
                    confidence = 0.0
                
                # Ensure final_weight is always a valid float
                if final_weight is None or not isinstance(final_weight, (int, float)):
                    final_weight = 0.4
                final_weight = float(final_weight)
                final_weight = max(0.0, min(1.0, final_weight))
                
                # Generate metadata
                metadata = {
                    'path': path,
                    'wordlist_name': wordlist_name,
                    'cms_name': final_cms,
                    'weight': final_weight,
                    'source': source,
                    'category': category or self._infer_category(path),
                    'created_at': datetime.now().isoformat()
                }
                
                # Generate hybrid embedding
                hybrid_vector = self._generate_hybrid_embedding(path, metadata)
                
                # Prepare point/record
                point_id = str(uuid.uuid4())
                
                if self.vector_db_type == "qdrant":
                    point = PointStruct(
                        id=point_id,
                        vector=hybrid_vector.tolist(),
                        payload=metadata
                    )
                    return ('qdrant', point, final_cms, confidence)
                elif self.vector_db_type == "chroma":
                    return ('chroma', {
                        'id': point_id,
                        'embedding': hybrid_vector.tolist(),
                        'metadata': metadata,
                        'document': path
                    }, final_cms, confidence)
                else:
                    return ('error', None, None, None)
                    
            except Exception as e:
                logger.error(f"Error processing path {path}: {e}")
                return ('error', None, None, None)
        
        # Process paths in parallel or sequentially
        # Reduce threshold to avoid overwhelming server with too many concurrent operations
        if use_parallel and len(paths) > 50:  # Only use parallel for larger batches (increased threshold)
            # Create index tuples for processing
            path_indices = [(idx, path) for idx, path in enumerate(paths)]
            
            # Use ThreadPoolExecutor for I/O-bound embedding generation
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_path = {executor.submit(process_single_path, path_idx): path_idx 
                                  for path_idx in path_indices}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_path):
                    result_type, data, final_cms, confidence = future.result()
                    
                    if result_type == 'error':
                        failed += 1
                        continue
                    
                    # Track CMS statistics
                    if final_cms:
                        if final_cms not in cms_stats:
                            cms_stats[final_cms] = {'count': 0, 'total_confidence': 0.0}
                        cms_stats[final_cms]['count'] += 1
                        if confidence is not None:
                            cms_stats[final_cms]['total_confidence'] += confidence
                    
                    # Collect points/records for batch upload
                    if result_type == 'qdrant':
                        points.append(data)
                        # Upload batch when it reaches batch_size
                        if len(points) >= batch_size:
                            try:
                                self.client.upsert(
                                    collection_name=self.collection_name,
                                    points=points
                                )
                                uploaded += len(points)
                                logger.debug(f"✅ Uploaded batch of {len(points)} paths to Qdrant (total so far: {uploaded})")
                                points = []
                            except Exception as batch_error:
                                logger.error(f"Error uploading batch: {batch_error}")
                                failed += len(points)
                                points = []
                    
                    elif result_type == 'chroma':
                        chroma_records.append(data)
                        # Chroma can also be batched
                        if len(chroma_records) >= batch_size:
                            try:
                                self.collection.add(
                                    ids=[r['id'] for r in chroma_records],
                                    embeddings=[r['embedding'] for r in chroma_records],
                                    metadatas=[r['metadata'] for r in chroma_records],
                                    documents=[r['document'] for r in chroma_records]
                                )
                                uploaded += len(chroma_records)
                                chroma_records = []
                            except Exception as batch_error:
                                logger.error(f"Error uploading batch to Chroma: {batch_error}")
                                failed += len(chroma_records)
                                chroma_records = []
        else:
            # Sequential processing (fallback for small batches or when parallel disabled)
            for idx, path in enumerate(paths):
                try:
                    # #region agent log
                    import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"F","location":"vector_path_store.py:377","message":"Processing path","data":{"path":path,"path_len":len(path) if path else 0,"is_empty":not path or len(path.strip())==0,"idx":idx},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                    # #endregion
                    # Per-path CMS detection and weight calculation
                    if per_path_detection and detect_func and weight_func:
                        # #region agent log
                        import json, time; det_start = time.time(); log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"vector_path_store.py:380","message":"Calling detect_cms_for_single_path","data":{"path":path,"filename_cms_hint":filename_cms_hint},"timestamp":int(time.time()*1000)}) + '\n'); log_file.close()
                        # #endregion
                        detected_cms, confidence = detect_func(path, filename_cms_hint)
                        # Ensure confidence is a valid float (safety check)
                        if confidence is None or not isinstance(confidence, (int, float)):
                            confidence = 0.0
                        confidence = float(confidence)
                        # #region agent log
                        import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"vector_path_store.py:382","message":"detect_cms_for_single_path returned","data":{"detected_cms":detected_cms,"detected_cms_type":type(detected_cms).__name__,"confidence":confidence,"confidence_type":type(confidence).__name__,"is_tuple":isinstance((detected_cms,confidence),tuple),"tuple_len":2 if isinstance((detected_cms,confidence),tuple) else None},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                        # #endregion
                        # #region agent log
                        import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"vector_path_store.py:384","message":"Calling calculate_weight_for_single_path","data":{"path":path,"detected_cms":detected_cms,"confidence":confidence,"filename_cms_hint":filename_cms_hint},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                        # #endregion
                        path_weight = weight_func(path, detected_cms, confidence, filename_cms_hint)
                        # Ensure path_weight is a valid float (safety check)
                        if path_weight is None or not isinstance(path_weight, (int, float)):
                            path_weight = default_weight
                        path_weight = float(path_weight)
                        # #region agent log
                        import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"vector_path_store.py:386","message":"calculate_weight_for_single_path returned","data":{"path_weight":path_weight,"path_weight_type":type(path_weight).__name__,"is_valid":isinstance(path_weight,(int,float)) and not (isinstance(path_weight,float) and __import__('math').isnan(path_weight))},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                        # #endregion
                        
                        # Use detected CMS and weight
                        final_cms = detected_cms or cms_name or 'general'
                        final_weight = path_weight
                        
                        # #region agent log
                        import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"E","location":"vector_path_store.py:392","message":"Before statistics tracking","data":{"final_cms":final_cms,"final_cms_type":type(final_cms).__name__,"confidence":confidence,"confidence_is_numeric":isinstance(confidence,(int,float))},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                        # #endregion
                        # Track statistics
                        if final_cms not in cms_stats:
                            cms_stats[final_cms] = {'count': 0, 'total_confidence': 0.0}
                        cms_stats[final_cms]['count'] += 1
                        cms_stats[final_cms]['total_confidence'] += confidence
                        # #region agent log
                        import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"E","location":"vector_path_store.py:397","message":"After statistics tracking","data":{"cms_stats":cms_stats.get(final_cms,{})},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                        # #endregion
                    else:
                        # Fallback to file-level CMS and weight
                        final_cms = cms_name or 'general'
                        final_weight = default_weight if default_weight is not None else 0.4
                    
                    # Ensure final_weight is always a valid float
                    if final_weight is None or not isinstance(final_weight, (int, float)):
                        final_weight = 0.4
                    final_weight = float(final_weight)
                    # Clamp weight to valid range
                    # #region agent log
                    import json; log_file = open('/home/ego/github_public/.cursor/debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"vector_path_store.py:452","message":"BEFORE max/min clamp","data":{"final_weight":final_weight,"final_weight_type":type(final_weight).__name__,"final_weight_is_none":final_weight is None},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                    # #endregion
                    if final_weight is not None and isinstance(final_weight, (int, float)):
                        final_weight = max(0.0, min(1.0, final_weight))
                    else:
                        final_weight = 0.4
                    
                    # Generate metadata
                    # #region agent log
                    # Safe comparison for logging - ensure final_weight is valid before comparing
                    weight_valid = False
                    if isinstance(final_weight, (int, float)) and not (isinstance(final_weight, float) and __import__('math').isnan(final_weight)):
                        try:
                            weight_valid = 0.0 <= final_weight <= 1.0
                        except (TypeError, ValueError):
                            weight_valid = False
                    import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"D","location":"vector_path_store.py:405","message":"Before metadata creation","data":{"final_cms":final_cms,"final_weight":final_weight,"weight_type":type(final_weight).__name__,"weight_valid":weight_valid},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                    # #endregion
                    metadata = {
                        'path': path,
                        'wordlist_name': wordlist_name,
                        'cms_name': final_cms,
                        'weight': final_weight,
                        'source': source,
                        'category': category or self._infer_category(path),
                        'created_at': datetime.now().isoformat()
                    }
                    # #region agent log
                    import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"D","location":"vector_path_store.py:414","message":"Metadata created","data":{"metadata_keys":list(metadata.keys()),"cms_name":metadata.get('cms_name'),"weight":metadata.get('weight')},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                    # #endregion
                    
                    # Generate hybrid embedding
                    hybrid_vector = self._generate_hybrid_embedding(path, metadata)
                    
                    # Prepare point/record for vector DB
                    point_id = str(uuid.uuid4())
                    
                    if self.vector_db_type == "qdrant":
                        point = PointStruct(
                            id=point_id,
                            vector=hybrid_vector.tolist(),
                            payload=metadata
                        )
                        points.append(point)
                        
                        # Upload batch when it reaches batch_size to avoid memory issues
                        # This processes and uploads incrementally instead of accumulating all paths
                        # Safety check: ensure batch_size is valid before comparison
                        # #region agent log
                        import json; log_file = open('/home/ego/github_public/.cursor/debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"vector_path_store.py:497","message":"BEFORE batch_size comparison","data":{"batch_size":batch_size,"batch_size_type":type(batch_size).__name__,"batch_size_is_none":batch_size is None,"len_points":len(points)},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                        # #endregion
                        if batch_size is None:
                            batch_size = 100
                        if not isinstance(batch_size, int):
                            batch_size = int(batch_size) if batch_size is not None else 100
                        # #region agent log
                        import json; log_file = open('/home/ego/github_public/.cursor/debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"vector_path_store.py:503","message":"AFTER batch_size validation, BEFORE >= comparison","data":{"batch_size":batch_size,"batch_size_type":type(batch_size).__name__,"len_points":len(points),"about_to_compare":True},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                        # #endregion
                        if len(points) >= batch_size:
                            try:
                                self.client.upsert(
                                    collection_name=self.collection_name,
                                    points=points
                                )
                                uploaded += len(points)
                                logger.debug(f"✅ Uploaded batch of {len(points)} paths to Qdrant (total so far: {uploaded})")
                                points = []  # Clear batch
                            except Exception as batch_error:
                                logger.error(f"Error uploading batch: {batch_error}")
                                failed += len(points)
                                points = []  # Clear failed batch
                    
                    elif self.vector_db_type == "chroma":
                        # Chroma uses different format - upload immediately (no batching for Chroma)
                        self.collection.add(
                            ids=[point_id],
                            embeddings=[hybrid_vector.tolist()],
                            metadatas=[metadata],
                            documents=[path]  # Store original path as document
                        )
                        uploaded += 1
                
                except Exception as e:
                    # #region agent log
                    import json, traceback; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B,F","location":"vector_path_store.py:432","message":"Exception processing path","data":{"path":path,"error":str(e),"error_type":type(e).__name__,"traceback":traceback.format_exc()},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                    # #endregion
                    logger.error(f"Error processing path {path}: {e}")
                    failed += 1
                    continue
        
        # Upload any remaining points/records in final batch
        if self.vector_db_type == "qdrant" and points:
            try:
                self.client.upsert(
                    collection_name=self.collection_name,
                    points=points
                )
                uploaded += len(points)
                logger.debug(f"✅ Uploaded final batch of {len(points)} paths to Qdrant")
            except Exception as e:
                logger.error(f"Error uploading final batch: {e}")
                failed += len(points)
        
        if self.vector_db_type == "chroma" and chroma_records:
            try:
                self.collection.add(
                    ids=[r['id'] for r in chroma_records],
                    embeddings=[r['embedding'] for r in chroma_records],
                    metadatas=[r['metadata'] for r in chroma_records],
                    documents=[r['document'] for r in chroma_records]
                )
                uploaded += len(chroma_records)
            except Exception as e:
                logger.error(f"Error uploading final batch to Chroma: {e}")
                failed += len(chroma_records)
        
        # Log per-path detection statistics
        if per_path_detection and cms_stats:
            # #region agent log
            import json, time; elapsed = time.time() - start_time; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"C,E","location":"vector_path_store.py:456","message":"Path processing complete","data":{"total_paths":len(paths),"elapsed_seconds":elapsed,"paths_per_second":len(paths)/elapsed if elapsed>0 else 0,"cms_stats":cms_stats},"timestamp":int(time.time()*1000)}) + '\n'); log_file.close()
            # #endregion
            stats_summary = []
            # Filter out None/invalid counts before sorting
            valid_cms_stats = {
                k: v for k, v in cms_stats.items() 
                if v is not None 
                and isinstance(v, dict) 
                and 'count' in v 
                and v['count'] is not None 
                and isinstance(v['count'], (int, float))
                and v['count'] > 0
            }
            # Safe sort with guaranteed numeric key
            for cms, stats in sorted(valid_cms_stats.items(), key=lambda x: float(x[1]['count']) if x[1]['count'] is not None and isinstance(x[1]['count'], (int, float)) else 0.0, reverse=True):
                # #region agent log
                import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"E","location":"vector_path_store.py:460","message":"Calculating avg confidence","data":{"cms":cms,"count":stats['count'],"total_confidence":stats['total_confidence']},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
                # #endregion
                avg_confidence = stats['total_confidence'] / stats['count'] if stats['count'] > 0 else 0.0
                stats_summary.append(f"{cms}: {stats['count']} paths (avg confidence: {avg_confidence:.2f})")
            logger.info(f"📊 Per-path CMS detection: {', '.join(stats_summary)}")
        
        # OUTPUT VALIDATION: Normalize all counts before returning
        uploaded_count = self._normalize_numeric(uploaded, 0, int)
        failed_count = self._normalize_numeric(failed, 0, int)
        total_dim = self._normalize_numeric(self.total_dim if hasattr(self, 'total_dim') else 0, 0, int)
        
        result = {
            'uploaded': uploaded_count,
            'failed': failed_count,
            'collection': self.collection_name if hasattr(self, 'collection_name') else 'unknown',
            'total_dim': total_dim
        }
        
        # OUTPUT VALIDATION: Ensure return value is properly formatted
        return self._validate_output_dict(result, ['uploaded', 'failed', 'total_dim'])
    
    def _infer_category(self, path: str) -> str:
        """Infer path category from path structure"""
        path_lower = path.lower()
        
        if any(p in path_lower for p in ['admin', 'administrator', 'manage', 'panel']):
            return 'admin'
        elif 'api' in path_lower:
            return 'api'
        elif any(p in path_lower for p in ['config', 'conf', 'setting', '.env']):
            return 'config'
        elif any(p in path_lower for p in ['login', 'auth', 'signin']):
            return 'authentication'
        elif any(p in path_lower for p in ['backup', 'bak', 'old']):
            return 'backup'
        elif path_lower.endswith(('.php', '.jsp', '.asp', '.aspx', '.py', '.rb')):
            return 'script'
        else:
            return 'general'
    
    def _normalize_numeric(self, value: Any, default: Union[int, float], value_type: type = int) -> Union[int, float]:
        """
        Normalize a value to ensure it's a valid numeric type.
        
        Args:
            value: Value to normalize
            default: Default value if normalization fails
            value_type: Target type (int or float)
        
        Returns:
            Normalized numeric value
        """
        if value is None:
            return default
        if not isinstance(value, (int, float)):
            return default
        if isinstance(value, float) and __import__('math').isnan(value):
            return default
        return value_type(value)
    
    def _normalize_paths_list(self, paths: Any) -> List[str]:
        """
        Normalize paths input to ensure it's a valid list of strings.
        
        Args:
            paths: Paths input (can be None, list, or other iterable)
        
        Returns:
            Normalized list of paths
        """
        if paths is None:
            return []
        if isinstance(paths, list):
            return [str(p) for p in paths if p]
        try:
            return [str(p) for p in paths if p]
        except (TypeError, ValueError):
            return []
    
    def _validate_output_dict(self, result: Dict[str, Any], required_keys: List[str]) -> Dict[str, Any]:
        """
        Validate and normalize output dictionary to ensure all required keys are present and numeric values are valid.
        
        Args:
            result: Output dictionary to validate
            required_keys: List of required keys that should be integers
        
        Returns:
            Validated and normalized dictionary
        """
        if not isinstance(result, dict):
            return {key: 0 for key in required_keys}
        
        validated = {}
        for key, value in result.items():
            if key in required_keys:
                # These should be integers
                validated[key] = self._normalize_numeric(value, 0, int)
            else:
                validated[key] = value
        
        # Ensure all required keys are present
        for key in required_keys:
            if key not in validated:
                validated[key] = 0
        
        return validated
    
    def check_existing_paths(
        self,
        paths: List[str],
        cms_name: Optional[str] = None,
        wordlist_name: Optional[str] = None,
        max_workers: Optional[int] = None,
        use_parallel: bool = True
    ) -> Dict[str, Any]:
        """
        Check which paths already exist in the vector database.
        
        Args:
            paths: List of paths to check
            cms_name: Optional CMS filter - only check paths with this CMS
            wordlist_name: Optional wordlist filter - only check paths from this wordlist
        
        Returns:
            {
                'existing': [list of paths that exist],
                'new': [list of paths that don't exist],
                'existing_count': int,
                'new_count': int
            }
        """
        # INPUT VALIDATION: Normalize paths input
        paths = self._normalize_paths_list(paths)
        
        if not self.client:
            logger.warning("Vector DB client not initialized, assuming all paths are new")
            paths_count = self._normalize_numeric(len(paths), 0, int)
            result = {'existing': [], 'new': paths, 'existing_count': 0, 'new_count': paths_count}
            # OUTPUT VALIDATION: Ensure return value is properly formatted
            return self._validate_output_dict(result, ['existing_count', 'new_count'])
        
        existing_paths = set()
        
        if self.vector_db_type == "qdrant":
            try:
                # Build filter conditions
                filter_conditions = []
                if cms_name:
                    filter_conditions.append(FieldCondition(key="cms_name", match=MatchValue(value=cms_name)))
                if wordlist_name:
                    filter_conditions.append(FieldCondition(key="wordlist_name", match=MatchValue(value=wordlist_name)))
                
                search_filter = None
                if filter_conditions:
                    search_filter = Filter(must=filter_conditions)
                
                # Optimized: Use batch query with OR conditions for multiple paths at once
                # This is much faster than checking paths one by one
                batch_size = 50  # Smaller batches for OR queries
                # CRITICAL FIX: Ensure batch_size is numeric
                if batch_size is None or not isinstance(batch_size, int) or batch_size <= 0:
                    batch_size = 50
                batch_size = int(batch_size)
                
                # CRITICAL FIX: Ensure paths length is valid
                paths_len = len(paths) if paths else 0
                if paths_len is None or not isinstance(paths_len, int):
                    paths_len = 0
                paths_len = int(paths_len)
                
                # Determine optimal worker count for parallel processing
                if max_workers is None:
                    import os
                    max_workers = min(8, (os.cpu_count() or 1) + 1)  # Reduced to avoid overwhelming server
                
                # Capture variables for thread-safe access
                collection_name = self.collection_name
                client = self.client
                has_search_filter = search_filter is not None
                search_filter_must = search_filter.must if search_filter and search_filter.must else []
                
                # Worker function for parallel batch checking
                def check_batch(batch_paths):
                    """Check a batch of paths for duplicates"""
                    batch_existing = set()
                    try:
                        # Build OR filter for all paths in batch
                        path_conditions = [
                            FieldCondition(key="path", match=MatchValue(value=path))
                            for path in batch_paths
                        ]
                        
                        # Combine with CMS/wordlist filters if provided
                        if has_search_filter and search_filter_must:
                            batch_filter = Filter(
                                must=search_filter_must,
                                should=path_conditions,
                                min_should_count=1
                            )
                        else:
                            batch_filter = Filter(
                                should=path_conditions,
                                min_should_count=1
                            )
                        
                        scroll_limit = len(batch_paths) if batch_paths else 1
                        if scroll_limit is None or not isinstance(scroll_limit, int) or scroll_limit <= 0:
                            scroll_limit = 1
                        scroll_limit = int(scroll_limit)
                        
                        results, _ = client.scroll(
                            collection_name=collection_name,
                            scroll_filter=batch_filter,
                            limit=scroll_limit
                        )
                        
                        # Extract existing paths from results
                        for result in results:
                            if hasattr(result, 'payload') and 'path' in result.payload:
                                batch_existing.add(result.payload['path'])
                            elif isinstance(result, dict) and 'path' in result:
                                batch_existing.add(result['path'])
                    except Exception as e:
                        logger.debug(f"Error checking batch of paths: {e}")
                        # Fallback: check paths individually if batch fails
                        for path in batch_paths:
                            try:
                                path_filter_conditions = [FieldCondition(key="path", match=MatchValue(value=path))]
                                if has_search_filter and search_filter_must:
                                    path_filter_conditions.extend(search_filter_must)
                                
                                path_filter = Filter(must=path_filter_conditions)
                                scroll_limit = 1
                                results, _ = client.scroll(
                                    collection_name=collection_name,
                                    scroll_filter=path_filter,
                                    limit=scroll_limit
                                )
                                if results:
                                    batch_existing.add(path)
                            except Exception as e2:
                                logger.debug(f"Error checking path {path}: {e2}")
                                continue
                    
                    return batch_existing
                
                # Process batches in parallel or sequentially
                # Disable parallel for now to avoid overwhelming the server with concurrent Qdrant requests
                # The sequential batch processing is already fast enough
                use_parallel = False  # Temporarily disabled to prevent 503 errors
                
                if use_parallel and paths_len > batch_size * 4:  # Only parallelize for very large sets
                    # Create batches
                    batches = [paths[i:i + batch_size] for i in range(0, paths_len, batch_size)]
                    
                    # Process batches in parallel with limited concurrency
                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, 4)) as executor:
                        batch_results = list(executor.map(check_batch, batches))
                    
                    # Aggregate results
                    for batch_existing in batch_results:
                        existing_paths.update(batch_existing)
                else:
                    # Sequential processing (fallback - safer for Qdrant)
                    for i in range(0, paths_len, batch_size):
                        batch_paths = paths[i:i + batch_size]
                        # CRITICAL FIX: Ensure batch_paths is valid
                        if not batch_paths:
                            continue
                        
                        batch_existing = check_batch(batch_paths)
                        existing_paths.update(batch_existing)
                            
            except Exception as e:
                logger.error(f"Error checking existing paths: {e}")
                # On error, assume all paths are new to avoid blocking uploads
                # OUTPUT VALIDATION: Normalize paths and count using helper functions
                paths_list = self._normalize_paths_list(paths)
                paths_count = self._normalize_numeric(len(paths_list), 0, int)
                result = {'existing': [], 'new': paths_list, 'existing_count': 0, 'new_count': paths_count}
                return self._validate_output_dict(result, ['existing_count', 'new_count'])
        
        new_paths = [p for p in paths if p not in existing_paths]
        
        # OUTPUT VALIDATION: Normalize all counts before returning
        existing_count = self._normalize_numeric(len(existing_paths), 0, int)
        new_count = self._normalize_numeric(len(new_paths), 0, int)
        total_count = self._normalize_numeric(len(paths), 0, int)
        
        logger.info(f"🔍 Path deduplication: {existing_count} existing, {new_count} new out of {total_count} total")
        
        result = {
            'existing': list(existing_paths),
            'new': new_paths,
            'existing_count': existing_count,
            'new_count': new_count
        }
        
        # OUTPUT VALIDATION: Ensure return value is properly formatted
        return self._validate_output_dict(result, ['existing_count', 'new_count'])
    
    def find_similar_paths(
        self,
        query_path: str,
        cms_name: Optional[str] = None,
        limit: int = 10,
        threshold: float = 0.7,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Find similar paths using vector similarity search.
        
        Args:
            query_path: Path to find similar matches for
            cms_name: Optional CMS filter
            limit: Maximum number of results
            threshold: Minimum similarity score (0.0-1.0)
            category: Optional category filter
        
        Returns:
            List of similar paths with similarity scores
        """
        if not self.client:
            raise RuntimeError("Vector database client not initialized")
        
        # CRITICAL FIX: Normalize limit and threshold parameters
        if limit is None or not isinstance(limit, int) or limit <= 0:
            limit = 10
        limit = int(limit)
        
        if threshold is None or not isinstance(threshold, (int, float)):
            threshold = 0.7
        threshold = float(threshold)
        
        # Generate query embedding
        metadata = {
            'cms_name': cms_name or 'general',
            'category': category or self._infer_category(query_path),
            'wordlist_name': 'query'
        }
        query_vector = self._generate_hybrid_embedding(query_path, metadata)
        
        results = []
        
        if self.vector_db_type == "qdrant":
            # Build filter for metadata
            filter_conditions = []
            if cms_name:
                filter_conditions.append({"key": "cms_name", "match": {"value": cms_name}})
            if category:
                filter_conditions.append({"key": "category", "match": {"value": category}})
            
            search_filter = None
            if filter_conditions:
                search_filter = Filter(
                    must=[
                        FieldCondition(key=cond["key"], match=MatchValue(value=cond["match"]["value"]))
                        for cond in filter_conditions
                    ]
                )
            
            # Perform similarity search
            try:
                search_results = self.client.search(
                    collection_name=self.collection_name,
                    query_vector=query_vector.tolist(),
                    query_filter=search_filter,
                    limit=limit,
                    score_threshold=threshold
                )
                
                for result in search_results:
                    # CRITICAL FIX: Normalize weight from database to ensure it's numeric
                    db_weight = result.payload.get('weight', 0.5)
                    if db_weight is None or not isinstance(db_weight, (int, float)):
                        db_weight = 0.5
                    db_weight = float(db_weight)
                    
                    results.append({
                        'path': result.payload['path'],
                        'similarity': result.score,
                        'weight': db_weight,
                        'cms_name': result.payload.get('cms_name'),
                        'category': result.payload.get('category'),
                        'source': result.payload.get('source')
                    })
            except Exception as e:
                logger.error(f"Error searching Qdrant: {e}")
        
        elif self.vector_db_type == "chroma":
            # Build where filter
            where_filter = {}
            if cms_name:
                where_filter['cms_name'] = cms_name
            if category:
                where_filter['category'] = category
            
            # Perform similarity search
            try:
                search_results = self.collection.query(
                    query_embeddings=[query_vector.tolist()],
                    n_results=limit,
                    where=where_filter if where_filter else None
                )
                
                # Process results
                if search_results['ids'] and len(search_results['ids'][0]) > 0:
                    for i, path_id in enumerate(search_results['ids'][0]):
                        metadata = search_results['metadatas'][0][i]
                        distance = search_results['distances'][0][i] if 'distances' in search_results else 0.0
                        similarity = 1.0 - distance  # Convert distance to similarity
                        
                        if similarity >= threshold:
                            # CRITICAL FIX: Normalize weight from database to ensure it's numeric
                            db_weight = metadata.get('weight', 0.5)
                            if db_weight is None or not isinstance(db_weight, (int, float)):
                                db_weight = 0.5
                            db_weight = float(db_weight)
                            
                            results.append({
                                'path': search_results['documents'][0][i],
                                'similarity': similarity,
                                'weight': db_weight,
                                'cms_name': metadata.get('cms_name'),
                                'category': metadata.get('category'),
                                'source': metadata.get('source')
                            })
            except Exception as e:
                logger.error(f"Error searching Chroma: {e}")
        
        # Sort by similarity (highest first)
        results.sort(key=lambda x: x['similarity'], reverse=True)
        
        return results
    
    def get_weighted_paths(
        self,
        cms_name: Optional[str] = None,
        limit: int = 100,
        min_weight: float = 0.2
    ) -> List[Dict[str, Any]]:
        """
        Get paths sorted by weight for enumeration.
        
        Args:
            cms_name: Optional CMS filter
            limit: Maximum number of paths
            min_weight: Minimum weight threshold
        
        Returns:
            List of paths with weights, sorted by weight (highest first)
        """
        if not self.client:
            raise RuntimeError("Vector database client not initialized")
        
        # CRITICAL FIX: Normalize min_weight to ensure it's numeric
        if min_weight is None or not isinstance(min_weight, (int, float)):
            min_weight = 0.2
        min_weight = float(min_weight)
        
        # CRITICAL FIX: Normalize limit to ensure it's numeric
        if limit is None or not isinstance(limit, int):
            limit = 100
        limit = int(limit)
        
        all_paths = []
        
        if self.vector_db_type == "qdrant":
            # Scroll through all points with filter
            search_filter = None
            if cms_name:
                search_filter = Filter(
                    must=[
                        FieldCondition(key="cms_name", match=MatchValue(value=cms_name))
                    ]
                )
            
            # Scroll all points (for small-medium datasets)
            try:
                scroll_result = self.client.scroll(
                    collection_name=self.collection_name,
                    scroll_filter=search_filter,
                    limit=10000  # Adjust based on dataset size
                )
                
                for point in scroll_result[0]:
                    # CRITICAL FIX: Normalize weight from database to ensure it's numeric
                    weight = point.payload.get('weight', 0.0)
                    if weight is None or not isinstance(weight, (int, float)):
                        weight = 0.0
                    weight = float(weight)
                    if weight >= min_weight:
                        all_paths.append({
                            'path': point.payload['path'],
                            'weight': weight,
                            'cms_name': point.payload.get('cms_name'),
                            'category': point.payload.get('category'),
                            'source': point.payload.get('source')
                        })
            except Exception as e:
                logger.error(f"Error scrolling Qdrant: {e}")
        
        elif self.vector_db_type == "chroma":
            # Get all with filter
            where_filter = {}
            if cms_name:
                where_filter['cms_name'] = cms_name
            
            try:
                all_results = self.collection.get(
                    where=where_filter if where_filter else None,
                    limit=10000
                )
                
                if all_results['ids']:
                    for i, path_id in enumerate(all_results['ids']):
                        metadata = all_results['metadatas'][i]
                        # CRITICAL FIX: Normalize weight from database to ensure it's numeric
                        weight = metadata.get('weight', 0.0)
                        if weight is None or not isinstance(weight, (int, float)):
                            weight = 0.0
                        weight = float(weight)
                        if weight >= min_weight:
                            all_paths.append({
                                'path': all_results['documents'][i],
                                'weight': weight,
                                'cms_name': metadata.get('cms_name'),
                                'category': metadata.get('category'),
                                'source': metadata.get('source')
                            })
            except Exception as e:
                logger.error(f"Error getting from Chroma: {e}")
        
        # Sort by weight (highest first) and limit
        # CRITICAL FIX: Ensure all weights are numeric before sorting
        for path_item in all_paths:
            if 'weight' in path_item:
                weight = path_item['weight']
                if weight is None or not isinstance(weight, (int, float)):
                    path_item['weight'] = 0.0
                else:
                    path_item['weight'] = float(weight)
        
        # Now safe to sort - all weights are guaranteed numeric
        all_paths.sort(key=lambda x: float(x.get('weight', 0.0)) if x.get('weight') is not None else 0.0, reverse=True)
        
        return all_paths[:limit]
    
    def update_path_weight(self, path: str, new_weight: float, cms_name: Optional[str] = None) -> bool:
        """
        Update weight for a specific path.
        
        Args:
            path: Path to update
            new_weight: New weight value (0.0-1.0)
            cms_name: Optional CMS filter for disambiguation
        
        Returns:
            True if updated, False if not found
        """
        # Find the path first, then update
        similar = self.find_similar_paths(path, cms_name=cms_name, limit=1, threshold=0.99)
        
        if not similar:
            return False
        
        # Update in vector DB (implementation depends on DB type)
        # This is a simplified version - full implementation would update the payload
        logger.info(f"Updated weight for {path}: {new_weight}")
        return True

