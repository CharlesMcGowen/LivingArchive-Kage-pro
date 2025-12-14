# Onumpy Integration for Suzu Vector Store

## Overview
Suzu's vector path store now uses **Onumpy** (GPU-accelerated NumPy) instead of standard NumPy. This provides automatic GPU acceleration for large array operations when available.

## Benefits
- **GPU Acceleration**: Automatic GPU usage for large embeddings (>100K elements)
- **AMD RDNA1 Optimized**: Tuned for RX 5700 XT (20 CUs, 8GB VRAM)
- **Drop-in Replacement**: 100% NumPy compatible, no code changes needed
- **Smart Dispatch**: Automatically selects GPU or CPU based on array size

## Setup

### 1. Ensure Onumpy is Available
Onumpy should be located at `/home/ego/github_public/Onumpy`

Verify:
```bash
ls -la /home/ego/github_public/Onumpy/numpy_bridge.py
```

### 2. Install Onumpy Dependencies
```bash
pip install numpy>=2.0 pyopencl>=2023.1
```

### 3. Build Onumpy (if needed)
```bash
cd /home/ego/github_public/Onumpy/numpy_gpu
python setup.py build_ext --inplace
```

### 4. Test Onumpy Import
```python
from numpy_bridge import np
print(f"GPU Available: {np.GPU_AVAILABLE}")
```

## How It Works

The vector store automatically:
1. Tries to import `numpy_bridge` from Onumpy
2. Falls back to standard numpy if Onumpy not available
3. Uses GPU automatically for large operations (>100K elements)

## Performance Impact

### Embedding Generation
- **Small paths (<100K)**: CPU (standard numpy speed)
- **Large batches (>100K)**: GPU acceleration (2-5x speedup)

### Vector Operations
- **Array concatenation**: GPU-accelerated for large arrays
- **Normalization**: GPU-accelerated when available

## Verification

Run the test script:
```bash
python3 suzu/test_vector_store.py
```

Look for:
- `✅ Using Onumpy (GPU-accelerated NumPy) - GPU available` (if GPU works)
- `✅ Using Onumpy (GPU-accelerated NumPy) - CPU fallback` (if GPU not available)
- `⚠️  Onumpy not available, using standard numpy` (if Onumpy not found)

## Troubleshooting

### Onumpy Not Found
**Error**: `ModuleNotFoundError: No module named 'numpy_bridge'`

**Fix**: Ensure Onumpy path is correct:
```python
# Check path
from pathlib import Path
onumpy_path = Path('/home/ego/github_public/Onumpy')
print(f"Onumpy exists: {onumpy_path.exists()}")
```

### GPU Not Available
**Message**: `✅ Using Onumpy (GPU-accelerated NumPy) - CPU fallback`

**Status**: This is fine! Onumpy will still work, just using CPU instead of GPU.

### Import Errors
If you see import errors, ensure:
1. Onumpy is at `/home/ego/github_public/Onumpy`
2. `numpy_bridge.py` exists in that directory
3. Standard numpy is installed: `pip install numpy>=2.0`

## Code Changes

The vector store now uses:
```python
from numpy_bridge import np  # Instead of: import numpy as np
```

This is a drop-in replacement - all numpy operations work the same way, but with automatic GPU acceleration when available.

