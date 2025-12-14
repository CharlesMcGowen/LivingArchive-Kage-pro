# Onumpy Import Troubleshooting

## Why Onumpy Might Not Be Found

The vector store tries to import Onumpy from `/home/ego/github_public/Onumpy/numpy_bridge.py`. If it's not found, it falls back to standard numpy.

## Common Issues

### 1. Path Not Found
**Error**: `Onumpy directory not found at /home/ego/github_public/Onumpy`

**Check**:
```bash
ls -la /home/ego/github_public/Onumpy/numpy_bridge.py
```

**Fix**: Ensure Onumpy is at the correct path.

### 2. Import Error from numpy_bridge
**Error**: `Onumpy not available (ImportError: ...)`

**Possible causes**:
- `numpy_bridge.py` has import errors (e.g., missing dependencies)
- `numpy_gpu` module not built or not available
- Standard numpy not installed

**Check**:
```bash
cd /home/ego/github_public/Onumpy
python3 -c "from numpy_bridge import np; print('OK')"
```

### 3. Module Doesn't Have GPU_AVAILABLE
**Error**: `Imported module is not Onumpy (missing GPU_AVAILABLE attribute)`

**Cause**: Import succeeded but got wrong module (maybe standard numpy was imported instead)

**Check**: The import might be finding a different `numpy_bridge` module somewhere else in the path.

## Diagnostic Steps

### Step 1: Run Diagnostic Script
```bash
cd /home/ego/github_public/LivingArchive-Kage-pro
python3 suzu/diagnose_onumpy.py
```

This will show:
- If Onumpy directory exists
- If numpy_bridge.py exists
- If import works
- What error occurs (if any)

### Step 2: Test Direct Import
```bash
cd /home/ego/github_public/Onumpy
python3 -c "from numpy_bridge import np; print(f'GPU: {np.GPU_AVAILABLE}')"
```

### Step 3: Check Logs
When the vector store loads, check the logs for:
- `✅ Using Onumpy (GPU-accelerated NumPy) - GPU available` (success)
- `✅ Using Onumpy (GPU-accelerated NumPy) - CPU fallback` (success, no GPU)
- `⚠️  Onumpy not available (...), using standard numpy` (fallback)

### Step 4: Enable Debug Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
# Then import vector_path_store
```

This will show the full traceback if import fails.

## Current Import Mechanism

The vector store now uses a robust import mechanism:

1. **Path Check**: Verifies Onumpy directory exists
2. **File Check**: Verifies `numpy_bridge.py` exists
3. **Path Addition**: Adds Onumpy to `sys.path`
4. **Importlib Import**: Uses `importlib.util` for explicit loading
5. **Fallback**: Falls back to standard import if importlib fails
6. **Verification**: Checks for `GPU_AVAILABLE` attribute to confirm it's Onumpy
7. **Final Fallback**: Uses standard numpy if all else fails

## Expected Behavior

### Success Case
```
✅ Using Onumpy (GPU-accelerated NumPy) - GPU available
```
or
```
✅ Using Onumpy (GPU-accelerated NumPy) - CPU fallback
```

### Fallback Case
```
⚠️  Onumpy not available (ImportError: ...), using standard numpy
```

**Note**: The system will still work with standard numpy, just without GPU acceleration.

## Manual Testing

Test the import directly:
```python
import sys
from pathlib import Path

# Add Onumpy to path
onumpy_path = Path('/home/ego/github_public/Onumpy')
sys.path.insert(0, str(onumpy_path))

# Try importing
from numpy_bridge import np
print(f"Type: {type(np)}")
print(f"GPU Available: {np.GPU_AVAILABLE}")
```

## If Onumpy Still Not Found

1. **Check file permissions**: Ensure `numpy_bridge.py` is readable
2. **Check Python version**: Onumpy requires Python 3.8+
3. **Check dependencies**: Ensure standard numpy is installed
4. **Check numpy_gpu**: Onumpy might fail if `numpy_gpu` has issues, but should still import

The vector store will automatically fall back to standard numpy, so functionality is not affected - you just won't get GPU acceleration.

