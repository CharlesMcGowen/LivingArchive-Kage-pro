# Surge Nuclei Memory Bridge - Testing Guide

## Overview

This directory contains tests and verification tools for the Surge Nuclei Memory Bridge.

## Test Files

### 1. `test_build.sh` - Docker Build Test
Tests compilation in a clean Docker environment.

**Usage:**
```bash
./test_build.sh
```

**What it does:**
- Uses `golang:1.21-alpine` Docker image
- Downloads dependencies
- Compiles the shared library
- Verifies the output

**Expected output:**
- ✅ Go version confirmation
- ✅ Dependency download
- ✅ Successful build
- ✅ Library file verification

### 2. `test_memory_cleanup.py` - Python Memory Cleanup Test
Verifies that Python ctypes properly handles C string memory returned from Go.

**Usage:**
```bash
python3 test_memory_cleanup.py
```

**What it does:**
- Loads the bridge library
- Performs 100 initialize/cleanup cycles
- Performs 1000 GetScanState calls
- Monitors memory usage
- Reports memory leaks

**Expected result:**
- Memory increase < 10MB after all tests
- No significant memory leaks

**Note:** Requires compiled `libnuclei_bridge.so` to be present.

### 3. `bridge_test.go` - Go Unit Tests
Comprehensive unit tests for bridge functionality.

**Usage:**
```bash
go test -v ./bridge_test.go ./bridge.go
```

**Test coverage:**
- Helper function tests (createCString, jsonError, jsonSuccess)
- URL validation tests
- Bridge initialization tests
- Event channel handling
- Thread safety tests
- Performance benchmarks

**Run specific tests:**
```bash
go test -v -run TestValidateURL
go test -v -run TestThreadSafety
go test -bench=.
```

## Running All Tests

```bash
# 1. Build test
./test_build.sh

# 2. Memory cleanup test (requires built library)
python3 test_memory_cleanup.py

# 3. Unit tests (requires Go environment)
go test -v ./bridge_test.go ./bridge.go
```

## Test Results Interpretation

### Build Test
- ✅ **PASS**: Library compiles successfully
- ❌ **FAIL**: Check Go version, dependencies, or CGO configuration

### Memory Cleanup Test
- ✅ **PASS**: Memory increase < 10MB
- ⚠️ **WARNING**: Memory increase 10-50MB (may indicate minor leaks)
- ❌ **FAIL**: Memory increase > 50MB (significant leak detected)

### Unit Tests
- ✅ **PASS**: All tests pass
- ❌ **FAIL**: Review failing test output for details

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Build Test
  run: ./test_build.sh

- name: Memory Test
  run: python3 test_memory_cleanup.py

- name: Unit Tests
  run: go test -v ./bridge_test.go ./bridge.go
```

## Troubleshooting

### Build fails
- Check Go version (requires 1.21+)
- Verify CGO is enabled
- Check Nuclei dependency version

### Memory test fails
- Ensure library is compiled
- Check Python version (3.8+)
- Verify ctypes is working

### Unit tests fail
- Check Go test environment
- Verify all dependencies are available
- Review test output for specific errors

