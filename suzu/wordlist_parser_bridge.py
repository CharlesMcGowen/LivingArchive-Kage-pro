#!/usr/bin/env python3
"""
Go-based wordlist parser bridge for high-performance file parsing.

This module provides a Python interface to the Go-based wordlist parser,
which can parse large wordlist files much faster than pure Python.

Usage:
    from suzu.wordlist_parser_bridge import parse_wordlist_file
    
    result = parse_wordlist_file(
        file_path='/path/to/wordlist.txt',
        batch_size=1000,
        max_paths=0,  # 0 = unlimited
        skip_comments=True,
        normalize_paths=True
    )
    
    paths = result['paths']
    batches = result['batches']
    stats = result['stats']
"""

import json
import subprocess
import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, BinaryIO
from io import BytesIO

logger = logging.getLogger(__name__)

# Try to find the Go binary
_GO_PARSER_BINARY = None
_GO_PARSER_AVAILABLE = False

def _find_go_parser_binary():
    """Find the Go wordlist parser binary"""
    global _GO_PARSER_BINARY, _GO_PARSER_AVAILABLE
    
    if _GO_PARSER_BINARY is not None:
        return _GO_PARSER_AVAILABLE
    
    # Possible locations for the binary
    possible_paths = [
        # In go/cmd/wordlist-parser/ directory (after build)
        Path(__file__).parent.parent / 'go' / 'cmd' / 'wordlist-parser' / 'wordlist-parser',
        # In go/ directory
        Path(__file__).parent.parent / 'go' / 'wordlist-parser',
        # In bin/ directory
        Path(__file__).parent.parent / 'bin' / 'wordlist-parser',
        # System PATH
        'wordlist-parser',
    ]
    
    for path in possible_paths:
        if isinstance(path, str):
            # Check system PATH
            import shutil
            full_path = shutil.which(path)
            if full_path:
                _GO_PARSER_BINARY = full_path
                _GO_PARSER_AVAILABLE = True
                logger.info(f"✅ Found Go wordlist parser at: {full_path}")
                return True
        else:
            # Check file path
            if path.exists() and os.access(path, os.X_OK):
                _GO_PARSER_BINARY = str(path)
                _GO_PARSER_AVAILABLE = True
                logger.info(f"✅ Found Go wordlist parser at: {_GO_PARSER_BINARY}")
                return True
    
    logger.warning("⚠️  Go wordlist parser binary not found - will use Python fallback")
    _GO_PARSER_AVAILABLE = False
    return False

def parse_wordlist_file(
    file_path: str,
    batch_size: int = 1000,
    max_paths: int = 0,
    skip_comments: bool = True,
    normalize_paths: bool = True,
    filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parse a wordlist file using the Go parser (if available) or Python fallback.
    
    Args:
        file_path: Path to the wordlist file
        batch_size: Number of paths per batch (default: 1000)
        max_paths: Maximum paths to parse (0 = unlimited)
        skip_comments: Skip lines starting with # (default: True)
        normalize_paths: Ensure paths start with / (default: True)
        filename: Original filename for CMS detection hints
    
    Returns:
        Dictionary with:
        - paths: List of all parsed paths
        - batches: List of batches (each batch is a list of paths)
        - stats: Dictionary with parsing statistics
        - error: Error message if parsing failed
    """
    # Try Go parser first
    if _find_go_parser_binary() and _GO_PARSER_AVAILABLE:
        try:
            return _parse_with_go_file(file_path, batch_size, max_paths, skip_comments, normalize_paths, filename)
        except Exception as e:
            logger.warning(f"Go parser failed, falling back to Python: {e}")
    
    # Fallback to Python parser
    return _parse_with_python(file_path, batch_size, max_paths, skip_comments, normalize_paths)

def parse_wordlist_stream(
    file_stream: Union[BytesIO, BinaryIO],
    batch_size: int = 1000,
    max_paths: int = 0,
    skip_comments: bool = True,
    normalize_paths: bool = True,
    filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parse a wordlist from a file stream (for Django UploadedFile) using Go parser.
    
    Args:
        file_stream: File-like object (BytesIO, Django UploadedFile, etc.)
        batch_size: Number of paths per batch
        max_paths: Maximum paths to parse (0 = unlimited)
        skip_comments: Skip lines starting with #
        normalize_paths: Ensure paths start with /
        filename: Original filename for CMS detection hints
    
    Returns:
        Dictionary with parsed paths, batches, and statistics
    """
    # Try Go parser first
    if _find_go_parser_binary() and _GO_PARSER_AVAILABLE:
        try:
            return _parse_with_go_stream(file_stream, batch_size, max_paths, skip_comments, normalize_paths, filename)
        except Exception as e:
            logger.warning(f"Go parser failed, falling back to Python: {e}")
    
    # Fallback to Python parser
    return _parse_with_python_stream(file_stream, batch_size, max_paths, skip_comments, normalize_paths)

def _parse_with_go_file(
    file_path: str,
    batch_size: int,
    max_paths: int,
    skip_comments: bool,
    normalize_paths: bool,
    filename: Optional[str]
) -> Dict[str, Any]:
    """Parse file using Go binary (file-based)"""
    config = {
        'batch_size': batch_size,
        'max_paths': max_paths,
        'skip_comments': skip_comments,
        'normalize_paths': normalize_paths,
        'filename': filename or os.path.basename(file_path)
    }
    
    # Read file and pipe to Go parser
    with open(file_path, 'rb') as f:
        return _parse_with_go_stream(f, batch_size, max_paths, skip_comments, normalize_paths, filename)

def _parse_with_go_stream(
    file_stream: BytesIO,
    batch_size: int,
    max_paths: int,
    skip_comments: bool,
    normalize_paths: bool,
    filename: Optional[str]
) -> Dict[str, Any]:
    """Parse stream using Go binary (stdin/stdout)"""
    config = {
        'batch_size': batch_size,
        'max_paths': max_paths,
        'skip_comments': skip_comments,
        'normalize_paths': normalize_paths,
        'filename': filename or 'stream'
    }
    
    # Prepare input: JSON config on first line, then file content
    config_json = json.dumps(config)
    
    try:
        process = subprocess.Popen(
            [_GO_PARSER_BINARY],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1024*1024  # 1MB buffer for large files
        )
        
        # Send config JSON on first line
        process.stdin.write(config_json.encode('utf-8'))
        process.stdin.write(b'\n')
        
        # Send file content
        # Handle both BytesIO and Django UploadedFile (which might not have seek)
        try:
            file_stream.seek(0)  # Reset stream position if possible
        except (AttributeError, OSError):
            pass  # Some file objects don't support seek
        
        while True:
            chunk = file_stream.read(64 * 1024)  # 64KB chunks
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode('utf-8')
            process.stdin.write(chunk)
        
        process.stdin.close()
        
        # Read result JSON
        stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
        
        if process.returncode != 0:
            error_msg = stderr.decode('utf-8', errors='ignore') if stderr else 'Unknown error'
            raise Exception(f"Go parser failed (exit code {process.returncode}): {error_msg}")
        
        result = json.loads(stdout.decode('utf-8'))
        
        if result.get('error'):
            raise Exception(f"Go parser error: {result['error']}")
        
        return result
        
    except subprocess.TimeoutExpired:
        process.kill()
        raise Exception("Go parser timed out after 5 minutes")
    except Exception as e:
        logger.error(f"Error calling Go parser: {e}")
        raise

def _parse_with_python(
    file_path: str,
    batch_size: int,
    max_paths: int,
    skip_comments: bool,
    normalize_paths: bool
) -> Dict[str, Any]:
    """Python fallback parser"""
    stats = {
        'total_lines': 0,
        'valid_paths': 0,
        'skipped_lines': 0,
        'comment_lines': 0,
        'empty_lines': 0,
        'batches_count': 0
    }
    
    paths = []
    batches = []
    current_batch = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            stats['total_lines'] += 1
            line = line.strip()
            
            if not line:
                stats['empty_lines'] += 1
                continue
            
            if skip_comments and line.startswith('#'):
                stats['comment_lines'] += 1
                continue
            
            if normalize_paths and not line.startswith('/'):
                line = '/' + line
            
            paths.append(line)
            current_batch.append(line)
            stats['valid_paths'] += 1
            
            if len(current_batch) >= batch_size:
                batches.append(current_batch)
                stats['batches_count'] += 1
                current_batch = []
                
                if max_paths > 0 and stats['valid_paths'] >= max_paths:
                    break
    
    if current_batch:
        batches.append(current_batch)
        stats['batches_count'] += 1
    
    stats['skipped_lines'] = stats['comment_lines'] + stats['empty_lines']
    
    return {
        'paths': paths,
        'batches': batches,
        'stats': stats
    }

def _parse_with_python_stream(
    file_stream: BytesIO,
    batch_size: int,
    max_paths: int,
    skip_comments: bool,
    normalize_paths: bool
) -> Dict[str, Any]:
    """Python fallback parser for streams"""
    stats = {
        'total_lines': 0,
        'valid_paths': 0,
        'skipped_lines': 0,
        'comment_lines': 0,
        'empty_lines': 0,
        'batches_count': 0
    }
    
    paths = []
    batches = []
    current_batch = []
    
    # Reset stream position if possible
    try:
        file_stream.seek(0)
    except (AttributeError, OSError):
        pass  # Some file objects don't support seek
    
    for line in file_stream:
        stats['total_lines'] += 1
        try:
            line = line.decode('utf-8', errors='ignore').strip()
        except (AttributeError, UnicodeDecodeError):
            continue
        
        if not line:
            stats['empty_lines'] += 1
            continue
        
        if skip_comments and line.startswith('#'):
            stats['comment_lines'] += 1
            continue
        
        if normalize_paths and not line.startswith('/'):
            line = '/' + line
        
        paths.append(line)
        current_batch.append(line)
        stats['valid_paths'] += 1
        
        if len(current_batch) >= batch_size:
            batches.append(current_batch)
            stats['batches_count'] += 1
            current_batch = []
            
            if max_paths > 0 and stats['valid_paths'] >= max_paths:
                break
    
    if current_batch:
        batches.append(current_batch)
        stats['batches_count'] += 1
    
    stats['skipped_lines'] = stats['comment_lines'] + stats['empty_lines']
    
    return {
        'paths': paths,
        'batches': batches,
        'stats': stats
    }
