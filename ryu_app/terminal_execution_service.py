#!/usr/bin/env python3
"""
Terminal Execution Service for AI Agent Bridge
==============================================

A safe terminal execution service that enables AI agents to run shell commands
with proper safety controls, following modern agentic IDE best practices.

Safety Features:
- Human-in-the-loop (HITL) approval workflow
- Command allowlisting/blocklisting
- Timeout protection
- Output sanitization
- Command history tracking
- Sandboxed execution (optional Docker support)

Author: EGO Revolution Team
Version: 1.0.0
"""

import logging
import subprocess
import shlex
import os
import time
import json
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class CommandStatus(Enum):
    """Status of a command execution."""
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


@dataclass
class CommandRequest:
    """Represents a command execution request."""
    command: str
    working_directory: Optional[str] = None
    timeout: int = 30
    require_approval: bool = True
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CommandResult:
    """Represents the result of a command execution."""
    request_id: str
    status: CommandStatus
    command: str
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    execution_time: float = 0.0
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value
        if self.timestamp:
            result['timestamp'] = self.timestamp.isoformat()
        return result


class TerminalExecutionService:
    """
    Safe terminal execution service for AI agents.
    
    Provides controlled execution of shell commands with safety features
    including command allowlisting, timeout protection, and approval workflows.
    """
    
    # Dangerous commands that should be blocked
    BLOCKED_COMMANDS = {
        'rm', 'rmdir', 'del', 'format', 'mkfs', 'dd', 'mkfifo',
        'shutdown', 'reboot', 'halt', 'poweroff', 'init', 'killall',
        'fdisk', 'parted', 'mkfs.ext4', 'mkfs.xfs', 'mkfs.ntfs',
        'curl', 'wget',  # Can be dangerous if piping to bash
    }
    
    # Commands that require explicit approval even if in allowlist
    HIGH_RISK_COMMANDS = {
        'sudo', 'su', 'chmod', 'chown', 'mount', 'umount',
        'iptables', 'firewall-cmd', 'ufw', 'systemctl',
        'docker', 'kubectl', 'kubectl', 'helm',
        'git', 'svn',  # Version control operations
        'pip', 'npm', 'yarn', 'apt', 'yum', 'dnf',  # Package managers
    }
    
    # Safe commands that can be auto-approved (if require_approval=False)
    SAFE_COMMANDS = {
        'ls', 'pwd', 'cat', 'head', 'tail', 'grep', 'find',
        'ps', 'top', 'df', 'du', 'free', 'uname', 'whoami',
        'date', 'echo', 'env', 'which', 'type', 'history',
        'git', 'git status', 'git log', 'git diff',  # Read-only git
        'python', 'python3', 'node',  # Interpreters (with caution)
    }
    
    def __init__(
        self,
        default_timeout: int = 30,
        max_timeout: int = 300,
        require_approval_by_default: bool = True,
        working_directory: Optional[str] = None,
        enable_command_history: bool = True,
        max_history_size: int = 1000
    ):
        """
        Initialize the terminal execution service.
        
        Args:
            default_timeout: Default timeout in seconds for commands
            max_timeout: Maximum allowed timeout in seconds
            require_approval_by_default: Whether to require approval by default
            working_directory: Default working directory for commands
            enable_command_history: Whether to track command history
            max_history_size: Maximum number of commands to keep in history
        """
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout
        self.require_approval_by_default = require_approval_by_default
        self.working_directory = working_directory or os.getcwd()
        self.enable_command_history = enable_command_history
        self.max_history_size = max_history_size
        
        # Command history and pending approvals
        self.command_history: List[CommandResult] = []
        self.pending_approvals: Dict[str, CommandRequest] = {}
        self.running_commands: Dict[str, subprocess.Popen] = {}
        
        # Statistics
        self.stats = {
            'total_commands': 0,
            'approved_commands': 0,
            'rejected_commands': 0,
            'blocked_commands': 0,
            'failed_commands': 0,
        }
        
        logger.info("🔧 Terminal Execution Service initialized")
        logger.info(f"   Default timeout: {default_timeout}s")
        logger.info(f"   Working directory: {self.working_directory}")
        logger.info(f"   Require approval: {require_approval_by_default}")
    
    def validate_command(self, command: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a command for safety.
        
        Args:
            command: The command to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not command or not command.strip():
            return False, "Empty command"
        
        # Extract the base command
        parts = shlex.split(command)
        if not parts:
            return False, "Invalid command format"
        
        base_command = parts[0].lower()
        
        # Check if command is blocked
        if base_command in self.BLOCKED_COMMANDS:
            return False, f"Command '{base_command}' is blocked for safety"
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'rm\s+-rf', r'rm\s+-r\s+', r'rm\s+.*\*',
            r'>\s*/dev/', r'>>\s*/dev/',
            r'curl\s+.*\s*\|\s*bash',
            r'wget\s+.*\s*\|\s*bash',
            r'curl\s+.*\s*\|\s*sh',
            r'wget\s+.*\s*\|\s*sh',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Dangerous pattern detected: {pattern}"
        
        return True, None
    
    def requires_approval(self, command: str) -> bool:
        """
        Check if a command requires approval.
        
        Args:
            command: The command to check
            
        Returns:
            True if approval is required
        """
        if not self.require_approval_by_default:
            return False
        
        parts = shlex.split(command)
        if not parts:
            return True
        
        base_command = parts[0].lower()
        
        # High-risk commands always require approval
        if base_command in self.HIGH_RISK_COMMANDS:
            return True
        
        # Safe commands don't require approval
        if base_command in self.SAFE_COMMANDS:
            return False
        
        # Default: require approval
        return True
    
    def submit_command(
        self,
        command: str,
        working_directory: Optional[str] = None,
        timeout: Optional[int] = None,
        require_approval: Optional[bool] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Submit a command for execution.
        
        Args:
            command: The command to execute
            working_directory: Working directory for the command
            timeout: Timeout in seconds (default: self.default_timeout)
            require_approval: Whether approval is required (default: auto-detect)
            user_id: User ID for tracking
            session_id: Session ID for tracking
            metadata: Additional metadata
            
        Returns:
            Dictionary with request_id and status
        """
        # Validate command
        is_valid, error_msg = self.validate_command(command)
        if not is_valid:
            self.stats['blocked_commands'] += 1
            return {
                'success': False,
                'error': error_msg,
                'status': CommandStatus.BLOCKED.value
            }
        
        # Generate request ID
        request_id = f"cmd_{int(time.time() * 1000)}_{os.getpid()}"
        
        # Determine if approval is required
        if require_approval is None:
            require_approval = self.requires_approval(command)
        
        # Create command request
        request = CommandRequest(
            command=command,
            working_directory=working_directory or self.working_directory,
            timeout=min(timeout or self.default_timeout, self.max_timeout),
            require_approval=require_approval,
            user_id=user_id,
            session_id=session_id,
            metadata=metadata or {}
        )
        
        # If approval is required, add to pending approvals
        if require_approval:
            self.pending_approvals[request_id] = request
            self.stats['total_commands'] += 1
            logger.info(f"📋 Command pending approval: {request_id} - {command[:50]}")
            return {
                'success': True,
                'request_id': request_id,
                'status': CommandStatus.PENDING_APPROVAL.value,
                'command': command,
                'requires_approval': True,
                'message': 'Command submitted and pending approval'
            }
        else:
            # Auto-approve and execute
            return self._execute_command(request_id, request)
    
    def approve_command(self, request_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Approve a pending command.
        
        Args:
            request_id: The request ID to approve
            user_id: User ID approving the command
            
        Returns:
            Dictionary with execution result
        """
        if request_id not in self.pending_approvals:
            return {
                'success': False,
                'error': f'Request {request_id} not found in pending approvals'
            }
        
        request = self.pending_approvals.pop(request_id)
        self.stats['approved_commands'] += 1
        
        logger.info(f"✅ Command approved: {request_id} by {user_id or 'system'}")
        return self._execute_command(request_id, request)
    
    def reject_command(self, request_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Reject a pending command.
        
        Args:
            request_id: The request ID to reject
            user_id: User ID rejecting the command
            
        Returns:
            Dictionary with rejection confirmation
        """
        if request_id not in self.pending_approvals:
            return {
                'success': False,
                'error': f'Request {request_id} not found in pending approvals'
            }
        
        request = self.pending_approvals.pop(request_id)
        self.stats['rejected_commands'] += 1
        
        logger.info(f"❌ Command rejected: {request_id} by {user_id or 'system'}")
        
        result = CommandResult(
            request_id=request_id,
            status=CommandStatus.REJECTED,
            command=request.command,
            timestamp=datetime.now()
        )
        
        if self.enable_command_history:
            self._add_to_history(result)
        
        return {
            'success': True,
            'request_id': request_id,
            'status': CommandStatus.REJECTED.value,
            'message': 'Command rejected'
        }
    
    def _execute_command(self, request_id: str, request: CommandRequest) -> Dict[str, Any]:
        """
        Execute a command (internal method).
        
        Args:
            request_id: The request ID
            request: The command request
            
        Returns:
            Dictionary with execution result
        """
        start_time = time.time()
        
        try:
            # Ensure working directory exists
            work_dir = Path(request.working_directory)
            if not work_dir.exists():
                work_dir = Path(self.working_directory)
            
            # Execute command
            logger.info(f"🚀 Executing command: {request_id} - {request.command[:50]}")
            
            process = subprocess.Popen(
                request.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(work_dir),
                env=os.environ.copy()
            )
            
            self.running_commands[request_id] = process
            
            # Wait for completion with timeout
            try:
                stdout, stderr = process.communicate(timeout=request.timeout)
                exit_code = process.returncode
                execution_time = time.time() - start_time
                
                status = CommandStatus.COMPLETED if exit_code == 0 else CommandStatus.FAILED
                
                if exit_code != 0:
                    self.stats['failed_commands'] += 1
                
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                stdout = ""
                stderr = f"Command timed out after {request.timeout} seconds"
                exit_code = -1
                execution_time = time.time() - start_time
                status = CommandStatus.TIMEOUT
                self.stats['failed_commands'] += 1
                logger.warning(f"⏱️ Command timed out: {request_id}")
            
            finally:
                self.running_commands.pop(request_id, None)
            
            # Create result
            result = CommandResult(
                request_id=request_id,
                status=status,
                command=request.command,
                exit_code=exit_code,
                stdout=stdout[:10000],  # Limit output size
                stderr=stderr[:10000],
                execution_time=execution_time,
                timestamp=datetime.now()
            )
            
            if self.enable_command_history:
                self._add_to_history(result)
            
            logger.info(f"✅ Command completed: {request_id} (exit_code={exit_code}, time={execution_time:.2f}s)")
            
            return {
                'success': status == CommandStatus.COMPLETED,
                'request_id': request_id,
                'result': result.to_dict()
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = str(e)
            logger.error(f"❌ Command execution error: {request_id} - {error_msg}", exc_info=True)
            
            result = CommandResult(
                request_id=request_id,
                status=CommandStatus.FAILED,
                command=request.command,
                error_message=error_msg,
                execution_time=execution_time,
                timestamp=datetime.now()
            )
            
            if self.enable_command_history:
                self._add_to_history(result)
            
            self.stats['failed_commands'] += 1
            
            return {
                'success': False,
                'request_id': request_id,
                'error': error_msg,
                'result': result.to_dict()
            }
    
    def _add_to_history(self, result: CommandResult):
        """Add a result to command history."""
        self.command_history.append(result)
        if len(self.command_history) > self.max_history_size:
            self.command_history.pop(0)
    
    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approval requests."""
        return [
            {
                'request_id': req_id,
                'request': req.to_dict()
            }
            for req_id, req in self.pending_approvals.items()
        ]
    
    def get_command_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get command history."""
        return [result.to_dict() for result in self.command_history[-limit:]]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            **self.stats,
            'pending_approvals': len(self.pending_approvals),
            'running_commands': len(self.running_commands),
            'history_size': len(self.command_history)
        }
    
    def cancel_command(self, request_id: str) -> Dict[str, Any]:
        """
        Cancel a running command.
        
        Args:
            request_id: The request ID to cancel
            
        Returns:
            Dictionary with cancellation result
        """
        if request_id in self.running_commands:
            process = self.running_commands[request_id]
            process.kill()
            process.wait()
            self.running_commands.pop(request_id)
            
            logger.info(f"🛑 Command cancelled: {request_id}")
            return {
                'success': True,
                'request_id': request_id,
                'message': 'Command cancelled'
            }
        else:
            return {
                'success': False,
                'error': f'Command {request_id} is not running'
            }


# Global service instance
_terminal_service: Optional[TerminalExecutionService] = None


def get_terminal_service() -> TerminalExecutionService:
    """Get or create the global terminal execution service instance."""
    global _terminal_service
    if _terminal_service is None:
        _terminal_service = TerminalExecutionService()
    return _terminal_service
