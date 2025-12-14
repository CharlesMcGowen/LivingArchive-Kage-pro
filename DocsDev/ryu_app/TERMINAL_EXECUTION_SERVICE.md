# Terminal Execution Service - AI Agent Bridge

A safe terminal execution service that enables AI agents to run shell commands with proper safety controls, following modern agentic IDE best practices.

## Features

### Safety Features
- **Human-in-the-loop (HITL)**: Commands can require approval before execution
- **Command Allowlisting/Blocklisting**: Automatic blocking of dangerous commands
- **Timeout Protection**: All commands have configurable timeouts
- **Output Sanitization**: Limits output size to prevent memory issues
- **Command History**: Tracks all executed commands for auditing
- **Pattern Detection**: Blocks dangerous command patterns (e.g., `rm -rf`, `curl | bash`)

### Command Classification
- **Blocked Commands**: Always blocked (e.g., `rm`, `shutdown`, `dd`)
- **High-Risk Commands**: Always require approval (e.g., `sudo`, `chmod`, `docker`)
- **Safe Commands**: Can be auto-approved (e.g., `ls`, `cat`, `grep`)

## API Endpoints

All endpoints are prefixed with `/reconnaissance/api/terminal/`

### 1. Execute Command

**POST** `/api/terminal/execute/`

Submit a command for execution. If approval is required, the command will be queued for approval.

**Request Body:**
```json
{
    "command": "ls -la",
    "working_directory": "/path/to/dir",  // Optional
    "timeout": 30,  // Optional, default: 30 seconds
    "require_approval": true,  // Optional, default: auto-detect
    "user_id": "user123",  // Optional
    "session_id": "session456",  // Optional
    "metadata": {}  // Optional
}
```

**Response (Pending Approval):**
```json
{
    "success": true,
    "request_id": "cmd_1234567890_12345",
    "status": "pending_approval",
    "command": "ls -la",
    "requires_approval": true,
    "message": "Command submitted and pending approval"
}
```

**Response (Auto-Executed):**
```json
{
    "success": true,
    "request_id": "cmd_1234567890_12345",
    "result": {
        "request_id": "cmd_1234567890_12345",
        "status": "completed",
        "command": "ls -la",
        "exit_code": 0,
        "stdout": "total 24\ndrwxr-xr-x ...",
        "stderr": "",
        "execution_time": 0.05,
        "timestamp": "2024-01-15T10:30:00"
    }
}
```

### 2. Approve Command

**POST** `/api/terminal/approve/<request_id>/`

Approve a pending command and execute it.

**Request Body (Optional):**
```json
{
    "user_id": "user123"
}
```

**Response:**
```json
{
    "success": true,
    "request_id": "cmd_1234567890_12345",
    "result": {
        "request_id": "cmd_1234567890_12345",
        "status": "completed",
        "command": "ls -la",
        "exit_code": 0,
        "stdout": "...",
        "stderr": "",
        "execution_time": 0.05,
        "timestamp": "2024-01-15T10:30:00"
    }
}
```

### 3. Reject Command

**POST** `/api/terminal/reject/<request_id>/`

Reject a pending command without executing it.

**Request Body (Optional):**
```json
{
    "user_id": "user123"
}
```

**Response:**
```json
{
    "success": true,
    "request_id": "cmd_1234567890_12345",
    "status": "rejected",
    "message": "Command rejected"
}
```

### 4. Get Pending Approvals

**GET** `/api/terminal/pending/`

Get all commands waiting for approval.

**Response:**
```json
{
    "success": true,
    "pending": [
        {
            "request_id": "cmd_1234567890_12345",
            "request": {
                "command": "sudo apt update",
                "working_directory": "/home/user",
                "timeout": 30,
                "require_approval": true,
                "user_id": "user123",
                "session_id": "session456",
                "metadata": {}
            }
        }
    ],
    "count": 1
}
```

### 5. Get Command History

**GET** `/api/terminal/history/?limit=50`

Get command execution history.

**Query Parameters:**
- `limit`: Number of commands to return (default: 50, max: 500)

**Response:**
```json
{
    "success": true,
    "history": [
        {
            "request_id": "cmd_1234567890_12345",
            "status": "completed",
            "command": "ls -la",
            "exit_code": 0,
            "stdout": "...",
            "stderr": "",
            "execution_time": 0.05,
            "timestamp": "2024-01-15T10:30:00"
        }
    ],
    "count": 1
}
```

### 6. Get Statistics

**GET** `/api/terminal/stats/`

Get service statistics.

**Response:**
```json
{
    "success": true,
    "stats": {
        "total_commands": 100,
        "approved_commands": 80,
        "rejected_commands": 10,
        "blocked_commands": 5,
        "failed_commands": 5,
        "pending_approvals": 2,
        "running_commands": 1,
        "history_size": 50
    }
}
```

### 7. Cancel Running Command

**POST** `/api/terminal/cancel/<request_id>/`

Cancel a currently running command.

**Response:**
```json
{
    "success": true,
    "request_id": "cmd_1234567890_12345",
    "message": "Command cancelled"
}
```

## Usage Examples

### Python Client Example

```python
import requests
import json

BASE_URL = "http://localhost:8000/reconnaissance/api/terminal"

# 1. Submit a command
response = requests.post(
    f"{BASE_URL}/execute/",
    json={
        "command": "ls -la /tmp",
        "timeout": 10,
        "require_approval": False  # Auto-approve safe commands
    }
)
result = response.json()
print(f"Request ID: {result['request_id']}")
print(f"Status: {result['status']}")

# If pending approval, approve it
if result['status'] == 'pending_approval':
    request_id = result['request_id']
    approve_response = requests.post(
        f"{BASE_URL}/approve/{request_id}/",
        json={"user_id": "admin"}
    )
    print(approve_response.json())

# 2. Get pending approvals
pending = requests.get(f"{BASE_URL}/pending/").json()
print(f"Pending commands: {pending['count']}")

# 3. Get command history
history = requests.get(f"{BASE_URL}/history/?limit=10").json()
for cmd in history['history']:
    print(f"{cmd['command']} - {cmd['status']}")

# 4. Get statistics
stats = requests.get(f"{BASE_URL}/stats/").json()
print(f"Total commands: {stats['stats']['total_commands']}")
```

### cURL Examples

```bash
# Execute a command
curl -X POST http://localhost:8000/reconnaissance/api/terminal/execute/ \
  -H "Content-Type: application/json" \
  -d '{
    "command": "ls -la",
    "timeout": 10,
    "require_approval": false
  }'

# Approve a pending command
curl -X POST http://localhost:8000/reconnaissance/api/terminal/approve/cmd_1234567890_12345/ \
  -H "Content-Type: application/json" \
  -d '{"user_id": "admin"}'

# Get pending approvals
curl http://localhost:8000/reconnaissance/api/terminal/pending/

# Get command history
curl http://localhost:8000/reconnaissance/api/terminal/history/?limit=20

# Get statistics
curl http://localhost:8000/reconnaissance/api/terminal/stats/
```

### JavaScript/TypeScript Example

```typescript
const BASE_URL = 'http://localhost:8000/reconnaissance/api/terminal';

// Execute a command
async function executeCommand(command: string) {
  const response = await fetch(`${BASE_URL}/execute/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      command,
      timeout: 30,
      require_approval: false
    })
  });
  
  const result = await response.json();
  
  if (result.status === 'pending_approval') {
    // Approve the command
    await fetch(`${BASE_URL}/approve/${result.request_id}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: 'admin' })
    });
  }
  
  return result;
}

// Get pending approvals
async function getPendingApprovals() {
  const response = await fetch(`${BASE_URL}/pending/`);
  return await response.json();
}
```

## Integration with AI Agents

### Example: AI Agent Workflow

```python
from ryu_app.terminal_execution_service import get_terminal_service

service = get_terminal_service()

# AI agent wants to check if a file exists
result = service.submit_command(
    command="test -f /path/to/file && echo 'exists' || echo 'not found'",
    require_approval=False  # Safe command, auto-approve
)

if result['status'] == 'completed':
    output = result['result']['stdout']
    if 'exists' in output:
        print("File exists!")
    else:
        print("File not found")

# AI agent wants to install a package (requires approval)
result = service.submit_command(
    command="pip install requests",
    require_approval=True  # High-risk, requires approval
)

if result['status'] == 'pending_approval':
    request_id = result['request_id']
    # Wait for human approval via API
    # Or auto-approve if in trusted environment
    approved = service.approve_command(request_id, user_id="ai_agent")
```

## Configuration

The service can be configured when initializing:

```python
from ryu_app.terminal_execution_service import TerminalExecutionService

service = TerminalExecutionService(
    default_timeout=60,  # Default timeout in seconds
    max_timeout=300,  # Maximum allowed timeout
    require_approval_by_default=True,  # Require approval by default
    working_directory="/home/user/project",  # Default working directory
    enable_command_history=True,  # Track command history
    max_history_size=1000  # Maximum history size
)
```

## Safety Considerations

1. **Always Review Pending Commands**: Check pending approvals before approving
2. **Use Timeouts**: Set appropriate timeouts for long-running commands
3. **Monitor Statistics**: Regularly check service statistics for anomalies
4. **Review History**: Periodically review command history for security issues
5. **Limit Permissions**: Run the Django application with minimal required permissions
6. **Network Security**: Use HTTPS and authentication in production
7. **Docker Sandboxing**: Consider running commands in Docker containers for isolation

## Blocked Commands

The following commands are automatically blocked:
- `rm`, `rmdir`, `del` - File deletion
- `format`, `mkfs`, `dd` - Disk operations
- `shutdown`, `reboot`, `halt` - System control
- `killall` - Process termination
- `curl | bash`, `wget | bash` - Unsafe script execution

## High-Risk Commands (Require Approval)

These commands always require approval:
- `sudo`, `su` - Privilege escalation
- `chmod`, `chown` - Permission changes
- `mount`, `umount` - Filesystem operations
- `iptables`, `firewall-cmd` - Firewall changes
- `docker`, `kubectl` - Container orchestration
- `git` (write operations) - Version control
- Package managers (`pip`, `npm`, `apt`, etc.)

## Extending the Service

### Adding Custom Command Validators

```python
from ryu_app.terminal_execution_service import TerminalExecutionService

class CustomTerminalService(TerminalExecutionService):
    def validate_command(self, command: str) -> Tuple[bool, Optional[str]]:
        # Call parent validation
        is_valid, error = super().validate_command(command)
        if not is_valid:
            return is_valid, error
        
        # Add custom validation
        if 'custom_blocked_pattern' in command:
            return False, "Custom pattern blocked"
        
        return True, None
```

### Customizing Command Classification

```python
# Add to SAFE_COMMANDS for auto-approval
TerminalExecutionService.SAFE_COMMANDS.add('custom_safe_command')

# Add to HIGH_RISK_COMMANDS for always requiring approval
TerminalExecutionService.HIGH_RISK_COMMANDS.add('custom_risky_command')

# Add to BLOCKED_COMMANDS for complete blocking
TerminalExecutionService.BLOCKED_COMMANDS.add('custom_blocked_command')
```

## Troubleshooting

### Command Times Out
- Increase the timeout value
- Check if the command is actually hanging
- Consider breaking the command into smaller parts

### Command Blocked Unexpectedly
- Check if the command matches blocked patterns
- Review the command classification
- Consider adding the command to SAFE_COMMANDS if appropriate

### Approval Not Working
- Verify the request_id is correct
- Check if the command is still pending
- Review service logs for errors

## License

Part of the LivingArchive-Kage-pro project.
