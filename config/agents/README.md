# Agent Configuration Files

This directory contains configuration files for each agent daemon (Kage, Kaze, Kumo, Ryu, and Suzu). These configuration files allow agents to connect to the central server from separate networks or servers, enabling distributed deployments.

## Overview

Each agent can read its configuration from a JSON file, which includes:
- **Server URL**: The base URL of the Django server the agent connects to
- **Intervals**: How often the agent performs its operations
- **Limits**: Maximum operations per cycle
- **Retry Settings**: Configuration for connection retries
- **Timeouts**: API request timeouts

## Configuration File Locations

The config loader searches for configuration files in the following order (first found is used):

1. `config/agents/{agent_name}.json` (project directory - **recommended**)
2. `/etc/agents/{agent_name}.json` (system-wide)
3. `~/.config/agents/{agent_name}.json` (user-specific)
4. `./config/{agent_name}.json` (current directory)

## Environment Variable Override

Environment variables take precedence over config file values, allowing for runtime overrides:

- `DJANGO_API_BASE`: Server URL (e.g., `http://192.168.1.100:9000`)
- `{AGENT}_SCAN_INTERVAL`: Scan interval in seconds
- `{AGENT}_SPIDER_INTERVAL`: Spider interval in seconds
- `{AGENT}_ENUM_INTERVAL`: Enumeration interval in seconds
- `{AGENT}_ASSESSMENT_INTERVAL`: Assessment interval in seconds
- `{AGENT}_MAX_SCANS`: Maximum scans per cycle
- `{AGENT}_MAX_SPIDERS`: Maximum spiders per cycle
- `{AGENT}_MAX_ENUMS`: Maximum enumerations per cycle
- `{AGENT}_MAX_ASSESSMENTS`: Maximum assessments per cycle

Where `{AGENT}` is one of: `KAGE`, `KAZE`, `KUMO`, `RYU`, `SUZU`

## Example Config Files

### kage.json (Port Scanner)
```json
{
  "server_url": "http://192.168.1.100:9000",
  "pid_file": "/tmp/kage_daemon.pid",
  "scan_interval": 30,
  "max_scans_per_cycle": 5,
  "max_retries": 5,
  "retry_base_wait": 2,
  "retry_max_wait": 60,
  "api_timeout": 10,
  "submit_timeout": 30
}
```

### kaze.json (High-Speed Scanner)
```json
{
  "server_url": "http://192.168.1.100:9000",
  "pid_file": "/tmp/kaze_daemon.pid",
  "scan_interval": 15,
  "max_scans_per_cycle": 10,
  "max_retries": 5,
  "retry_base_wait": 2,
  "retry_max_wait": 60,
  "api_timeout": 10,
  "submit_timeout": 30
}
```

### kumo.json (HTTP Spider)
```json
{
  "server_url": "http://192.168.1.100:9000",
  "pid_file": "/tmp/kumo_daemon.pid",
  "spider_interval": 45,
  "max_spiders_per_cycle": 3,
  "max_retries": 5,
  "retry_base_wait": 2,
  "retry_max_wait": 60,
  "api_timeout": 10,
  "submit_timeout": 30
}
```

### ryu.json (Threat Assessment)
```json
{
  "server_url": "http://192.168.1.100:9000",
  "pid_file": "/tmp/ryu_daemon.pid",
  "scan_interval": 30,
  "assessment_interval": 60,
  "max_scans_per_cycle": 5,
  "max_assessments_per_cycle": 2,
  "max_retries": 5,
  "retry_base_wait": 2,
  "retry_max_wait": 60,
  "api_timeout": 10,
  "submit_timeout": 30
}
```

### suzu.json (Directory Enumeration)
```json
{
  "server_url": "http://192.168.1.100:9000",
  "pid_file": "/tmp/suzu_daemon.pid",
  "enum_interval": 60,
  "max_enums_per_cycle": 2,
  "max_retries": 5,
  "retry_base_wait": 2,
  "retry_max_wait": 60,
  "api_timeout": 10,
  "submit_timeout": 60
}
```

## Setting Up Distributed Agents

### Step 1: Identify Your Server

Determine the IP address or hostname of your Django server:
- Local network: Use the server's local IP (e.g., `192.168.1.100`)
- Remote server: Use the public IP or domain name
- Docker: Use the container network IP or exposed port

### Step 2: Create Config Files

For each agent on a separate server/network:

1. Copy the example config file for the agent:
   ```bash
   cp config/agents/kage.json config/agents/kage.json.local
   ```

2. Edit the config file and update the `server_url`:
   ```json
   {
     "server_url": "http://your-server-ip-or-domain:9000",
     ...
   }
   ```

3. Ensure network connectivity:
   - Firewall rules allow outbound connections from agent to server
   - Server firewall allows inbound connections on port 9000 (or your configured port)
   - Network routing allows communication between agent and server

### Step 3: Deploy Config Files

Place the config file in one of the search locations:

**Option A: Project Directory (Recommended for development)**
```bash
# On agent server
mkdir -p /path/to/LivingArchive-Kage-pro/config/agents
cp kage.json /path/to/LivingArchive-Kage-pro/config/agents/
```

**Option B: System-Wide (Recommended for production)**
```bash
# On agent server (requires root)
sudo mkdir -p /etc/agents
sudo cp kage.json /etc/agents/
sudo chmod 644 /etc/agents/kage.json
```

**Option C: User Config (For user-specific deployments)**
```bash
# On agent server
mkdir -p ~/.config/agents
cp kage.json ~/.config/agents/
```

### Step 4: Start the Agent

Start the agent daemon on the remote server:

```bash
cd /path/to/LivingArchive-Kage-pro
python3 daemons/kage_daemon.py
```

The agent will:
1. Load configuration from the config file
2. Connect to the server at the configured URL
3. Start processing tasks from the server

## Configuration Parameters

### Required Parameters

- **server_url**: Base URL of the Django API server (e.g., `http://192.168.1.100:9000`)

### Optional Parameters

#### Timing Intervals (seconds)
- **scan_interval**: How often to check for scan tasks (default: 30)
- **spider_interval**: How often to check for spider tasks (default: 45)
- **enum_interval**: How often to check for enumeration tasks (default: 60)
- **assessment_interval**: How often to check for assessment tasks (default: 60)

#### Operation Limits
- **max_scans_per_cycle**: Maximum scans per cycle (default: 5)
- **max_spiders_per_cycle**: Maximum spiders per cycle (default: 3)
- **max_enums_per_cycle**: Maximum enumerations per cycle (default: 2)
- **max_assessments_per_cycle**: Maximum assessments per cycle (default: 2)

#### Retry Configuration
- **max_retries**: Maximum connection retry attempts (default: 5)
- **retry_base_wait**: Base wait time for exponential backoff in seconds (default: 2)
- **retry_max_wait**: Maximum wait time between retries in seconds (default: 60)

#### Timeouts (seconds)
- **api_timeout**: Timeout for API GET requests (default: 10)
- **submit_timeout**: Timeout for API POST requests (default: 30)

#### Process Management
- **pid_file**: Path to PID file for daemon process management (default: `/tmp/{agent_name}_daemon.pid`)

## Troubleshooting

### Agent Cannot Connect to Server

1. **Check server URL**: Verify the `server_url` in the config file is correct
2. **Test connectivity**: Use `curl` or `wget` to test connection:
   ```bash
   curl http://your-server-ip:9000/reconnaissance/api/health/
   ```
3. **Check firewall**: Ensure outbound connections are allowed from agent to server
4. **Check server logs**: Look for connection attempts in Django server logs

### Configuration Not Loading

1. **Check file location**: Verify config file is in one of the search locations
2. **Check file permissions**: Ensure the file is readable by the daemon process
3. **Check JSON syntax**: Validate JSON syntax using `python3 -m json.tool kage.json`
4. **Check logs**: Look for configuration loading messages in daemon logs

### Using Environment Variables Instead

If config files aren't working, you can use environment variables:

```bash
export DJANGO_API_BASE=http://192.168.1.100:9000
export KAGE_SCAN_INTERVAL=30
export KAGE_MAX_SCANS=5
python3 daemons/kage_daemon.py
```

## Security Considerations

1. **Network Security**: Use VPN or encrypted tunnels for agent-server communication
2. **File Permissions**: Restrict config file permissions (e.g., `chmod 600`) if containing sensitive data
3. **HTTPS**: Consider using HTTPS for production deployments (requires Django SSL configuration)
4. **Authentication**: Implement API key authentication for agent connections if needed

## Example: Multi-Server Deployment

```
┌─────────────────┐         ┌─────────────────┐
│  Server (Django)│         │  Agent Server 1 │
│  192.168.1.100  │◄────────┤  (kage, kaze)   │
│                 │         │  192.168.1.101  │
└─────────────────┘         └─────────────────┘
         ▲
         │
         │
         │
┌─────────────────┐
│  Agent Server 2 │
│  (kumo, suzu)   │
│  192.168.1.102  │
└─────────────────┘
```

Each agent server has its own config file pointing to `http://192.168.1.100:9000`

## See Also

- `daemons/config_loader.py`: Configuration loader implementation
- `agent.example.json`: Template configuration file
- Individual agent daemon files in `daemons/` directory
