# Agent Logs

This directory contains log files for all daemon agents.

## Directory Structure

- `kage/` - Kage port scanner daemon logs
- `kaze/` - Kaze high-speed port scanner daemon logs
- `kumo/` - Kumo HTTP spider daemon logs
- `ryu/` - Ryu cybersecurity assessment daemon logs
- `suzu/` - Suzu directory enumeration daemon logs

## Log Files

Log files are automatically created with daily rotation:
- Format: `{agent}_daemon_{YYYYMMDD}.log`
- Example: `kage_daemon_20251215.log`

## Git Configuration

Log files (`.log`, `.txt`) are excluded from git via `.gitignore`, but the directory structure is preserved with `.gitkeep` files. This allows the log directories to exist in the repository without committing actual log data.
