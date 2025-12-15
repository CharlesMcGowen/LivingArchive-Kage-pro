# Logs Directory

This directory contains log files for all daemon services.

## Directory Structure

- `kage/` - Kage port scanner daemon logs
- `kaze/` - Kaze high-speed scanner daemon logs
- `kumo/` - Kumo HTTP spider daemon logs
- `ryu/` - Ryu cybersecurity daemon logs
- `suzu/` - Suzu directory enumerator daemon logs

## Log Files

Log files are named by date: `{agent}_daemon_{YYYYMMDD}.log`

Example: `kage_daemon_20251215.log`

## Git

Log files (`.log`) are ignored by git, but the directory structure is preserved via `.gitkeep` files.
