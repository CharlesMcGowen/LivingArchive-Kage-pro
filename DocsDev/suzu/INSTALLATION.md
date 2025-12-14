# Suzu Directory Enumerator - Tool Installation Guide

## Current Tool Status

### ✅ Available
- **dirsearch**: Found at `/mnt/webapps-nvme/tools/dirsearch/dirsearch.py`
  - ⚠️ Note: Has pkg_resources deprecation warning but should still function
  - May need: `pip install setuptools<81` to suppress warning

### ❌ Not Installed (Optional)
- **ffuf**: Fast web fuzzer (Go-based)
- **gobuster**: Directory/file brute-forcer (Go-based)

### ✅ Fallback Available
- **Custom Python Enumeration**: Built-in fallback that works without external tools
  - Uses requests library for HTTP enumeration
  - Generates wordlists from Kumo's spidering data
  - Fully functional even without external tools

## Installation Instructions

### Option 1: Install ffuf (Recommended - Fastest)

```bash
# Download pre-built binary
wget https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz
tar -xzf ffuf_linux_amd64.tar.gz
sudo mv ffuf /usr/local/bin/
chmod +x /usr/local/bin/ffuf

# Verify
ffuf -V
```

### Option 2: Install gobuster

```bash
# Using Go (if installed)
go install github.com/OJ/gobuster/v3@latest

# Or download pre-built binary
wget https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz
tar -xzf gobuster_Linux_x86_64.tar.gz
sudo mv gobuster /usr/local/bin/
chmod +x /usr/local/bin/gobuster

# Verify
gobuster version
```

### Option 3: Fix dirsearch (Optional)

```bash
# Install compatible setuptools version
pip install "setuptools<81"

# Or update dirsearch
cd /mnt/webapps-nvme/tools/dirsearch
git pull origin master  # If using git
pip install -r requirements.txt
```

## Wordlist Installation

### Install Seclists (Recommended)

```bash
# Clone seclists repository
cd /mnt/webapps-nvme/wordlists
git clone https://github.com/danielmiessler/SecLists.git

# Or download specific wordlists
mkdir -p /mnt/webapps-nvme/wordlists/Seclists/Discovery/Web-Content
cd /mnt/webapps-nvme/wordlists/Seclists/Discovery/Web-Content
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### Alternative: Use Existing Wordlists

Suzu will automatically detect:
- Metasploit wordlists: `/mnt/webapps-nvme/tools/metasploit-framework/data/wordlists/`
- Dirsearch wordlists: `/mnt/webapps-nvme/tools/dirsearch/*.txt`

## Verification

After installation, verify tools are accessible:

```bash
# Check ffuf
which ffuf && ffuf -V

# Check gobuster
which gobuster && gobuster version

# Check dirsearch
python3 /mnt/webapps-nvme/tools/dirsearch/dirsearch.py --help 2>&1 | head -3

# Check wordlists
ls -la /mnt/webapps-nvme/wordlists/Seclists/Discovery/Web-Content/ 2>/dev/null | head -5
```

## Suzu Will Work Without External Tools

**Important**: Suzu has a built-in custom Python enumeration fallback that works without any external tools. It will:
1. Generate wordlists from Kumo's spidering patterns
2. Use common paths (admin, api, backup, etc.)
3. Perform HTTP enumeration using Python's `requests` library
4. Store results in the same format as external tools

The external tools (ffuf, gobuster, dirsearch) provide:
- **Faster enumeration** (especially ffuf)
- **More advanced features** (recursion, filtering, etc.)
- **Better performance** on large wordlists

But they are **optional** - Suzu will function with just the Python fallback.

## Priority Order

Suzu tries tools in this order:
1. **ffuf** (fastest, most features)
2. **gobuster** (fast, good performance)
3. **dirsearch** (Python-based, more features)
4. **Custom Python** (fallback, always available)

If a tool is not found, Suzu automatically falls back to the next option.

