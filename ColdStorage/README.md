# ColdStorage - Development Scripts and Tools

This directory contains development scripts, test files, demo scripts, and legacy code that is not part of the production system but is preserved for reference or development purposes.

## Purpose

These files are kept separate from the main codebase to:
- Maintain a clean production code structure
- Organize development tools separately from production code
- Preserve reference implementations and test utilities
- Keep test/demo scripts accessible but out of main code paths
- Support development and debugging workflows

## Organization

### Root Level Scripts
- **check_dashboard_data.py** - Script to check dashboard data
- **clone_script.py** - Development cloning utility
- **do_clone.py** - Alternative cloning script
- **test_database_connection.py** - Database connection testing script
- **verify_dashboard_fixes.sh** - Dashboard fix verification script
- **setup_database_connection.sh** - Database connection setup script
- **llm_enhancer.py** - LLM enhancement utility (legacy)
- **fallback_storage.py** - Fallback storage implementation
- **daemon_api.py** - Legacy API reference

### Subdirectory Scripts

#### kage/
Kage-related test and demo scripts:
- **test_bgp_standalone.py** - BGP lookup testing
- **test_bgp_and_firewall.py** - BGP and firewall rule testing
- **demo_complete_system.py** - Complete system demonstration
- **demo_ipv6_complete.py** - IPv6 demonstration
- **firewall_rules_cloudflare.sh** - Firewall rule generation script
- Files with `_ai.py` suffix are versions moved from `artificial_intelligence/` directory

#### suzu/
Suzu test and diagnostic scripts:
- **test_vector_store.py** - Vector store testing
- **test_onumpy_import.py** - Onumpy import testing
- **diagnose_onumpy.py** - Onumpy diagnostic utility

#### surge_nuclei_bridge/
Surge/Nuclei bridge scripts:
- **build.sh** - Build scripts
- **test_build.sh** - Build testing
- **test_template_loading.py** - Template loading tests
- **test_memory_cleanup.py** - Memory cleanup tests
- **test_pg.py** - PostgreSQL integration tests

## Note

These scripts are preserved for reference but are not actively used in production. They may be outdated or superseded by core functionality. Use with caution and verify compatibility before running.

When adding new development scripts, please place them in the appropriate subdirectory within ColdStorage to maintain organization.

