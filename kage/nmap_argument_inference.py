#!/usr/bin/env python3
"""
Nmap Argument Inference and Heuristics Engine
==============================================

Extracts Nmap arguments from knowledge base, performs inference,
and generates heuristics for intelligent argument selection.
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ArgumentCategory(Enum):
    """Categories of Nmap arguments."""
    SCAN_TYPE = "scan_type"  # -sS, -sT, -sU, etc.
    HOST_DISCOVERY = "host_discovery"  # -PS, -PA, -PU, etc.
    PORT_SPECIFICATION = "port_specification"  # -p, --top-ports
    TIMING = "timing"  # Advanced: --scan-delay, --min-rate, --max-retries, etc. (legacy: -T0 to -T5)
    SERVICE_DETECTION = "service_detection"  # -sV, -A
    OS_DETECTION = "os_detection"  # -O
    FIREWALL_EVASION = "firewall_evasion"  # -f, --mtu, -D, etc.
    OUTPUT = "output"  # -oN, -oX, -oG
    SCRIPTING = "scripting"  # --script, --script-args
    MISC = "misc"  # -v, -d, -n, etc.


@dataclass
class NmapArgument:
    """Represents a single Nmap argument with metadata."""
    flag: str  # e.g., "-sS", "--script"
    category: ArgumentCategory
    description: str
    examples: List[str] = field(default_factory=list)
    use_cases: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)  # Required flags
    conflicts: List[str] = field(default_factory=list)  # Conflicting flags
    heuristics: Dict[str, Any] = field(default_factory=dict)  # When to use


@dataclass
class ScanScenario:
    """Represents a scanning scenario for inference."""
    target_type: str  # "single_host", "network", "stealth", etc.
    waf_detected: bool = False
    waf_type: Optional[str] = None
    firewall_detected: bool = False
    ids_detected: bool = False
    stealth_required: bool = False
    speed_priority: str = "normal"  # "fast", "normal", "thorough"
    ports_to_scan: Optional[List[int]] = None
    service_detection_needed: bool = False
    os_detection_needed: bool = False
    previous_scan_failed: bool = False
    previous_technique: Optional[str] = None


class NmapArgumentInference:
    """
    Extracts Nmap arguments from knowledge base and provides inference.
    """
    
    # Common Nmap argument patterns
    ARGUMENT_PATTERNS = {
        # Scan types
        r'-sS\b': ('-sS', ArgumentCategory.SCAN_TYPE, 'TCP SYN scan'),
        r'-sT\b': ('-sT', ArgumentCategory.SCAN_TYPE, 'TCP connect scan'),
        r'-sU\b': ('-sU', ArgumentCategory.SCAN_TYPE, 'UDP scan'),
        r'-sA\b': ('-sA', ArgumentCategory.SCAN_TYPE, 'TCP ACK scan'),
        r'-sF\b': ('-sF', ArgumentCategory.SCAN_TYPE, 'TCP FIN scan'),
        r'-sN\b': ('-sN', ArgumentCategory.SCAN_TYPE, 'TCP NULL scan'),
        r'-sX\b': ('-sX', ArgumentCategory.SCAN_TYPE, 'TCP Xmas scan'),
        r'-sW\b': ('-sW', ArgumentCategory.SCAN_TYPE, 'TCP Window scan'),
        r'-sM\b': ('-sM', ArgumentCategory.SCAN_TYPE, 'TCP Maimon scan'),
        r'-sO\b': ('-sO', ArgumentCategory.SCAN_TYPE, 'IP protocol scan'),
        r'-sI\b': ('-sI', ArgumentCategory.SCAN_TYPE, 'TCP Idle scan'),
        r'-b\b': ('-b', ArgumentCategory.SCAN_TYPE, 'FTP bounce scan'),
        
        # Host discovery
        r'-PS\b': ('-PS', ArgumentCategory.HOST_DISCOVERY, 'TCP SYN ping'),
        r'-PA\b': ('-PA', ArgumentCategory.HOST_DISCOVERY, 'TCP ACK ping'),
        r'-PU\b': ('-PU', ArgumentCategory.HOST_DISCOVERY, 'UDP ping'),
        r'-PE\b': ('-PE', ArgumentCategory.HOST_DISCOVERY, 'ICMP echo ping'),
        r'-PP\b': ('-PP', ArgumentCategory.HOST_DISCOVERY, 'ICMP timestamp ping'),
        r'-PM\b': ('-PM', ArgumentCategory.HOST_DISCOVERY, 'ICMP netmask ping'),
        r'-PR\b': ('-PR', ArgumentCategory.HOST_DISCOVERY, 'ARP ping'),
        r'-PO\b': ('-PO', ArgumentCategory.HOST_DISCOVERY, 'IP protocol ping'),
        r'-Pn\b': ('-Pn', ArgumentCategory.HOST_DISCOVERY, 'Skip host discovery'),
        r'-sL\b': ('-sL', ArgumentCategory.HOST_DISCOVERY, 'List scan'),
        
        # Port specification
        r'-p\s+[^\s]+': ('-p', ArgumentCategory.PORT_SPECIFICATION, 'Port specification'),
        r'--top-ports\s+\d+': ('--top-ports', ArgumentCategory.PORT_SPECIFICATION, 'Top ports'),
        r'-F\b': ('-F', ArgumentCategory.PORT_SPECIFICATION, 'Fast scan (top 100 ports)'),
        r'-r\b': ('-r', ArgumentCategory.PORT_SPECIFICATION, 'Don\'t randomize ports'),
        
        # Timing (legacy -T switches, kept for detection but not recommended)
        r'-T0\b': ('-T0', ArgumentCategory.TIMING, 'Paranoid timing (legacy - use advanced arguments)'),
        r'-T1\b': ('-T1', ArgumentCategory.TIMING, 'Sneaky timing (legacy - use advanced arguments)'),
        r'-T2\b': ('-T2', ArgumentCategory.TIMING, 'Polite timing (legacy - use advanced arguments)'),
        r'-T3\b': ('-T3', ArgumentCategory.TIMING, 'Normal timing (legacy - use advanced arguments)'),
        r'-T4\b': ('-T4', ArgumentCategory.TIMING, 'Aggressive timing (legacy - use advanced arguments)'),
        r'-T5\b': ('-T5', ArgumentCategory.TIMING, 'Insane timing (legacy - use advanced arguments)'),
        
        # Advanced timing controls (replace -T switches for granular control)
        r'--scan-delay\s+[\d.]+(?:ms|s|m)?': ('--scan-delay', ArgumentCategory.TIMING, 'Delay between probes'),
        r'--min-rate\s+\d+': ('--min-rate', ArgumentCategory.TIMING, 'Minimum packet rate'),
        r'--max-rate\s+\d+': ('--max-rate', ArgumentCategory.TIMING, 'Maximum packet rate'),
        r'--max-retries\s+\d+': ('--max-retries', ArgumentCategory.TIMING, 'Maximum retry attempts'),
        r'--host-timeout\s+[\d.]+(?:ms|s|m)?': ('--host-timeout', ArgumentCategory.TIMING, 'Host timeout'),
        r'--max-rtt-timeout\s+[\d.]+(?:ms|s|m)?': ('--max-rtt-timeout', ArgumentCategory.TIMING, 'Maximum RTT timeout'),
        r'--initial-rtt-timeout\s+[\d.]+(?:ms|s|m)?': ('--initial-rtt-timeout', ArgumentCategory.TIMING, 'Initial RTT timeout'),
        r'--min-rtt-timeout\s+[\d.]+(?:ms|s|m)?': ('--min-rtt-timeout', ArgumentCategory.TIMING, 'Minimum RTT timeout'),
        r'--max-scan-delay\s+[\d.]+(?:ms|s|m)?': ('--max-scan-delay', ArgumentCategory.TIMING, 'Maximum scan delay'),
        r'--min-hostgroup\s+\d+': ('--min-hostgroup', ArgumentCategory.TIMING, 'Minimum host group size'),
        r'--max-hostgroup\s+\d+': ('--max-hostgroup', ArgumentCategory.TIMING, 'Maximum host group size'),
        r'--min-parallelism\s+\d+': ('--min-parallelism', ArgumentCategory.TIMING, 'Minimum parallel probes'),
        r'--max-parallelism\s+\d+': ('--max-parallelism', ArgumentCategory.TIMING, 'Maximum parallel probes'),
        
        # Service detection
        r'-sV\b': ('-sV', ArgumentCategory.SERVICE_DETECTION, 'Version detection'),
        r'-sC\b': ('-sC', ArgumentCategory.SERVICE_DETECTION, 'Default scripts'),
        r'-A\b': ('-A', ArgumentCategory.SERVICE_DETECTION, 'Aggressive scan'),
        
        # OS detection
        r'-O\b': ('-O', ArgumentCategory.OS_DETECTION, 'OS detection'),
        r'--osscan-guess\b': ('--osscan-guess', ArgumentCategory.OS_DETECTION, 'Guess OS'),
        r'--osscan-limit\b': ('--osscan-limit', ArgumentCategory.OS_DETECTION, 'Limit OS detection'),
        
        # Firewall evasion
        r'-f\b': ('-f', ArgumentCategory.FIREWALL_EVASION, 'Fragment packets'),
        r'--mtu\s+\d+': ('--mtu', ArgumentCategory.FIREWALL_EVASION, 'Set MTU'),
        r'-D\s+[^\s]+': ('-D', ArgumentCategory.FIREWALL_EVASION, 'Decoy scan'),
        r'-S\s+[^\s]+': ('-S', ArgumentCategory.FIREWALL_EVASION, 'Spoof source IP'),
        r'-e\s+[^\s]+': ('-e', ArgumentCategory.FIREWALL_EVASION, 'Interface'),
        r'--source-port\s+[^\s]+': ('--source-port', ArgumentCategory.FIREWALL_EVASION, 'Source port'),
        r'--data-length\s+\d+': ('--data-length', ArgumentCategory.FIREWALL_EVASION, 'Data length'),
        r'--data-string\s+[^\s]+': ('--data-string', ArgumentCategory.FIREWALL_EVASION, 'Data string'),
        r'--scanflags\s+[^\s]+': ('--scanflags', ArgumentCategory.FIREWALL_EVASION, 'Custom scan flags'),
        r'--badsum\b': ('--badsum', ArgumentCategory.FIREWALL_EVASION, 'Bad checksum'),
        
        # Scripting
        r'--script\s+[^\s]+': ('--script', ArgumentCategory.SCRIPTING, 'NSE script'),
        r'--script-args\s+[^\s]+': ('--script-args', ArgumentCategory.SCRIPTING, 'Script arguments'),
        r'--script-updatedb\b': ('--script-updatedb', ArgumentCategory.SCRIPTING, 'Update script DB'),
        
        # Output
        r'-oN\s+[^\s]+': ('-oN', ArgumentCategory.OUTPUT, 'Normal output'),
        r'-oX\s+[^\s]+': ('-oX', ArgumentCategory.OUTPUT, 'XML output'),
        r'-oG\s+[^\s]+': ('-oG', ArgumentCategory.OUTPUT, 'Grepable output'),
        r'-oS\s+[^\s]+': ('-oS', ArgumentCategory.OUTPUT, 'Script kiddie output'),
        r'-oA\s+[^\s]+': ('-oA', ArgumentCategory.OUTPUT, 'All formats'),
        
        # Misc
        r'-v\b': ('-v', ArgumentCategory.MISC, 'Verbose'),
        r'-vv\b': ('-vv', ArgumentCategory.MISC, 'Very verbose'),
        r'-d\b': ('-d', ArgumentCategory.MISC, 'Debug'),
        r'-n\b': ('-n', ArgumentCategory.MISC, 'No DNS resolution'),
        r'-R\b': ('-R', ArgumentCategory.MISC, 'Always resolve DNS'),
        r'--resolve-all\b': ('--resolve-all', ArgumentCategory.MISC, 'Resolve all IPs'),
        r'-6\b': ('-6', ArgumentCategory.MISC, 'IPv6 scan'),
    }
    
    def __init__(self, knowledge_base: Optional[Dict[str, Any]] = None):
        """Initialize with knowledge base."""
        self.knowledge_base = knowledge_base or {}
        self.arguments: Dict[str, NmapArgument] = {}
        self.heuristics_rules: List[Dict[str, Any]] = []
        
        # Always build heuristics (they're rule-based, not dependent on knowledge base)
        self._build_heuristics()
        
        # Extract arguments from knowledge base if available
        if self.knowledge_base:
            self._extract_arguments()
    
    def _extract_arguments(self):
        """Extract all Nmap arguments from knowledge base."""
        logger.info("Extracting Nmap arguments from knowledge base...")
        
        # Process all categories
        categories = self.knowledge_base.get('categories', {})
        
        for category_name, entries in categories.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                text = entry.get('text', '')
                examples = entry.get('examples', [])
                title = entry.get('title', '')
                
                # Find all arguments in text and examples
                found_args = set()
                
                # Check text
                for pattern, (flag, arg_category, description) in self.ARGUMENT_PATTERNS.items():
                    if re.search(pattern, text, re.IGNORECASE):
                        found_args.add((flag, arg_category, description))
                
                # Check examples
                for example in examples:
                    for pattern, (flag, arg_category, description) in self.ARGUMENT_PATTERNS.items():
                        if re.search(pattern, example, re.IGNORECASE):
                            found_args.add((flag, arg_category, description))
                
                # Create or update argument objects
                for flag, arg_category, description in found_args:
                    if flag not in self.arguments:
                        self.arguments[flag] = NmapArgument(
                            flag=flag,
                            category=arg_category,
                            description=description,
                            examples=[],
                            use_cases=[],
                            heuristics={}
                        )
                    
                    # Add examples
                    if examples:
                        self.arguments[flag].examples.extend(examples[:3])  # Limit to 3
                    
                    # Extract use cases from text
                    use_case_keywords = {
                        'stealth': 'stealth_required',
                        'firewall': 'firewall_detected',
                        'waf': 'waf_detected',
                        'ids': 'ids_detected',
                        'fast': 'speed_priority=fast',
                        'slow': 'speed_priority=slow',
                        'thorough': 'speed_priority=thorough',
                    }
                    
                    text_lower = text.lower()
                    for keyword, use_case in use_case_keywords.items():
                        if keyword in text_lower:
                            if use_case not in self.arguments[flag].use_cases:
                                self.arguments[flag].use_cases.append(use_case)
        
        logger.info(f"Extracted {len(self.arguments)} unique Nmap arguments")
    
    def _build_heuristics(self):
        """Build heuristics rules for argument selection."""
        logger.info("Building heuristics rules...")
        
        # Heuristic: WAF detection -> use non-HTTP probes
        self.heuristics_rules.append({
            'condition': {'waf_detected': True},
            'recommendations': [
                {'flag': '-PS', 'ports': [22, 443, 8080], 'reason': 'TCP SYN ping to non-HTTP ports'},
                {'flag': '-PA', 'ports': [80, 443], 'reason': 'TCP ACK ping appears as established connection'},
                {'flag': '-PU', 'ports': [53], 'reason': 'UDP DNS probe often bypasses WAFs'},
                {'flag': '-sS', 'reason': 'TCP SYN scan is stealthier than connect scan'},
            ],
            'avoid': ['-sT', '-A', '-T0', '-T1', '-T2', '-T3', '-T4', '-T5'],  # Avoid connect scan, aggressive, and legacy timing
        })
        
        # Heuristic: Stealth required -> use advanced timing controls and scan type
        self.heuristics_rules.append({
            'condition': {'stealth_required': True},
            'recommendations': [
                {'flag': '--scan-delay', 'value': '1000ms', 'reason': 'Delay between probes reduces detection'},
                {'flag': '--max-rtt-timeout', 'value': '2000ms', 'reason': 'Conservative timeout for stealth'},
                {'flag': '--max-retries', 'value': '2', 'reason': 'Fewer retries reduce noise'},
                {'flag': '-sS', 'reason': 'SYN scan is stealthier'},
                {'flag': '-f', 'reason': 'Fragment packets to evade IDS'},
                {'flag': '--scanflags', 'value': 'URG', 'reason': 'Custom flags confuse IDS'},
            ],
            'avoid': ['-T0', '-T1', '-T2', '-T3', '-T4', '-T5', '-A', '-sT', '--min-rate'],
        })
        
        # Heuristic: Fast scan -> use advanced timing controls and port selection
        self.heuristics_rules.append({
            'condition': {'speed_priority': 'fast'},
            'recommendations': [
                {'flag': '--min-rate', 'value': '1000', 'reason': 'High packet rate for speed'},
                {'flag': '--max-retries', 'value': '2', 'reason': 'Fewer retries for speed'},
                {'flag': '--max-rtt-timeout', 'value': '1000ms', 'reason': 'Lower timeout for speed'},
                {'flag': '--initial-rtt-timeout', 'value': '300ms', 'reason': 'Fast initial timeout'},
                {'flag': '-F', 'reason': 'Fast scan (top 100 ports)'},
                {'flag': '--top-ports', 'value': 100, 'reason': 'Scan only top ports'},
            ],
            'avoid': ['-T0', '-T1', '-T2', '-T3', '-T4', '-T5', '--scan-delay'],
        })
        
        # Heuristic: Firewall detected -> use evasion techniques
        self.heuristics_rules.append({
            'condition': {'firewall_detected': True},
            'recommendations': [
                {'flag': '-sF', 'reason': 'FIN scan may bypass firewalls'},
                {'flag': '-sN', 'reason': 'NULL scan may bypass firewalls'},
                {'flag': '-sX', 'reason': 'Xmas scan may bypass firewalls'},
                {'flag': '-f', 'reason': 'Fragment packets'},
                {'flag': '--mtu', 'value': 8, 'reason': 'Small MTU fragments packets'},
            ],
        })
        
        # Heuristic: Previous scan failed -> try alternative technique
        self.heuristics_rules.append({
            'condition': {'previous_scan_failed': True},
            'recommendations': [
                {'flag': '-sA', 'reason': 'ACK scan if SYN failed'},
                {'flag': '-sU', 'reason': 'UDP scan if TCP failed'},
                {'flag': '-Pn', 'reason': 'Skip host discovery if it failed'},
            ],
        })
        
        # Heuristic: Service detection needed
        self.heuristics_rules.append({
            'condition': {'service_detection_needed': True},
            'recommendations': [
                {'flag': '-sV', 'reason': 'Version detection'},
                {'flag': '-sC', 'reason': 'Default scripts'},
            ],
        })
        
        # Heuristic: OS detection needed
        self.heuristics_rules.append({
            'condition': {'os_detection_needed': True},
            'recommendations': [
                {'flag': '-O', 'reason': 'OS detection'},
                {'flag': '--osscan-guess', 'reason': 'Guess OS if detection fails'},
            ],
        })
        
        logger.info(f"Built {len(self.heuristics_rules)} heuristics rules")
    
    def infer_arguments(self, scenario: ScanScenario) -> Dict[str, Any]:
        """
        Infer best Nmap arguments for a given scenario.
        
        Returns:
            Dictionary with recommended arguments, reasoning, and confidence.
        """
        recommendations = []
        avoid_flags = set()
        confidence_scores = {}
        
        # Apply heuristics rules
        for rule in self.heuristics_rules:
            condition = rule['condition']
            matches = True
            
            # Check if condition matches scenario
            for key, value in condition.items():
                scenario_value = getattr(scenario, key, None)
                if scenario_value != value:
                    matches = False
                    break
            
            if matches:
                # Add recommendations
                for rec in rule.get('recommendations', []):
                    flag = rec['flag']
                    reason = rec.get('reason', '')
                    value = rec.get('value')
                    
                    recommendations.append({
                        'flag': flag,
                        'value': value,
                        'reason': reason,
                        'category': self._get_category_for_flag(flag),
                    })
                    
                    confidence_scores[flag] = confidence_scores.get(flag, 0) + 1
                
                # Add flags to avoid
                for flag in rule.get('avoid', []):
                    avoid_flags.add(flag)
        
        # Default recommendations if no rules matched
        if not recommendations:
            # Default scan type
            if scenario.stealth_required:
                recommendations.append({
                    'flag': '-sS',
                    'reason': 'Default stealth scan',
                    'category': ArgumentCategory.SCAN_TYPE,
                })
            else:
                recommendations.append({
                    'flag': '-sS',
                    'reason': 'Default SYN scan',
                    'category': ArgumentCategory.SCAN_TYPE,
                })
            
            # Default timing using advanced arguments
            if scenario.speed_priority == 'fast':
                recommendations.append({
                    'flag': '--min-rate',
                    'value': '1000',
                    'reason': 'Fast scan with high packet rate',
                    'category': ArgumentCategory.TIMING,
                })
                recommendations.append({
                    'flag': '--max-retries',
                    'value': '2',
                    'reason': 'Fewer retries for speed',
                    'category': ArgumentCategory.TIMING,
                })
                recommendations.append({
                    'flag': '--max-rtt-timeout',
                    'value': '1000ms',
                    'reason': 'Lower timeout for speed',
                    'category': ArgumentCategory.TIMING,
                })
            elif scenario.speed_priority == 'thorough':
                recommendations.append({
                    'flag': '--scan-delay',
                    'value': '1000ms',
                    'reason': 'Thorough scan with delays',
                    'category': ArgumentCategory.TIMING,
                })
                recommendations.append({
                    'flag': '--max-rtt-timeout',
                    'value': '2000ms',
                    'reason': 'Conservative timeout for thoroughness',
                    'category': ArgumentCategory.TIMING,
                })
                recommendations.append({
                    'flag': '--max-retries',
                    'value': '3',
                    'reason': 'More retries for thoroughness',
                    'category': ArgumentCategory.TIMING,
                })
            else:
                recommendations.append({
                    'flag': '--max-retries',
                    'value': '3',
                    'reason': 'Normal retry count',
                    'category': ArgumentCategory.TIMING,
                })
                recommendations.append({
                    'flag': '--max-rtt-timeout',
                    'value': '1500ms',
                    'reason': 'Normal RTT timeout',
                    'category': ArgumentCategory.TIMING,
                })
        
        # Build command string
        command_parts = ['nmap']
        for rec in recommendations:
            flag = rec['flag']
            value = rec.get('value')
            ports = rec.get('ports')  # Handle port lists for host discovery flags
            
            if ports and isinstance(ports, list):
                # Format ports as comma-separated list
                ports_str = ','.join(map(str, ports))
                command_parts.append(f"{flag} {ports_str}")
            elif value:
                command_parts.append(f"{flag} {value}")
            else:
                command_parts.append(flag)
        
        return {
            'recommendations': recommendations,
            'avoid': list(avoid_flags),
            'command': ' '.join(command_parts),
            'confidence_scores': confidence_scores,
            'reasoning': self._generate_reasoning(scenario, recommendations),
        }
    
    def _get_category_for_flag(self, flag: str) -> ArgumentCategory:
        """Get category for a flag."""
        for pattern, (f, category, _) in self.ARGUMENT_PATTERNS.items():
            if f == flag:
                return category
        return ArgumentCategory.MISC
    
    def _generate_reasoning(self, scenario: ScanScenario, recommendations: List[Dict]) -> str:
        """Generate human-readable reasoning for recommendations."""
        reasons = []
        
        if scenario.waf_detected:
            reasons.append(f"WAF detected ({scenario.waf_type or 'unknown'}) - using evasion techniques")
        
        if scenario.stealth_required:
            reasons.append("Stealth required - using stealth scan techniques")
        
        if scenario.firewall_detected:
            reasons.append("Firewall detected - using firewall evasion")
        
        if scenario.speed_priority == 'fast':
            reasons.append("Fast scan priority - using aggressive timing")
        
        for rec in recommendations[:3]:  # Top 3
            reasons.append(f"{rec['flag']}: {rec['reason']}")
        
        return "; ".join(reasons)
    
    def get_argument_info(self, flag: str) -> Optional[NmapArgument]:
        """Get detailed information about a specific argument."""
        return self.arguments.get(flag)
    
    def search_arguments(self, query: str) -> List[NmapArgument]:
        """Search for arguments matching a query."""
        results = []
        query_lower = query.lower()
        
        for arg in self.arguments.values():
            if (query_lower in arg.flag.lower() or
                query_lower in arg.description.lower() or
                any(query_lower in uc.lower() for uc in arg.use_cases)):
                results.append(arg)
        
        return results
    
    def get_heuristics_for_scenario(self, scenario_type: str) -> List[Dict[str, Any]]:
        """Get heuristics for a specific scenario type."""
        matching_rules = []
        
        for rule in self.heuristics_rules:
            condition = rule.get('condition', {})
            if scenario_type in str(condition):
                matching_rules.append(rule)
        
        return matching_rules

