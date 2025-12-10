#!/usr/bin/env python3
"""
LLM-Powered Reconnaissance Enhancement Service
===============================================

Provides intelligent LLM-based enhancements for Kage, Kumo, and Ryu.
Uses EgoLlama Gateway (http://localhost:8082) for semantic understanding,
strategy generation, and threat assessment.

Features:
- Intelligent scan strategy recommendations
- Semantic analysis of scan results
- Content understanding for HTTP responses
- Threat correlation and assessment
- Natural language explanations

Author: EGO Revolution Team
Version: 1.0.0 - LLM Integration
"""

import logging
import asyncio
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import json

logger = logging.getLogger(__name__)


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, '__dict__'):
        return obj.__dict__
    raise TypeError(f"Type {type(obj)} not serializable")


def safe_json_dumps(obj, **kwargs):
    """Safely serialize objects to JSON, handling datetime and other non-serializable types"""
    return json.dumps(obj, default=json_serial, **kwargs)

# Try to import unified code generation service
try:
    from artificial_intelligence.services.unified_code_generation_service import (
        UnifiedCodeGenerationService,
        CodeGenerationRequest,
        CodeGenerationResult,
        BackendType
    )
    UNIFIED_SERVICE_AVAILABLE = True
except ImportError:
    UNIFIED_SERVICE_AVAILABLE = False
    logger.warning("Unified code generation service not available - LLM enhancements disabled")

# Try to import requests for sync fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class ScanStrategyRecommendation:
    """LLM-generated scan strategy recommendation"""
    strategy: Dict[str, Any]
    reasoning: str
    confidence: float
    nmap_arguments: List[Dict[str, Any]]
    alternative_strategies: List[Dict[str, Any]]


@dataclass
class ScanResultAnalysis:
    """LLM analysis of scan results"""
    summary: str
    security_concerns: List[str]
    interesting_findings: List[str]
    recommendations: List[str]
    risk_level: str  # "low", "medium", "high", "critical"


@dataclass
class ContentAnalysis:
    """LLM analysis of HTTP content"""
    content_type: str
    security_indicators: List[str]
    sensitive_data_detected: List[str]
    application_structure: Dict[str, Any]
    recommendations: List[str]


@dataclass
class ThreatAssessment:
    """LLM-generated threat assessment"""
    overall_risk: str
    threat_summary: str
    vulnerabilities: List[Dict[str, Any]]
    attack_vectors: List[str]
    remediation_priorities: List[str]
    narrative: str  # Human-readable assessment


class ReconnaissanceLLMEnhancer:
    """
    LLM-powered enhancements for reconnaissance services.
    
    Provides intelligent analysis, strategy generation, and threat assessment
    using EgoLlama Gateway and knowledge base integration.
    """
    
    def __init__(self, egollama_url: str = "http://localhost:8082", enabled: bool = True):
        """
        Initialize LLM enhancer for reconnaissance.
        
        Args:
            egollama_url: EgoLlama Gateway URL
            enabled: Whether to enable LLM enhancements
        """
        self.enabled = enabled and UNIFIED_SERVICE_AVAILABLE
        self.egollama_url = egollama_url
        
        # Load Nmap book knowledge for context
        self.book_knowledge = None
        try:
            import sys
            from pathlib import Path
            # Add nmap_knowledge directory to path
            nmap_kb_path = Path('/mnt/webapps-nvme/nmap_knowledge')
            if str(nmap_kb_path) not in sys.path:
                sys.path.insert(0, str(nmap_kb_path.parent))
            
            from nmap_knowledge.nmap_book_knowledge_loader import load_nmap_book_knowledge
            self.book_knowledge = load_nmap_book_knowledge()
            if self.book_knowledge:
                logger.info(f"📚 Loaded Nmap book knowledge ({len(self.book_knowledge.sections)} sections)")
        except Exception as e:
            logger.debug(f"Could not load Nmap book knowledge: {e}")
        
        if self.enabled:
            try:
                self.llm_service = UnifiedCodeGenerationService(
                    egollama_url=egollama_url,
                    use_knowledge_context=True
                )
                logger.info(f"✅ LLM enhancer initialized (EgoLlama: {egollama_url})")
            except Exception as e:
                logger.warning(f"⚠️  LLM service initialization failed: {e}")
                self.enabled = False
                self.llm_service = None
        else:
            self.llm_service = None
            logger.debug("LLM enhancer disabled or unavailable")
    
    async def analyze_scan_strategy(
        self,
        target: str,
        target_info: Dict[str, Any],
        previous_scans: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[ScanStrategyRecommendation]:
        """
        Use LLM to recommend optimal scan strategy based on target analysis.
        
        Args:
            target: Target hostname or IP
            target_info: Dictionary with target characteristics
            previous_scans: Optional list of previous scan results
            
        Returns:
            ScanStrategyRecommendation or None if LLM unavailable
        """
        if not self.enabled or not self.llm_service:
            return None
        
        try:
            # Build context from target info
            context_parts = [
                f"Target: {target}",
                f"Domain pattern: {target_info.get('domain_pattern', 'unknown')}",
                f"Known ports: {target_info.get('known_ports', [])}",
                f"WAF detected: {target_info.get('waf_detected', False)}",
                f"WAF type: {target_info.get('waf_type', 'none')}",
            ]
            
            if previous_scans:
                context_parts.append(f"\nPrevious scan results:")
                for scan in previous_scans[:3]:  # Last 3 scans
                    context_parts.append(f"  - {scan.get('technique', 'unknown')}: {scan.get('result', 'unknown')}")
            
            context = "\n".join(context_parts)
            
            # Add book knowledge context for composite strategies
            book_context = ""
            if self.book_knowledge:
                conditions = {
                    'waf_detected': target_info.get('waf_detected', False),
                    'stealth_required': target_info.get('stealth_required', False),
                    'firewall_detected': target_info.get('firewall_detected', False),
                    'ids_detected': target_info.get('ids_detected', False),
                    'speed_priority': target_info.get('speed_priority', 'normal'),
                    'service_detection_needed': target_info.get('service_detection_needed', False)
                }
                book_context = self.book_knowledge.get_composite_strategy_context(conditions)
            
            # Enhanced prompt with book knowledge
            prompt = f"""
As a cybersecurity reconnaissance expert with deep knowledge of Nmap from the official Nmap Network Scanning book, analyze this target and recommend an optimal COMPOSITE scan strategy that STACKS multiple advanced arguments.

Target Information:
{context}

{f'''
KNOWLEDGE BASE - Relevant excerpts from Nmap Network Scanning book:
{book_context}
''' if book_context else ''}

CRITICAL: Generate COMPOSITE strategies that COMBINE multiple conditions:
- If WAF detected AND stealth required: Stack decoy scan (-D RND:5,ME) + source port spoofing (-g 443) + exotic scan (-sF) + data length (--data-length 25) + timing controls (--scan-delay 1000ms)
- If WAF detected AND service detection needed: Combine SYN scan (-sS) + version detection (-sV --version-intensity 9) + evasion (-g 443 -D RND:3,ME)
- If firewall detected AND speed priority: Use fast timing (--min-rate 1000) + evasion (-f -D RND:3,ME) + top ports (-F)

Consider:
1. Best scan technique (SYN, connect, UDP, etc.) - choose based on conditions
2. Optimal port selection - adapt to stealth/speed requirements
3. Advanced timing controls (--scan-delay, --max-rtt-timeout, --min-rate) - NOT legacy -T switches
4. WAF/IDS evasion techniques (decoy, fragmentation, source port spoofing, exotic scans)
5. Service detection with appropriate intensity
6. Composite argument stacking for maximum effectiveness

Provide:
- Recommended Nmap arguments as a COMPOSITE strategy (JSON array with multiple stacked flags)
- Detailed reasoning explaining WHY each argument is combined
- Alternative composite strategies if primary fails
- Confidence level (0.0-1.0)

Format response as JSON:
{{
    "strategy": {{
        "technique": "tcp_syn",
        "ports": [80, 443, 8080],
        "timing": "advanced",
        "stealth": true,
        "evasion": true
    }},
    "reasoning": "Composite strategy combining WAF evasion (decoy + source port) with stealth timing and service detection. Based on Nmap book techniques for bypassing stateless firewalls while maintaining low profile.",
    "confidence": 0.85,
    "nmap_arguments": [
        {{"flag": "-sS", "value": null, "reason": "SYN scan is stealthier than connect scan"}},
        {{"flag": "-sV", "value": null, "reason": "Version detection needed"}},
        {{"flag": "--version-intensity", "value": "9", "reason": "High intensity for accuracy"}},
        {{"flag": "-D", "value": "RND:5,ME", "reason": "Random decoys to cloak real IP"}},
        {{"flag": "-g", "value": "443", "reason": "Spoof source port to trusted HTTPS port"}},
        {{"flag": "--scan-delay", "value": "1000ms", "reason": "Delay reduces detection"}},
        {{"flag": "--max-rtt-timeout", "value": "2000ms", "reason": "Conservative timeout for stealth"}}
    ],
    "alternatives": [
        {{
            "nmap_arguments": [
                {{"flag": "-sF", "value": null}},
                {{"flag": "-D", "value": "RND:3,ME"}},
                {{"flag": "--data-length", "value": "25"}}
            ],
            "reasoning": "Fallback: FIN scan with lighter decoy usage if SYN scan fails"
        }}
    ]
}}
"""
            
            request = CodeGenerationRequest(
                prompt=prompt,
                language="json",  # We want structured output
                personality="kage",  # Use Ash's perspective
                max_tokens=1500,
                temperature=0.3,  # Lower temperature for more deterministic recommendations
                context=context,
                use_knowledge_context=True,
                preferred_backend=BackendType.EGOLlAMA
            )
            
            result = await self.llm_service.generate_code(request)
            
            if result.success and result.code:
                try:
                    # Parse JSON response
                    strategy_data = json.loads(result.code)
                    
                    return ScanStrategyRecommendation(
                        strategy=strategy_data.get('strategy', {}),
                        reasoning=strategy_data.get('reasoning', 'No reasoning provided'),
                        confidence=float(strategy_data.get('confidence', 0.5)),
                        nmap_arguments=strategy_data.get('nmap_arguments', []),
                        alternative_strategies=strategy_data.get('alternatives', [])
                    )
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse LLM strategy response: {e}")
                    logger.debug(f"Response: {result.code[:500]}")
                    return None
            else:
                logger.debug(f"LLM strategy generation failed: {result.error}")
                return None
                
        except Exception as e:
            logger.warning(f"Error in LLM scan strategy analysis: {e}")
            return None
    
    async def interpret_scan_results(
        self,
        target: str,
        scan_results: Dict[str, Any],
        scan_metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[ScanResultAnalysis]:
        """
        Use LLM to semantically understand and analyze scan results.
        
        Args:
            target: Target that was scanned
            scan_results: Dictionary with scan results (ports, services, etc.)
            scan_metadata: Optional metadata about the scan
            
        Returns:
            ScanResultAnalysis or None if LLM unavailable
        """
        if not self.enabled or not self.llm_service:
            return None
        
        try:
            # Format scan results for LLM
            results_summary = {
                'target': target,
                'open_ports': scan_results.get('open_ports', []),
                'services': scan_results.get('services', []),
                'waf_detected': scan_results.get('waf_detected', False),
                'ssl_info': scan_results.get('ssl_analysis', {}),
                'scan_duration': scan_results.get('scan_duration', 0)
            }
            
            prompt = f"""
As a cybersecurity analyst, analyze these Nmap scan results and provide insights.

Scan Results:
{safe_json_dumps(results_summary, indent=2)}

Analyze:
1. Security concerns (exposed services, misconfigurations, etc.)
2. Interesting findings (unusual ports, service versions, etc.)
3. Risk assessment (low/medium/high/critical)
4. Recommendations for further investigation

Format response as JSON:
{{
    "summary": "brief summary",
    "security_concerns": ["concern1", "concern2"],
    "interesting_findings": ["finding1", "finding2"],
    "recommendations": ["rec1", "rec2"],
    "risk_level": "medium"
}}
"""
            
            request = CodeGenerationRequest(
                prompt=prompt,
                language="json",
                personality="ryu",  # Use Jade's security perspective
                max_tokens=1000,
                temperature=0.4,
                context=safe_json_dumps(results_summary),
                use_knowledge_context=True,
                preferred_backend=BackendType.EGOLlAMA
            )
            
            result = await self.llm_service.generate_code(request)
            
            if result.success and result.code:
                try:
                    analysis_data = json.loads(result.code)
                    
                    return ScanResultAnalysis(
                        summary=analysis_data.get('summary', 'No summary available'),
                        security_concerns=analysis_data.get('security_concerns', []),
                        interesting_findings=analysis_data.get('interesting_findings', []),
                        recommendations=analysis_data.get('recommendations', []),
                        risk_level=analysis_data.get('risk_level', 'unknown')
                    )
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse LLM analysis response: {e}")
                    return None
            else:
                logger.debug(f"LLM result analysis failed: {result.error}")
                return None
                
        except Exception as e:
            logger.warning(f"Error in LLM scan result interpretation: {e}")
            return None
    
    async def analyze_http_content(
        self,
        url: str,
        response_headers: Dict[str, Any],
        response_body: str,
        status_code: int
    ) -> Optional[ContentAnalysis]:
        """
        Use LLM to analyze HTTP response content for security indicators.
        
        Args:
            url: URL that was requested
            response_headers: HTTP response headers
            response_body: Response body (truncated if large)
            status_code: HTTP status code
            
        Returns:
            ContentAnalysis or None if LLM unavailable
        """
        if not self.enabled or not self.llm_service:
            return None
        
        try:
            # Truncate body for LLM (keep first 5000 chars)
            body_sample = response_body[:5000] if response_body else ""
            
            prompt = f"""
As a web security analyst, analyze this HTTP response for security indicators.

URL: {url}
Status Code: {status_code}
Headers: {json.dumps(dict(list(response_headers.items())[:20]), indent=2)}
Body Sample: {body_sample[:2000]}...

Analyze for:
1. Content type and application structure
2. Security indicators (tokens, keys, sensitive data patterns)
3. Application framework/technology detection
4. Recommendations for further investigation

Format response as JSON:
{{
    "content_type": "web_application",
    "security_indicators": ["indicator1", "indicator2"],
    "sensitive_data_detected": ["data1", "data2"],
    "application_structure": {{"framework": "django", "version": "4.0"}},
    "recommendations": ["rec1", "rec2"]
}}
"""
            
            request = CodeGenerationRequest(
                prompt=prompt,
                language="json",
                personality="kumo",  # Use Misty's perspective
                max_tokens=1000,
                temperature=0.3,
                context=f"URL: {url}\nStatus: {status_code}",
                use_knowledge_context=True,
                preferred_backend=BackendType.EGOLlAMA
            )
            
            result = await self.llm_service.generate_code(request)
            
            if result.success and result.code:
                try:
                    analysis_data = json.loads(result.code)
                    
                    return ContentAnalysis(
                        content_type=analysis_data.get('content_type', 'unknown'),
                        security_indicators=analysis_data.get('security_indicators', []),
                        sensitive_data_detected=analysis_data.get('sensitive_data_detected', []),
                        application_structure=analysis_data.get('application_structure', {}),
                        recommendations=analysis_data.get('recommendations', [])
                    )
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse LLM content analysis: {e}")
                    return None
            else:
                logger.debug(f"LLM content analysis failed: {result.error}")
                return None
                
        except Exception as e:
            logger.warning(f"Error in LLM HTTP content analysis: {e}")
            return None
    
    async def generate_threat_assessment(
        self,
        target: str,
        kage_findings: List[Dict[str, Any]],
        kumo_findings: List[Dict[str, Any]],
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Optional[ThreatAssessment]:
        """
        Use LLM to correlate findings from Kage and Misty into comprehensive threat assessment.
        
        Args:
            target: Target being assessed
            kage_findings: List of findings from Kage (port scans, services, etc.)
            kumo_findings: List of findings from Kumo (HTTP responses, content, etc.)
            additional_context: Optional additional context
            
        Returns:
            ThreatAssessment or None if LLM unavailable
        """
        if not self.enabled or not self.llm_service:
            return None
        
        try:
            # Summarize findings
            findings_summary = {
                'target': target,
                'port_scan_results': kage_findings[:10],  # Limit to top 10
                'http_findings': kumo_findings[:10],
                'context': additional_context or {}
            }
            
            prompt = f"""
As a senior cybersecurity analyst, create a comprehensive threat assessment by correlating reconnaissance findings.

Target: {target}

Port Scan Findings (Ash):
{safe_json_dumps(kage_findings[:5], indent=2)}

HTTP/Content Findings (Misty):
{safe_json_dumps(kumo_findings[:5], indent=2)}

Additional Context:
{safe_json_dumps(additional_context or {}, indent=2)}

Create a threat assessment that:
1. Correlates findings across both sources
2. Identifies attack vectors
3. Prioritizes vulnerabilities
4. Provides remediation recommendations
5. Generates a human-readable narrative

Format response as JSON:
{{
    "overall_risk": "high",
    "threat_summary": "summary text",
    "vulnerabilities": [
        {{"type": "exposed_service", "severity": "medium", "description": "..."}}
    ],
    "attack_vectors": ["vector1", "vector2"],
    "remediation_priorities": ["priority1", "priority2"],
    "narrative": "Human-readable assessment narrative"
}}
"""
            
            request = CodeGenerationRequest(
                prompt=prompt,
                language="json",
                personality="ryu",  # Use Jade's security expertise
                max_tokens=2000,
                temperature=0.4,
                context=safe_json_dumps(findings_summary),
                use_knowledge_context=True,
                preferred_backend=BackendType.EGOLlAMA
            )
            
            result = await self.llm_service.generate_code(request)
            
            if result.success and result.code:
                try:
                    assessment_data = json.loads(result.code)
                    
                    return ThreatAssessment(
                        overall_risk=assessment_data.get('overall_risk', 'unknown'),
                        threat_summary=assessment_data.get('threat_summary', ''),
                        vulnerabilities=assessment_data.get('vulnerabilities', []),
                        attack_vectors=assessment_data.get('attack_vectors', []),
                        remediation_priorities=assessment_data.get('remediation_priorities', []),
                        narrative=assessment_data.get('narrative', '')
                    )
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse LLM threat assessment: {e}")
                    return None
            else:
                logger.debug(f"LLM threat assessment generation failed: {result.error}")
                return None
                
        except Exception as e:
            logger.warning(f"Error in LLM threat assessment: {e}")
            return None
    
    def is_available(self) -> bool:
        """Check if LLM enhancement is available"""
        return self.enabled and self.llm_service is not None


# Global instance
_llm_enhancer_instance = None

def get_llm_enhancer(enabled: bool = True, egollama_url: str = "http://localhost:8082") -> ReconnaissanceLLMEnhancer:
    """
    Get or create global LLM enhancer instance.
    
    Args:
        enabled: Whether to enable LLM enhancements
        egollama_url: EgoLlama Gateway URL
        
    Returns:
        ReconnaissanceLLMEnhancer instance
    """
    global _llm_enhancer_instance
    
    if _llm_enhancer_instance is None:
        _llm_enhancer_instance = ReconnaissanceLLMEnhancer(
            enabled=enabled,
            egollama_url=egollama_url
        )
    
    return _llm_enhancer_instance


