#!/usr/bin/env python3
"""
Subdomain Enumeration Service
=============================

Extracted Amass functionality from AshEnhancedReconnaissanceService.
Standalone subdomain enumeration service with passive and active modes.

Author: EGO Revolution Team
Version: 1.0.0
"""

import logging
import subprocess
import os
import json
import time
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse

# Add EgoQT src to path for database services
import sys

from artificial_intelligence.personalities.reconnaissance import EGOQT_SRC  # noqa: F401

from database.customer_database import CustomerDatabaseService
from database.customer_models import Eggs, EggRecord

logger = logging.getLogger(__name__)


class SubdomainEnumerationService:
    """
    Standalone subdomain enumeration service using Amass.
    
    Supports both passive and active enumeration modes.
    Stores discovered subdomains as new EggRecord entries.
    """
    
    def __init__(self, database_url: str = None):
        """
        Initialize subdomain enumeration service.
        
        Args:
            database_url: Database connection URL. If None, uses default.
        """
        self.db_service = CustomerDatabaseService(database_url)
        
        # Amass configuration
        self.amass_path = "amass"  # Assume amass is in PATH
        self.output_dir = "/tmp/amass_recon"
        os.makedirs(self.output_dir, exist_ok=True)
        
        logger.info("🔍 SubdomainEnumerationService initialized")
    
    async def enumerate_domains(self, domains: List[str], mode: str = "passive") -> Dict[str, Any]:
        """
        Enumerate subdomains for a list of domains.
        
        Args:
            domains: List of domains to enumerate
            mode: Enumeration mode ("passive", "active", "both")
            
        Returns:
            Dictionary with enumeration results
        """
        logger.info(f"🔍 Enumerating subdomains for {len(domains)} domains (mode: {mode})")
        
        results = {
            'domains': domains,
            'mode': mode,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'success': True
        }
        
        try:
            for domain in domains:
                domain_results = await self._enumerate_single_domain(domain, mode)
                results['subdomains'].extend(domain_results)
            
            # Filter test domains and remove duplicates
            filtered_subdomains = self._filter_test_domains(results['subdomains'])
            unique_subdomains = list(set(filtered_subdomains))
            results['subdomains'] = unique_subdomains
            results['total_found'] = len(unique_subdomains)
            
            logger.info(f"🔍 Found {len(unique_subdomains)} unique valid subdomains (test domains filtered)")
            
        except Exception as e:
            logger.error(f"❌ Error during subdomain enumeration: {e}")
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    def _filter_test_domains(self, subdomains: List[str]) -> List[str]:
        """
        Filter out test, localhost, and example domains.
        
        Args:
            subdomains: List of subdomains to filter
            
        Returns:
            Filtered list of non-test subdomains
        """
        test_patterns = [
            'test', 'localhost', '127.0.0.1', 'example.com',
            'staging', 'dev', 'demo', 'sandbox', 'qa',
            'local', '.test', '.dev', '.local'
        ]
        
        filtered = []
        for subdomain in subdomains:
            subdomain_lower = subdomain.lower()
            # Skip if contains test patterns
            if any(pattern in subdomain_lower for pattern in test_patterns):
                logger.debug(f"🚫 Filtered test domain: {subdomain}")
                continue
            # Skip if IP address (127.0.0.1, localhost, etc.)
            if subdomain_lower.startswith('127.') or subdomain_lower == 'localhost':
                logger.debug(f"🚫 Filtered IP/localhost: {subdomain}")
                continue
            filtered.append(subdomain)
        
        filtered_count = len(subdomains) - len(filtered)
        if filtered_count > 0:
            logger.info(f"🚫 Filtered out {filtered_count} test/localhost subdomains")
        
        return filtered

    async def _enumerate_single_domain(self, domain: str, mode: str) -> List[str]:
        """
        Enumerate subdomains for a single domain.
        
        Args:
            domain: Domain to enumerate
            mode: Enumeration mode
            
        Returns:
            List of discovered subdomains (filtered to exclude test domains)
        """
        logger.info(f"🔍 Enumerating subdomains for: {domain}")
        
        # Skip test domains in enumeration
        domain_lower = domain.lower()
        test_patterns = ['test', 'localhost', '127.0.0.1', 'example.com']
        if any(pattern in domain_lower for pattern in test_patterns):
            logger.warning(f"🚫 Skipping test domain: {domain}")
            return []
        
        subdomains = []
        
        try:
            # Run Amass based on mode
            if mode == "passive":
                subdomains = await self._run_amass_passive(domain)
            elif mode == "active":
                subdomains = await self._run_amass_active(domain)
            elif mode == "both":
                passive_subdomains = await self._run_amass_passive(domain)
                active_subdomains = await self._run_amass_active(domain)
                subdomains = list(set(passive_subdomains + active_subdomains))
            
            # Filter out test subdomains
            subdomains = self._filter_test_domains(subdomains)
            
            logger.info(f"🔍 Found {len(subdomains)} valid subdomains for {domain} (after filtering)")
            
        except Exception as e:
            logger.error(f"❌ Error enumerating {domain}: {e}")
        
        return subdomains
    
    async def _run_amass_passive(self, domain: str) -> List[str]:
        """
        Run Amass in passive mode.
        
        Args:
            domain: Domain to enumerate
            
        Returns:
            List of discovered subdomains
        """
        try:
            output_file = os.path.join(self.output_dir, f"amass_passive_{domain}_{int(time.time())}.txt")
            
            cmd = [
                self.amass_path, "enum",
                "-d", domain,
                "-o", output_file,
                "-silent",
                "-passive"
            ]
            
            logger.info(f"🔍 Running Amass passive: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes max
                cwd=self.output_dir
            )
            
            subdomains = []
            if result.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            
            # Clean up
            if os.path.exists(output_file):
                os.remove(output_file)
            
            return subdomains
            
        except Exception as e:
            logger.error(f"❌ Error running Amass passive for {domain}: {e}")
            return []
    
    async def _run_amass_active(self, domain: str) -> List[str]:
        """
        Run Amass in active mode.
        
        Args:
            domain: Domain to enumerate
            
        Returns:
            List of discovered subdomains
        """
        try:
            output_file = os.path.join(self.output_dir, f"amass_active_{domain}_{int(time.time())}.txt")
            
            cmd = [
                self.amass_path, "enum",
                "-d", domain,
                "-o", output_file,
                "-silent",
                "-active"
            ]
            
            logger.info(f"🔍 Running Amass active: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1200,  # 20 minutes max
                cwd=self.output_dir
            )
            
            subdomains = []
            if result.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            
            # Clean up
            if os.path.exists(output_file):
                os.remove(output_file)
            
            return subdomains
            
        except Exception as e:
            logger.error(f"❌ Error running Amass active for {domain}: {e}")
            return []
    
    async def store_subdomains_as_records(self, egg_id: str, subdomains: List[str], parent_domain: str) -> Dict[str, Any]:
        """
        Store discovered subdomains as EggRecord entries.
        
        Args:
            egg_id: UUID string of the parent egg
            subdomains: List of discovered subdomains
            parent_domain: Parent domain name
            
        Returns:
            Dictionary with storage results
        """
        logger.info(f"🔍 Storing {len(subdomains)} subdomains as records for egg {egg_id}")
        
        try:
            successful = 0
            failed = 0
            errors = []
            
            for subdomain in subdomains:
                try:
                    # Create record data
                    record_data = {
                        'egg_id': egg_id,
                        'sub_domain': subdomain,
                        'domain_name': parent_domain,
                        'alive': True,  # Assume alive until proven otherwise
                        'aws_scan': False,
                        'data_source': 'amass_enumeration',
                        'validation_timestamp': datetime.now()
                    }
                    
                    # Create record
                    record, message = self.db_service.create_egg_record(record_data)
                    
                    if record:
                        successful += 1
                    else:
                        failed += 1
                        errors.append(f"Subdomain {subdomain}: {message}")
                        
                except Exception as e:
                    failed += 1
                    errors.append(f"Subdomain {subdomain}: {str(e)}")
            
            logger.info(f"🔍 Stored {successful} subdomains, {failed} failed")
            
            return {
                'success': True,
                'total_subdomains': len(subdomains),
                'successful': successful,
                'failed': failed,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"❌ Error storing subdomains: {e}")
            return {
                'success': False,
                'error': str(e),
                'total_subdomains': len(subdomains),
                'successful': 0,
                'failed': len(subdomains)
            }
    
    async def enumerate_egg_scope(self, egg_id: str, mode: str = "passive") -> Dict[str, Any]:
        """
        Enumerate subdomains for an egg's domain scope.
        
        Args:
            egg_id: UUID string of the egg
            mode: Enumeration mode
            
        Returns:
            Dictionary with enumeration results
        """
        logger.info(f"🔍 Enumerating subdomains for egg {egg_id}")
        
        try:
            # Get egg from database
            egg = self.db_service.get_egg_by_id(egg_id)
            if not egg:
                return {
                    'success': False,
                    'error': f'Egg {egg_id} not found'
                }
            
            # Get domain scope
            domain_scope = egg.domain_scope or []
            if not domain_scope:
                return {
                    'success': False,
                    'error': f'No domain scope found for egg {egg_id}'
                }
            
            # Clean domains (remove wildcards)
            clean_domains = []
            for domain in domain_scope:
                if domain.startswith('*.'):
                    clean_domains.append(domain[2:])  # Remove *. prefix
                else:
                    clean_domains.append(domain)
            
            # Enumerate subdomains
            enumeration_results = await self.enumerate_domains(clean_domains, mode)
            
            if not enumeration_results['success']:
                return enumeration_results
            
            # Store subdomains as records
            all_subdomains = enumeration_results['subdomains']
            storage_results = []
            
            for domain in clean_domains:
                # Filter subdomains for this domain
                domain_subdomains = [
                    subdomain for subdomain in all_subdomains
                    if subdomain.endswith(domain)
                ]
                
                if domain_subdomains:
                    storage_result = await self.store_subdomains_as_records(
                        egg_id, domain_subdomains, domain
                    )
                    storage_results.append(storage_result)
            
            return {
                'success': True,
                'egg_id': egg_id,
                'domains_enumerated': clean_domains,
                'total_subdomains_found': len(all_subdomains),
                'enumeration_results': enumeration_results,
                'storage_results': storage_results
            }
            
        except Exception as e:
            logger.error(f"❌ Error enumerating egg scope for {egg_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_enumeration_statistics(self, egg_id: str) -> Dict[str, Any]:
        """
        Get subdomain enumeration statistics for an egg.
        
        Args:
            egg_id: UUID string of the egg
            
        Returns:
            Dictionary with statistics
        """
        try:
            # Get egg records
            egg_records = self.db_service.get_egg_records(egg_id)
            
            # Filter records from Amass enumeration
            amass_records = [
                record for record in egg_records
                if record.data_source == 'amass_enumeration'
            ]
            
            # Categorize subdomains
            admin_subdomains = [
                record for record in amass_records
                if 'admin' in record.sub_domain.lower()
            ]
            
            api_subdomains = [
                record for record in amass_records
                if 'api' in record.sub_domain.lower()
            ]
            
            dev_subdomains = [
                record for record in amass_records
                if any(dev in record.sub_domain.lower() for dev in ['dev', 'test', 'staging'])
            ]
            
            return {
                'total_amass_records': len(amass_records),
                'admin_subdomains': len(admin_subdomains),
                'api_subdomains': len(api_subdomains),
                'dev_subdomains': len(dev_subdomains),
                'alive_amass_records': len([r for r in amass_records if r.alive])
            }
            
        except Exception as e:
            logger.error(f"❌ Error getting enumeration statistics for {egg_id}: {e}")
            return {}
    
    def close(self):
        """Close database connections."""
        if self.db_service:
            self.db_service.close()
            logger.info("✅ SubdomainEnumerationService closed")


# Global instance
_subdomain_enumeration_service = None

def get_subdomain_enumeration_service(database_url: str = None):
    """Get subdomain enumeration service instance (singleton)."""
    global _subdomain_enumeration_service
    
    if _subdomain_enumeration_service is None:
        _subdomain_enumeration_service = SubdomainEnumerationService(database_url)
    
    return _subdomain_enumeration_service


async def enumerate_egg_scope(egg_id: str, mode: str = "passive") -> Dict[str, Any]:
    """
    Enumerate subdomains for an egg's domain scope.
    
    Args:
        egg_id: UUID string of the egg
        mode: Enumeration mode ("passive", "active", "both")
        
    Returns:
        Dictionary with enumeration results
    """
    service = get_subdomain_enumeration_service()
    return await service.enumerate_egg_scope(egg_id, mode)


async def enumerate_domains(domains: List[str], mode: str = "passive") -> Dict[str, Any]:
    """
    Enumerate subdomains for a list of domains.
    
    Args:
        domains: List of domains to enumerate
        mode: Enumeration mode ("passive", "active", "both")
        
    Returns:
        Dictionary with enumeration results
    """
    service = get_subdomain_enumeration_service()
    return await service.enumerate_domains(domains, mode)


if __name__ == "__main__":
    # Test the subdomain enumeration service
    import asyncio
    
    async def test_subdomain_service():
        service = SubdomainEnumerationService()
        
        # Test enumeration
        results = await service.enumerate_domains(["example.com"], "passive")
        print(f"Subdomain enumeration results: {results}")
        
        service.close()
    
    asyncio.run(test_subdomain_service())

