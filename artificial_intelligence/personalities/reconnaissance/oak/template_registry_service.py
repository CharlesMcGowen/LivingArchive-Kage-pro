#!/usr/bin/env python3
"""
Oak Template Registry Service
==============================

Scans and indexes Nuclei templates from the template directory.
Stores template metadata in eggrecords database for correlation with EggRecords.

Author: EGO Revolution Team - Oak
Version: 1.0.0
"""

import logging
import os
import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from django.db import connections, transaction
from django.utils import timezone
import uuid
import json

logger = logging.getLogger(__name__)


class OakTemplateRegistryService:
    """
    Service for scanning, indexing, and querying Nuclei templates.
    
    Connects to eggrecords database to store template metadata so Oak can
    correlate templates with EggRecords based on technology fingerprints and CVEs.
    """
    
    def __init__(self, templates_dir: Optional[str] = None, additional_dirs: Optional[List[str]] = None):
        """
        Initialize template registry service.
        
        Args:
            templates_dir: Path to primary Nuclei templates directory (default: /home/ego/nuclei-templates)
            additional_dirs: List of additional template directories to scan
        """
        self.logger = logging.getLogger(__name__)
        
        # Default templates directory (same as Surge uses)
        if templates_dir is None:
            templates_dir = os.environ.get('NUCLEI_TEMPLATES_DIR', '/home/ego/nuclei-templates')
        
        self.templates_dir = Path(templates_dir)
        
        # Additional template directories (e.g., from Celestia's cloned repos)
        self.additional_dirs = []
        if additional_dirs:
            self.additional_dirs = [Path(d) for d in additional_dirs if Path(d).exists()]
        else:
            # Auto-detect common additional directories
            auto_dirs = [
                '/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/40k-nuclei-templates',
                '/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/nuclei-templates',
                '/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/nuclei-templates-ai',
            ]
            for dir_path in auto_dirs:
                path = Path(dir_path)
                if path.exists():
                    self.additional_dirs.append(path)
        
        self._ensure_database_table()
    
    def _ensure_database_table(self):
        """Ensure the template registry table exists in eggrecords database."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    # Check if table exists
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'public'
                            AND table_name = 'enrichment_system_nucleitemplate'
                        )
                    """)
                    
                    table_exists = cursor.fetchone()[0]
                    
                    if not table_exists:
                        # Create table
                        cursor.execute("""
                            CREATE TABLE enrichment_system_nucleitemplate (
                                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                template_id VARCHAR(500) UNIQUE NOT NULL,
                                template_path VARCHAR(1000) NOT NULL,
                                template_name VARCHAR(500),
                                cve_id VARCHAR(50),
                                technology VARCHAR(200),
                                tags JSONB DEFAULT '[]'::jsonb,
                                severity VARCHAR(20),
                                author VARCHAR(200),
                                description TEXT,
                                reference TEXT,
                                classification JSONB,
                                raw_content TEXT,
                                created_at TIMESTAMP DEFAULT NOW(),
                                updated_at TIMESTAMP DEFAULT NOW(),
                                indexed_at TIMESTAMP DEFAULT NOW()
                            )
                        """)
                        
                        # Create indexes separately
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_nuclei_template_cve 
                            ON enrichment_system_nucleitemplate(cve_id)
                        """)
                        
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_nuclei_template_technology 
                            ON enrichment_system_nucleitemplate(technology)
                        """)
                        
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_nuclei_template_severity 
                            ON enrichment_system_nucleitemplate(severity)
                        """)
                        
                        # Create GIN index for tags JSONB
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_nuclei_template_tags_gin 
                            ON enrichment_system_nucleitemplate USING GIN (tags)
                        """)
                        
                        self.logger.info("✅ Created enrichment_system_nucleitemplate table")
        except Exception as e:
            self.logger.error(f"Error ensuring database table: {e}", exc_info=True)
    
    def scan_and_index_templates(self, force_rescan: bool = False) -> Dict[str, Any]:
        """
        Scan templates directory and index all templates in database.
        
        Args:
            force_rescan: If True, re-index existing templates
            
        Returns:
            Dict with scan statistics
        """
        if not self.templates_dir.exists():
            self.logger.warning(f"Templates directory does not exist: {self.templates_dir}")
            return {
                'success': False,
                'error': f'Templates directory not found: {self.templates_dir}',
                'scanned': 0,
                'indexed': 0,
                'errors': 0
            }
        
        # Collect all template directories to scan
        all_dirs = [self.templates_dir] + self.additional_dirs
        dirs_to_scan = [d for d in all_dirs if d.exists()]
        
        if not dirs_to_scan:
            self.logger.warning(f"No template directories found to scan")
            return {
                'success': False,
                'error': 'No template directories found',
                'scanned': 0,
                'indexed': 0,
                'errors': 0
            }
        
        self.logger.info(f"🔍 Scanning {len(dirs_to_scan)} template directory(ies):")
        for d in dirs_to_scan:
            self.logger.info(f"   - {d}")
        
        scanned = 0
        indexed = 0
        updated = 0
        errors = 0
        
        # Find all YAML template files from all directories
        template_files = []
        for template_dir in dirs_to_scan:
            template_files.extend(list(template_dir.rglob('*.yaml')))
            template_files.extend(list(template_dir.rglob('*.yml')))
        
        self.logger.info(f"Found {len(template_files)} template files")
        
        for template_file in template_files:
            try:
                scanned += 1
                
                # Parse template file
                template_data = self._parse_template_file(template_file)
                
                if not template_data:
                    continue
                
                # Index template in database
                result = self._index_template(template_file, template_data, force_rescan)
                
                if result == 'indexed':
                    indexed += 1
                elif result == 'updated':
                    updated += 1
                elif result == 'skipped':
                    pass  # Already exists and not forcing rescan
                else:
                    errors += 1
                    
            except Exception as e:
                errors += 1
                self.logger.debug(f"Error processing {template_file}: {e}")
        
        self.logger.info(f"✅ Template scan complete: {scanned} scanned, {indexed} indexed, {updated} updated, {errors} errors")
        
        return {
            'success': True,
            'scanned': scanned,
            'indexed': indexed,
            'updated': updated,
            'errors': errors,
            'total_templates': scanned
        }
    
    def _parse_template_file(self, template_file: Path) -> Optional[Dict[str, Any]]:
        """Parse a Nuclei template YAML file."""
        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                content = f.read()
                template_data = yaml.safe_load(content)
            
            if not template_data or 'id' not in template_data:
                return None
            
            # Extract template metadata
            template_id = template_data.get('id', '')
            info = template_data.get('info', {})
            
            # Extract CVE ID from various fields
            cve_id = None
            if 'classification' in info:
                cve_id = info['classification'].get('cve-id', [])
                if isinstance(cve_id, list) and len(cve_id) > 0:
                    cve_id = cve_id[0]
                elif not cve_id:
                    cve_id = None
            
            # Also check tags and name for CVE
            if not cve_id:
                tags = info.get('tags', [])
                for tag in tags:
                    if tag.startswith('cve-') or 'CVE-' in tag.upper():
                        cve_id = tag.upper().replace('CVE-', 'CVE-')
                        break
            
            if not cve_id and 'name' in info:
                name = info['name']
                cve_match = re.search(r'CVE[-\s]?(\d{4})[-\s]?(\d{4,})', name, re.IGNORECASE)
                if cve_match:
                    cve_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
            
            # Extract technology from tags
            technology = None
            tags_list = info.get('tags', [])
            if isinstance(tags_list, list):
                # Common technology tags
                tech_tags = ['apache', 'nginx', 'iis', 'wordpress', 'drupal', 'joomla',
                           'mysql', 'postgres', 'mongodb', 'redis', 'tomcat', 'jetty',
                           'jenkins', 'grafana', 'kibana', 'elasticsearch']
                for tag in tags_list:
                    tag_lower = tag.lower()
                    for tech in tech_tags:
                        if tech in tag_lower:
                            technology = tech
                            break
                    if technology:
                        break
            
            # Extract severity
            severity = info.get('severity', 'info').lower()
            if severity not in ['critical', 'high', 'medium', 'low', 'info']:
                severity = 'info'
            
            return {
                'template_id': template_id,
                'template_name': info.get('name', ''),
                'cve_id': cve_id,
                'technology': technology,
                'tags': tags_list if isinstance(tags_list, list) else [],
                'severity': severity,
                'author': ','.join(info.get('author', [])) if isinstance(info.get('author'), list) else info.get('author', ''),
                'description': info.get('description', ''),
                'reference': info.get('reference', []),
                'classification': info.get('classification', {}),
                'raw_content': content
            }
            
        except Exception as e:
            self.logger.debug(f"Error parsing template {template_file}: {e}")
            return None
    
    def _index_template(self, template_file: Path, template_data: Dict[str, Any], 
                       force_rescan: bool = False) -> str:
        """
        Index a template in the database.
        
        Returns:
            'indexed', 'updated', 'skipped', or 'error'
        """
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    template_id = template_data['template_id']
                    
                    # Find which directory this template belongs to
                    all_dirs = [self.templates_dir] + self.additional_dirs
                    template_path = str(template_file)
                    for template_dir in all_dirs:
                        try:
                            template_path = str(template_file.relative_to(template_dir))
                            break
                        except ValueError:
                            # File is not in this directory, try next
                            continue
                    # If not found in any directory, use absolute path
                    if template_path == str(template_file):
                        template_path = str(template_file)
                    
                    # Check if template already exists
                    cursor.execute("""
                        SELECT id, updated_at FROM enrichment_system_nucleitemplate
                        WHERE template_id = %s
                    """, [template_id])
                    
                    existing = cursor.fetchone()
                    
                    # Prepare data
                    reference_text = ''
                    if isinstance(template_data.get('reference'), list):
                        reference_text = '\n'.join(template_data['reference'])
                    elif isinstance(template_data.get('reference'), str):
                        reference_text = template_data['reference']
                    
                    tags_json = json.dumps(template_data.get('tags', []))
                    classification_json = json.dumps(template_data.get('classification', {}))
                    
                    if existing and not force_rescan:
                        # Update if file is newer or force_rescan
                        cursor.execute("""
                            UPDATE enrichment_system_nucleitemplate
                            SET template_path = %s,
                                template_name = %s,
                                cve_id = %s,
                                technology = %s,
                                tags = %s::jsonb,
                                severity = %s,
                                author = %s,
                                description = %s,
                                reference = %s,
                                classification = %s::jsonb,
                                raw_content = %s,
                                updated_at = NOW(),
                                indexed_at = NOW()
                            WHERE template_id = %s
                        """, [
                            template_path,
                            template_data.get('template_name', ''),
                            template_data.get('cve_id'),
                            template_data.get('technology'),
                            tags_json,
                            template_data.get('severity', 'info'),
                            template_data.get('author', ''),
                            template_data.get('description', ''),
                            reference_text,
                            classification_json,
                            template_data.get('raw_content', ''),
                            template_id
                        ])
                        return 'updated'
                    elif not existing:
                        # Insert new template
                        template_uuid = str(uuid.uuid4())
                        cursor.execute("""
                            INSERT INTO enrichment_system_nucleitemplate (
                                id, template_id, template_path, template_name,
                                cve_id, technology, tags, severity, author,
                                description, reference, classification, raw_content,
                                created_at, updated_at, indexed_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s::jsonb, %s, NOW(), NOW(), NOW())
                        """, [
                            template_uuid,
                            template_id,
                            template_path,
                            template_data.get('template_name', ''),
                            template_data.get('cve_id'),
                            template_data.get('technology'),
                            tags_json,
                            template_data.get('severity', 'info'),
                            template_data.get('author', ''),
                            template_data.get('description', ''),
                            reference_text,
                            classification_json,
                            template_data.get('raw_content', '')
                        ])
                        return 'indexed'
                    else:
                        return 'skipped'
                        
        except Exception as e:
            self.logger.error(f"Error indexing template {template_data.get('template_id')}: {e}")
            return 'error'
    
    def find_templates_by_technology(self, technology: str, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find templates matching a technology.
        
        Args:
            technology: Technology name (e.g., 'apache', 'wordpress')
            severity: Optional severity filter
            
        Returns:
            List of template dicts
        """
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    tech_lower = technology.lower()
                    
                    query = """
                        SELECT template_id, template_path, template_name, cve_id,
                               technology, tags, severity, description
                        FROM enrichment_system_nucleitemplate
                        WHERE LOWER(technology) = %s
                    """
                    params = [tech_lower]
                    
                    if severity:
                        query += " AND severity = %s"
                        params.append(severity.lower())
                    
                    query += " ORDER BY severity DESC, template_name"
                    
                    cursor.execute(query, params)
                    
                    templates = []
                    for row in cursor.fetchall():
                        tags = row[5] if isinstance(row[5], list) else json.loads(row[5]) if isinstance(row[5], str) else []
                        templates.append({
                            'template_id': row[0],
                            'template_path': row[1],
                            'template_name': row[2],
                            'cve_id': row[3],
                            'technology': row[4],
                            'tags': tags,
                            'severity': row[6],
                            'description': row[7]
                        })
                    
                    return templates
        except Exception as e:
            self.logger.error(f"Error finding templates by technology: {e}")
            return []
    
    def find_templates_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Find templates matching a CVE ID."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT template_id, template_path, template_name, cve_id,
                               technology, tags, severity, description
                        FROM enrichment_system_nucleitemplate
                        WHERE cve_id = %s
                        ORDER BY severity DESC
                    """, [cve_id.upper()])
                    
                    templates = []
                    for row in cursor.fetchall():
                        tags = row[5] if isinstance(row[5], list) else json.loads(row[5]) if isinstance(row[5], str) else []
                        templates.append({
                            'template_id': row[0],
                            'template_path': row[1],
                            'template_name': row[2],
                            'cve_id': row[3],
                            'technology': row[4],
                            'tags': tags,
                            'severity': row[6],
                            'description': row[7]
                        })
                    
                    return templates
        except Exception as e:
            self.logger.error(f"Error finding templates by CVE: {e}")
            return []
    
    def find_templates_by_tags(self, tags: List[str]) -> List[Dict[str, Any]]:
        """Find templates matching any of the provided tags."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    # Use JSONB contains operator
                    tag_conditions = []
                    params = []
                    
                    for tag in tags:
                        tag_conditions.append("tags @> %s::jsonb")
                        params.append(json.dumps([tag.lower()]))
                    
                    query = f"""
                        SELECT template_id, template_path, template_name, cve_id,
                               technology, tags, severity, description
                        FROM enrichment_system_nucleitemplate
                        WHERE {' OR '.join(tag_conditions)}
                        ORDER BY severity DESC
                    """
                    
                    cursor.execute(query, params)
                    
                    templates = []
                    for row in cursor.fetchall():
                        row_tags = row[5] if isinstance(row[5], list) else json.loads(row[5]) if isinstance(row[5], str) else []
                        templates.append({
                            'template_id': row[0],
                            'template_path': row[1],
                            'template_name': row[2],
                            'cve_id': row[3],
                            'technology': row[4],
                            'tags': row_tags,
                            'severity': row[6],
                            'description': row[7]
                        })
                    
                    return templates
        except Exception as e:
            self.logger.error(f"Error finding templates by tags: {e}")
            return []
    
    def get_template_by_id(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Get a template by its ID."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT template_id, template_path, template_name, cve_id,
                               technology, tags, severity, description, raw_content
                        FROM enrichment_system_nucleitemplate
                        WHERE template_id = %s
                    """, [template_id])
                    
                    row = cursor.fetchone()
                    if row:
                        tags = row[5] if isinstance(row[5], list) else json.loads(row[5]) if isinstance(row[5], str) else []
                        return {
                            'template_id': row[0],
                            'template_path': row[1],
                            'template_name': row[2],
                            'cve_id': row[3],
                            'technology': row[4],
                            'tags': tags,
                            'severity': row[6],
                            'description': row[7],
                            'raw_content': row[8]
                        }
                    return None
        except Exception as e:
            self.logger.error(f"Error getting template by ID: {e}")
            return None

