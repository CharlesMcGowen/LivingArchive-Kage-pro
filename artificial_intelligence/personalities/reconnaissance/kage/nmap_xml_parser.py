"""
Nmap XML Parser - Comprehensive XML to JSON Converter
=====================================================
Parses Nmap XML output according to the expected structure:
- Host information (IP, hostname, status, OS detection)
- Port and service data (portid, protocol, state, service name, product, version, CPE)
- Script results (NSE output)
- Scan metadata (args, runstats)
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class NmapXMLParser:
    """
    Comprehensive Nmap XML parser that extracts all structured data
    according to the expected JSON structure.
    """
    
    @staticmethod
    def parse_nmap_xml(xml_content: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output into structured JSON format.
        
        Args:
            xml_content: Raw XML string from Nmap -oX output
            
        Returns:
            Dict with structure:
            {
                'nmaprun': {
                    'args': 'nmap command line arguments',
                    'runstats': {...}
                },
                'hosts': [
                    {
                        'address': {'addr': '192.168.1.1', 'addrtype': 'ipv4'},
                        'hostnames': ['example.com'],
                        'status': {'state': 'up', 'reason': 'echo-reply'},
                        'starttime': 1234567890,
                        'endtime': 1234567900,
                        'os': {'osmatch': [...]},
                        'ports': [
                            {
                                'portid': 443,
                                'protocol': 'tcp',
                                'state': {'state': 'open', 'reason': 'syn-ack'},
                                'service': {
                                    'name': 'https',
                                    'product': 'nginx',
                                    'version': '1.20.0',
                                    'extrainfo': 'Ubuntu',
                                    'cpe': ['cpe:/a:nginx:nginx:1.20.0']
                                },
                                'scripts': [
                                    {'id': 'ssl-cert', 'output': '...', 'elements': [...]}
                                ]
                            }
                        ]
                    }
                ]
            }
        """
        try:
            root = ET.fromstring(xml_content)
            
            result = {
                'nmaprun': {},
                'hosts': []
            }
            
            # Parse nmaprun metadata
            if root.tag == 'nmaprun':
                result['nmaprun']['args'] = root.get('args', '')
                result['nmaprun']['start'] = root.get('start', '')
                result['nmaprun']['startstr'] = root.get('startstr', '')
                
                # Parse runstats
                runstats = root.find('runstats')
                if runstats is not None:
                    finished = runstats.find('finished')
                    if finished is not None:
                        result['nmaprun']['runstats'] = {
                            'finished': {
                                'time': finished.get('time', ''),
                                'timestr': finished.get('timestr', ''),
                                'summary': finished.get('summary', ''),
                                'elapsed': finished.get('elapsed', '')
                            }
                        }
            
            # Parse hosts
            for host in root.findall('host'):
                host_data = NmapXMLParser._parse_host(host)
                if host_data:
                    result['hosts'].append(host_data)
            
            return result
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return {'error': str(e), 'hosts': []}
        except Exception as e:
            logger.error(f"Unexpected error parsing Nmap XML: {e}", exc_info=True)
            return {'error': str(e), 'hosts': []}
    
    @staticmethod
    def _parse_host(host_elem) -> Optional[Dict[str, Any]]:
        """Parse a single <host> element."""
        host_data = {
            'address': {},
            'hostnames': [],
            'status': {},
            'ports': [],
            'os': {}
        }
        
        # Parse address
        address = host_elem.find('address')
        if address is not None:
            host_data['address'] = {
                'addr': address.get('addr', ''),
                'addrtype': address.get('addrtype', '')
            }
        
        # Parse hostnames
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            for hostname in hostnames.findall('hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name', ''),
                    'type': hostname.get('type', '')
                })
        
        # Parse status
        status = host_elem.find('status')
        if status is not None:
            host_data['status'] = {
                'state': status.get('state', ''),
                'reason': status.get('reason', ''),
                'reason_ttl': status.get('reason_ttl', '')
            }
        
        # Parse starttime/endtime
        starttime = host_elem.get('starttime')
        endtime = host_elem.get('endtime')
        if starttime:
            host_data['starttime'] = int(starttime)
        if endtime:
            host_data['endtime'] = int(endtime)
        
        # Parse OS detection
        os_elem = host_elem.find('os')
        if os_elem is not None:
            osmatches = []
            for osmatch in os_elem.findall('osmatch'):
                osmatches.append({
                    'name': osmatch.get('name', ''),
                    'accuracy': osmatch.get('accuracy', ''),
                    'line': osmatch.get('line', '')
                })
            host_data['os']['osmatch'] = osmatches
        
        # Parse ports
        ports = host_elem.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_data = NmapXMLParser._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
        
        return host_data
    
    @staticmethod
    def _parse_port(port_elem) -> Optional[Dict[str, Any]]:
        """Parse a single <port> element."""
        port_data = {
            'portid': port_elem.get('portid', ''),
            'protocol': port_elem.get('protocol', 'tcp'),
            'state': {},
            'service': {},
            'scripts': []
        }
        
        # Parse state
        state = port_elem.find('state')
        if state is not None:
            port_data['state'] = {
                'state': state.get('state', ''),
                'reason': state.get('reason', ''),
                'reason_ttl': state.get('reason_ttl', '')
            }
        
        # Parse service
        service = port_elem.find('service')
        if service is not None:
            port_data['service'] = {
                'name': service.get('name', ''),
                'product': service.get('product', ''),
                'version': service.get('version', ''),
                'extrainfo': service.get('extrainfo', ''),
                'method': service.get('method', ''),
                'conf': service.get('conf', ''),
                'cpe': []
            }
            
            # Parse CPE strings
            for cpe in service.findall('cpe'):
                cpe_str = cpe.text if cpe.text else ''
                if cpe_str:
                    port_data['service']['cpe'].append(cpe_str)
        
        # Parse scripts (NSE results)
        for script in port_elem.findall('script'):
            script_data = {
                'id': script.get('id', ''),
                'output': script.get('output', ''),
                'elements': []
            }
            
            # Parse script elements (structured data)
            for elem in script.findall('elem'):
                script_data['elements'].append({
                    'key': elem.get('key', ''),
                    'value': elem.text if elem.text else ''
                })
            
            # Parse script tables
            for table in script.findall('table'):
                table_data = NmapXMLParser._parse_table(table)
                script_data['elements'].append(table_data)
            
            port_data['scripts'].append(script_data)
        
        return port_data
    
    @staticmethod
    def _parse_table(table_elem) -> Dict[str, Any]:
        """Parse a <table> element (nested structure from NSE scripts)."""
        table_data = {
            'key': table_elem.get('key', ''),
            'type': 'table',
            'rows': []
        }
        
        for row in table_elem.findall('table'):
            row_data = {}
            for elem in row.findall('elem'):
                row_data[elem.get('key', '')] = elem.text if elem.text else ''
            if row_data:
                table_data['rows'].append(row_data)
        
        return table_data
    
    @staticmethod
    def convert_to_scan_result_format(parsed_xml: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert parsed XML structure to the format expected by scan storage.
        
        Returns list of port results compatible with existing storage format.
        """
        results = []
        
        for host in parsed_xml.get('hosts', []):
            for port in host.get('ports', []):
                if port['state'].get('state') != 'open':
                    continue
                
                service = port.get('service', {})
                
                result = {
                    'port': int(port['portid']) if port['portid'].isdigit() else 0,
                    'protocol': port.get('protocol', 'tcp'),
                    'status': port['state'].get('state', 'open'),
                    'state': port['state'].get('state', 'open'),
                    'reason': port['state'].get('reason', ''),
                    
                    # Service information (mapped to existing fields)
                    'service': service.get('name', ''),
                    'service_name': service.get('name', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'service_version': service.get('version', ''),
                    'extrainfo': service.get('extrainfo', ''),
                    'banner': service.get('extrainfo', '') or service.get('product', ''),
                    'service_info': service.get('extrainfo', '') or service.get('product', ''),
                    
                    # CPE strings
                    'cpe': service.get('cpe', []),
                    
                    # Script results
                    'scripts': port.get('scripts', []),
                    
                    # Host information
                    'host_address': host.get('address', {}).get('addr', ''),
                    'hostnames': [h.get('name', '') for h in host.get('hostnames', [])],
                    
                    # OS detection
                    'os_matches': host.get('os', {}).get('osmatch', [])
                }
                
                results.append(result)
        
        return results

