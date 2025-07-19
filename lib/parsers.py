#!/usr/bin/env python3
"""
Output Parsers for AD-Automaton
Handles parsing output from various penetration testing tools into structured data.
"""

import re
import json
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Optional, Any, Tuple
from ipaddress import ip_address, AddressValueError
import base64

from database import Host, Service, User, Credential, Share, Vulnerability

class ParserError(Exception):
    """Custom exception for parsing errors."""
    pass

class BaseParser:
    """Base class for all output parsers."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def _clean_string(self, text: str) -> str:
        """Clean and normalize string input."""
        if not text:
            return ""
        return text.strip().replace('\x00', '').replace('\r', '')
    
    def _extract_ip_addresses(self, text: str) -> List[str]:
        """Extract valid IP addresses from text."""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        potential_ips = re.findall(ip_pattern, text)
        
        valid_ips = []
        for ip in potential_ips:
            try:
                ip_address(ip)
                valid_ips.append(ip)
            except AddressValueError:
                continue
        
        return valid_ips
    
    def _extract_hostnames(self, text: str) -> List[str]:
        """Extract hostnames/FQDNs from text."""
        hostname_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b'
        return re.findall(hostname_pattern, text)

class NmapParser(BaseParser):
    """Parser for nmap XML output."""
    
    def parse_xml(self, xml_content: str) -> Tuple[List[Host], List[Service]]:
        """
        Parse nmap XML output to extract hosts and services.
        
        Args:
            xml_content: Raw XML content from nmap -oX
            
        Returns:
            Tuple of (hosts, services) lists
        """
        hosts = []
        services = []
        
        try:
            root = ET.fromstring(xml_content)
            
            for host_elem in root.findall('host'):
                # Extract host information
                address_elem = host_elem.find('address[@addrtype="ipv4"]')
                if address_elem is None:
                    continue
                
                ip_addr = address_elem.get('addr')
                if not ip_addr:
                    continue
                
                # Get hostname if available
                hostname = None
                hostnames_elem = host_elem.find('hostnames')
                if hostnames_elem is not None:
                    hostname_elem = hostnames_elem.find('hostname[@type="PTR"]')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')
                
                # Get OS information
                os_info = None
                os_elem = host_elem.find('os')
                if os_elem is not None:
                    osmatch_elem = os_elem.find('osmatch')
                    if osmatch_elem is not None:
                        os_info = osmatch_elem.get('name')
                
                # Create host object
                host = Host(
                    ip_address=ip_addr,
                    hostname=hostname,
                    os=os_info
                )
                hosts.append(host)
                
                # Extract services
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        port_num = int(port_elem.get('portid', 0))
                        protocol = port_elem.get('protocol', 'tcp')
                        
                        state_elem = port_elem.find('state')
                        if state_elem is None or state_elem.get('state') != 'open':
                            continue
                        
                        service_elem = port_elem.find('service')
                        service_name = None
                        banner = None
                        
                        if service_elem is not None:
                            service_name = service_elem.get('name')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            extrainfo = service_elem.get('extrainfo', '')
                            
                            # Build banner from available info
                            banner_parts = [part for part in [product, version, extrainfo] if part]
                            if banner_parts:
                                banner = ' '.join(banner_parts)
                        
                        service = Service(
                            host_id=0,  # Will be set when inserted into DB
                            port=port_num,
                            protocol=protocol,
                            service_name=service_name,
                            banner=banner
                        )
                        services.append((host, service))  # Tuple to link service to host
            
            self.logger.info(f"Parsed {len(hosts)} hosts and {len(services)} services from nmap XML")
            return hosts, services
            
        except ET.ParseError as e:
            raise ParserError(f"Failed to parse nmap XML: {e}")
        except Exception as e:
            raise ParserError(f"Error parsing nmap output: {e}")

class CrackMapExecParser(BaseParser):
    """Parser for CrackMapExec output."""
    
    def parse_authentication_results(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse CME authentication results.
        
        Args:
            output: Raw CME output text
            
        Returns:
            List of authentication result dictionaries
        """
        results = []
        
        # Pattern for successful authentication
        success_pattern = r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+.*\[([+*])\]\s+(\S+\\?\S+):(\S*)'
        
        # Pattern for Pwn3d! results
        pwned_pattern = r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+.*\(Pwn3d!\)'
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Check for successful authentication
            match = re.search(success_pattern, line)
            if match:
                ip, hostname, status, username, password_hash = match.groups()
                
                # Determine access level
                access_level = 'ADMIN' if '(Pwn3d!)' in line else 'USER'
                
                result = {
                    'ip': ip,
                    'hostname': hostname,
                    'username': username,
                    'password_hash': password_hash if password_hash else None,
                    'access_level': access_level,
                    'success': status in ['+', '*']
                }
                results.append(result)
        
        self.logger.info(f"Parsed {len(results)} authentication results from CME output")
        return results
    
    def parse_sam_dump(self, output: str) -> List[Credential]:
        """
        Parse SAM dump output from CME.
        
        Args:
            output: Raw CME SAM dump output
            
        Returns:
            List of Credential objects
        """
        credentials = []
        
        # Pattern for SAM dump entries
        sam_pattern = r'(\S+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::'
        
        for match in re.finditer(sam_pattern, output):
            username, uid, lm_hash, nt_hash = match.groups()
            
            # Skip machine accounts and disabled accounts
            if username.endswith('$') or username in ['Guest', 'DefaultAccount']:
                continue
            
            credential = Credential(
                username=username,
                hash_value=f"{lm_hash}:{nt_hash}",
                hash_type="NTLM",
                source_tool="crackmapexec"
            )
            credentials.append(credential)
        
        self.logger.info(f"Parsed {len(credentials)} credentials from SAM dump")
        return credentials
    
    def parse_shares(self, output: str) -> List[Share]:
        """
        Parse share enumeration output from CME.
        
        Args:
            output: Raw CME shares output
            
        Returns:
            List of Share objects
        """
        shares = []
        
        # Pattern for share listings
        share_pattern = r'SMB\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\S+\s+\[([+*])\]\s+Enumerated shares'
        share_detail_pattern = r'(\S+)\s+(READ|WRITE|READ,WRITE|NO ACCESS)\s*(.*)'
        
        lines = output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Look for share enumeration start
            if 'Enumerated shares' in line:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_host = ip_match.group(1)
                continue
            
            # Parse individual share details
            if current_host and line:
                match = re.match(share_detail_pattern, line)
                if match:
                    share_name, permissions, comment = match.groups()
                    
                    share = Share(
                        host_id=0,  # Will be set when inserted
                        share_name=share_name,
                        permissions=permissions,
                        comment=comment.strip() if comment else None
                    )
                    shares.append((current_host, share))
        
        self.logger.info(f"Parsed {len(shares)} shares from CME output")
        return shares

class ImpacketParser(BaseParser):
    """Parser for Impacket tools output."""
    
    def parse_secretsdump(self, output: str) -> List[Credential]:
        """
        Parse secretsdump.py output for credentials.
        
        Args:
            output: Raw secretsdump output
            
        Returns:
            List of Credential objects
        """
        credentials = []
        
        # Patterns for different credential types
        ntds_pattern = r'(\S+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::'
        kerberos_pattern = r'(\S+):(\$krb5\$\d+\$\S+)'
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse NTDS hashes
            ntds_match = re.match(ntds_pattern, line)
            if ntds_match:
                username, uid, lm_hash, nt_hash = ntds_match.groups()
                
                # Extract domain if present
                domain = None
                if '\\' in username:
                    domain, username = username.split('\\', 1)
                
                credential = Credential(
                    username=username,
                    domain=domain,
                    hash_value=f"{lm_hash}:{nt_hash}",
                    hash_type="NTLM",
                    source_tool="secretsdump"
                )
                credentials.append(credential)
            
            # Parse Kerberos tickets
            kerberos_match = re.match(kerberos_pattern, line)
            if kerberos_match:
                username, ticket = kerberos_match.groups()
                
                credential = Credential(
                    username=username,
                    hash_value=ticket,
                    hash_type="Kerberos",
                    source_tool="secretsdump"
                )
                credentials.append(credential)
        
        self.logger.info(f"Parsed {len(credentials)} credentials from secretsdump output")
        return credentials
    
    def parse_getuserspns(self, output: str) -> List[Credential]:
        """
        Parse GetUserSPNs.py output for Kerberoastable hashes.
        
        Args:
            output: Raw GetUserSPNs output
            
        Returns:
            List of Credential objects
        """
        credentials = []
        
        # Pattern for Kerberos TGS hashes
        tgs_pattern = r'\$krb5tgs\$\d+\$\*([^*]+)\*\$([a-fA-F0-9]+)'
        
        for match in re.finditer(tgs_pattern, output):
            username_info, hash_data = match.groups()
            
            # Extract username from the info
            username = username_info.split('$')[0] if '$' in username_info else username_info
            
            # Full TGS hash
            full_hash = match.group(0)
            
            credential = Credential(
                username=username,
                hash_value=full_hash,
                hash_type="Kerberos-TGS",
                source_tool="GetUserSPNs"
            )
            credentials.append(credential)
        
        self.logger.info(f"Parsed {len(credentials)} Kerberoastable hashes")
        return credentials

class ResponderParser(BaseParser):
    """Parser for Responder tool output."""
    
    def parse_log_file(self, log_content: str) -> List[Credential]:
        """
        Parse Responder log files for captured hashes.
        
        Args:
            log_content: Content of Responder log file
            
        Returns:
            List of Credential objects
        """
        credentials = []
        
        # Patterns for different hash types captured by Responder
        ntlmv2_pattern = r'(\S+)::(\S+):([a-fA-F0-9]{16}):([a-fA-F0-9]{32}):([a-fA-F0-9]+)'
        ntlmv1_pattern = r'(\S+)::(\S+):([a-fA-F0-9]{48}):([a-fA-F0-9]{48})'
        
        lines = log_content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse NTLMv2 hashes
            ntlmv2_match = re.search(ntlmv2_pattern, line)
            if ntlmv2_match:
                username, domain, challenge, response, blob = ntlmv2_match.groups()
                
                # Reconstruct full NTLMv2 hash
                full_hash = f"{username}::{domain}:{challenge}:{response}:{blob}"
                
                credential = Credential(
                    username=username,
                    domain=domain,
                    hash_value=full_hash,
                    hash_type="NTLMv2",
                    source_tool="responder"
                )
                credentials.append(credential)
            
            # Parse NTLMv1 hashes
            ntlmv1_match = re.search(ntlmv1_pattern, line)
            if ntlmv1_match:
                username, domain, response1, response2 = ntlmv1_match.groups()
                
                full_hash = f"{username}::{domain}:{response1}:{response2}"
                
                credential = Credential(
                    username=username,
                    domain=domain,
                    hash_value=full_hash,
                    hash_type="NTLMv1",
                    source_tool="responder"
                )
                credentials.append(credential)
        
        self.logger.info(f"Parsed {len(credentials)} credentials from Responder logs")
        return credentials

class CertipyParser(BaseParser):
    """Parser for Certipy tool output."""
    
    def parse_find_output(self, output: str) -> List[Vulnerability]:
        """
        Parse Certipy find command output for AD CS vulnerabilities.
        
        Args:
            output: Raw Certipy find output
            
        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []
        
        # Patterns for different ESC vulnerabilities
        esc_patterns = {
            'ESC1': r'ESC1.*Template Name.*:\s*(\S+)',
            'ESC2': r'ESC2.*Template Name.*:\s*(\S+)',
            'ESC3': r'ESC3.*Template Name.*:\s*(\S+)',
            'ESC4': r'ESC4.*Template Name.*:\s*(\S+)',
            'ESC8': r'ESC8.*CA Name.*:\s*(\S+)'
        }
        
        lines = output.split('\n')
        current_ca = None
        
        for line in lines:
            line = line.strip()
            
            # Extract CA information
            ca_match = re.search(r'CA Name.*:\s*(\S+)', line)
            if ca_match:
                current_ca = ca_match.group(1)
                continue
            
            # Check for ESC vulnerabilities
            for vuln_type, pattern in esc_patterns.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    template_or_ca = match.group(1)
                    
                    vuln = Vulnerability(
                        host_id=0,  # Will be set when linked to CA host
                        vuln_name=vuln_type,
                        description=f"AD CS vulnerability in template/CA: {template_or_ca}",
                        source_tool="certipy"
                    )
                    vulnerabilities.append((current_ca, vuln))
        
        self.logger.info(f"Parsed {len(vulnerabilities)} AD CS vulnerabilities")
        return vulnerabilities
    
    def parse_auth_output(self, output: str) -> Optional[Credential]:
        """
        Parse Certipy auth command output for obtained credentials.
        
        Args:
            output: Raw Certipy auth output
            
        Returns:
            Credential object if successful
        """
        # Pattern for extracted hash
        hash_pattern = r'Hash.*:\s*([a-fA-F0-9]{32})'
        # Pattern for username
        user_pattern = r'Username.*:\s*(\S+)'
        # Pattern for domain
        domain_pattern = r'Domain.*:\s*(\S+)'
        
        hash_match = re.search(hash_pattern, output)
        user_match = re.search(user_pattern, output)
        domain_match = re.search(domain_pattern, output)
        
        if hash_match and user_match:
            credential = Credential(
                username=user_match.group(1),
                domain=domain_match.group(1) if domain_match else None,
                hash_value=hash_match.group(1),
                hash_type="NTLM",
                source_tool="certipy"
            )
            
            self.logger.info(f"Parsed credential for {credential.username} from Certipy auth")
            return credential
        
        return None

class DNSParser(BaseParser):
    """Parser for DNS enumeration output."""
    
    def parse_zone_transfer(self, output: str) -> List[Host]:
        """
        Parse DNS zone transfer output for host discovery.
        
        Args:
            output: Raw DNS zone transfer output
            
        Returns:
            List of Host objects
        """
        hosts = []
        
        # Pattern for A records
        a_record_pattern = r'(\S+)\.\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)'
        
        for match in re.finditer(a_record_pattern, output):
            hostname, ip = match.groups()
            
            # Validate IP address
            try:
                ip_address(ip)
                
                host = Host(
                    ip_address=ip,
                    hostname=hostname
                )
                hosts.append(host)
                
            except AddressValueError:
                continue
        
        self.logger.info(f"Parsed {len(hosts)} hosts from DNS zone transfer")
        return hosts

class KerbruteParser(BaseParser):
    """Parser for kerbrute output."""
    
    def parse_spray_output(self, output: str, domain: str) -> List[Credential]:
        """
        Parse kerbrute password spray output for successful credentials.
        
        Args:
            output: Raw kerbrute output
            domain: Domain name
            
        Returns:
            List of successful credentials
        """
        credentials = []
        
        # Look for successful authentication lines in kerbrute output
        success_pattern = r'\[VALID\]\s+(\S+)@\S+:(\S+)'
        
        for match in re.finditer(success_pattern, output):
            username, password = match.groups()
            
            credential = Credential(
                username=username,
                domain=domain,
                password=password,
                source_tool='kerbrute'
            )
            
            credentials.append(credential)
            self.logger.info(f"Parsed successful kerbrute credential: {domain}\\{username}")
        
        return credentials

class LDAPParser(BaseParser):
    """Parser for LDAP enumeration output."""
    
    def parse_ldapsearch_users(self, output: str) -> List[User]:
        """
        Parse ldapsearch output for user enumeration.
        
        Args:
            output: Raw ldapsearch output
            
        Returns:
            List of User objects
        """
        users = []
        current_user = {}
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('dn:') and 'CN=' in line:
                # Start of new user entry
                if current_user:
                    user = self._create_user_from_ldap_data(current_user)
                    if user:
                        users.append(user)
                current_user = {}
                continue
            
            # Parse attributes
            if ':' in line and current_user is not None:
                attr, value = line.split(':', 1)
                attr = attr.strip().lower()
                value = value.strip()
                
                if attr == 'samaccountname':
                    current_user['username'] = value
                elif attr == 'userprincipalname':
                    if '@' in value:
                        username, domain = value.split('@', 1)
                        current_user['domain'] = domain
                elif attr == 'description':
                    current_user['description'] = value
                elif attr == 'useraccountcontrol':
                    # Check if account is enabled
                    uac = int(value) if value.isdigit() else 0
                    current_user['is_enabled'] = not bool(uac & 0x02)  # ACCOUNTDISABLE flag
        
        # Handle last user
        if current_user:
            user = self._create_user_from_ldap_data(current_user)
            if user:
                users.append(user)
        
        self.logger.info(f"Parsed {len(users)} users from LDAP search")
        return users
    
    def _create_user_from_ldap_data(self, user_data: Dict[str, Any]) -> Optional[User]:
        """Create User object from parsed LDAP data."""
        username = user_data.get('username')
        if not username:
            return None
        
        return User(
            username=username,
            domain=user_data.get('domain'),
            description=user_data.get('description'),
            is_enabled=user_data.get('is_enabled', True)
        )

class SMBParser(BaseParser):
    """Parser for SMB enumeration output."""
    
    def parse_enum4linux_output(self, output: str) -> Tuple[List[User], List[Share]]:
        """
        Parse enum4linux-ng output for users and shares.
        
        Args:
            output: Raw enum4linux-ng output
            
        Returns:
            Tuple of (users, shares) lists
        """
        users = []
        shares = []
        
        lines = output.split('\n')
        
        in_users_section = False
        in_shares_section = False
        
        for line in lines:
            line = line.strip()
            
            # Detect sections
            if 'Users via RID cycling' in line or 'Users via SAMR' in line:
                in_users_section = True
                in_shares_section = False
                continue
            elif 'Shares via RPC' in line or 'Share Enumeration' in line:
                in_users_section = False
                in_shares_section = True
                continue
            elif line.startswith('=') or not line:
                in_users_section = False
                in_shares_section = False
                continue
            
            # Parse users
            if in_users_section:
                user_match = re.search(r'(\S+)\s+\(Local User\)', line)
                if user_match:
                    username = user_match.group(1)
                    user = User(username=username)
                    users.append(user)
            
            # Parse shares
            if in_shares_section:
                share_match = re.search(r'(\S+)\s+(Disk|IPC|Printer)\s*(.*)', line)
                if share_match:
                    share_name, share_type, comment = share_match.groups()
                    
                    share = Share(
                        host_id=0,  # Will be set when inserted
                        share_name=share_name,
                        comment=comment.strip() if comment else None
                    )
                    shares.append(share)
        
        self.logger.info(f"Parsed {len(users)} users and {len(shares)} shares from enum4linux")
        return users, shares

# Factory function to get appropriate parser
def get_parser(tool_name: str) -> BaseParser:
    """
    Get the appropriate parser for a given tool.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Parser instance
        
    Raises:
        ValueError: If no parser is available for the tool
    """
    parsers = {
        'nmap': NmapParser,
        'crackmapexec': CrackMapExecParser,
        'secretsdump': ImpacketParser,
        'getuserspns': ImpacketParser,
        'responder': ResponderParser,
        'certipy': CertipyParser,
        'ldapsearch': LDAPParser,
        'enum4linux': SMBParser,
        'dns': DNSParser,
        'kerbrute': KerbruteParser
    }
    
    parser_class = parsers.get(tool_name.lower())
    if not parser_class:
        raise ValueError(f"No parser available for tool: {tool_name}")
    
    return parser_class() 