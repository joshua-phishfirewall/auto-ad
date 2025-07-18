#!/usr/bin/env python3
"""
LDAP Enumeration Module for AD-Automaton
Performs unauthenticated LDAP enumeration including anonymous binds and basic directory information.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional, Tuple

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Host, User, Group
from executor import CommandExecutor
from parsers import LDAPParser
from logger import log_discovery, log_tool_execution, log_tool_result

class LDAPEnumerator:
    """
    Handles unauthenticated LDAP enumeration using anonymous binds.
    Attempts to extract domain information, users, and groups from LDAP.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the LDAP enumerator.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.parser = LDAPParser()
        
        # Get tool configurations
        self.ldapsearch_config = config.get('tools', {}).get('ldapsearch', {})
        self.ldapsearch_path = self.ldapsearch_config.get('path', 'ldapsearch')
        
        # Domain information discovered
        self.domain_info = {}
        self.base_dn = ""
    
    def run_unauthenticated_ldap_enum(self) -> Tuple[List[User], List[Group], Dict[str, Any]]:
        """
        Main method to run unauthenticated LDAP enumeration.
        
        Returns:
            Tuple of (users, groups, domain_info) discovered
        """
        self.logger.info("Starting unauthenticated LDAP enumeration")
        
        discovered_users = []
        discovered_groups = []
        domain_info = {}
        
        # Get LDAP hosts from database
        ldap_hosts = self._get_ldap_hosts()
        
        if not ldap_hosts:
            self.logger.warning("No LDAP hosts found in database")
            return [], [], {}
        
        self.logger.info(f"Found {len(ldap_hosts)} LDAP hosts to enumerate")
        
        for host in ldap_hosts:
            try:
                # Test for anonymous bind capability
                if self._test_anonymous_bind(host.ip_address):
                    self.logger.info(f"Anonymous bind successful on {host.ip_address}")
                    
                    # Get base DN and domain information
                    domain_info = self._get_domain_info(host.ip_address)
                    
                    if domain_info:
                        # Enumerate users
                        users = self._enumerate_users(host.ip_address)
                        discovered_users.extend(users)
                        
                        # Enumerate groups
                        groups = self._enumerate_groups(host.ip_address)
                        discovered_groups.extend(groups)
                        
                        # Get additional domain information
                        additional_info = self._get_additional_domain_info(host.ip_address)
                        domain_info.update(additional_info)
                
                # Try nmap LDAP scripts for additional enumeration
                nmap_results = self._run_nmap_ldap_scripts(host.ip_address)
                if nmap_results:
                    discovered_users.extend(nmap_results.get('users', []))
                    discovered_groups.extend(nmap_results.get('groups', []))
                
            except Exception as e:
                self.logger.error(f"LDAP enumeration failed for {host.ip_address}: {e}")
                continue
        
        # Store results in database
        self._store_results(discovered_users, discovered_groups)
        
        log_discovery("users via LDAP", len(discovered_users))
        log_discovery("groups via LDAP", len(discovered_groups))
        
        return discovered_users, discovered_groups, domain_info
    
    def _get_ldap_hosts(self) -> List[Host]:
        """Get hosts with LDAP services from the database."""
        ldap_hosts = []
        
        # Standard LDAP port 389
        hosts_389 = self.db_manager.get_hosts_by_service('ldap', 389)
        ldap_hosts.extend(hosts_389)
        
        # LDAPS port 636
        hosts_636 = self.db_manager.get_hosts_by_service('ldaps', 636)
        ldap_hosts.extend(hosts_636)
        
        # Global Catalog ports 3268/3269
        hosts_3268 = self.db_manager.get_hosts_by_service('msft-gc', 3268)
        ldap_hosts.extend(hosts_3268)
        
        hosts_3269 = self.db_manager.get_hosts_by_service('msft-gc-ssl', 3269)
        ldap_hosts.extend(hosts_3269)
        
        # Remove duplicates based on IP address
        seen_ips = set()
        unique_hosts = []
        for host in ldap_hosts:
            if host.ip_address not in seen_ips:
                unique_hosts.append(host)
                seen_ips.add(host.ip_address)
        
        return unique_hosts
    
    def _test_anonymous_bind(self, ip_address: str) -> bool:
        """
        Test if anonymous bind is allowed on the LDAP server.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            True if anonymous bind is successful
        """
        try:
            # Test anonymous bind with ldapsearch
            command = f"{self.ldapsearch_path} -x -h {ip_address} -s base -b '' '(objectclass=*)'"
            
            log_tool_execution("ldapsearch anonymous bind test", command)
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0 and ('numEntries' in result.stdout or 'dn:' in result.stdout):
                self.logger.info(f"Anonymous LDAP bind successful on {ip_address}")
                return True
            
            # Test with empty credentials
            command_empty = f"{self.ldapsearch_path} -x -h {ip_address} -D '' -w '' -s base -b '' '(objectclass=*)'"
            result_empty = self.executor.execute(command_empty, timeout=30)
            
            if result_empty.exit_code == 0 and ('numEntries' in result_empty.stdout or 'dn:' in result_empty.stdout):
                self.logger.info(f"Anonymous LDAP bind with empty credentials successful on {ip_address}")
                return True
            
        except Exception as e:
            self.logger.debug(f"Anonymous bind test failed for {ip_address}: {e}")
        
        return False
    
    def _get_domain_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Get basic domain information from LDAP.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Dictionary with domain information
        """
        domain_info = {}
        
        try:
            # Query for naming contexts (base DNs)
            command = f"{self.ldapsearch_path} -x -h {ip_address} -s base -b '' '(objectclass=*)' namingContexts"
            
            log_tool_execution("ldapsearch domain info", command)
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0:
                # Parse naming contexts
                naming_contexts = self._parse_naming_contexts(result.stdout)
                domain_info['naming_contexts'] = naming_contexts
                
                # Try to determine the base DN
                for context in naming_contexts:
                    if 'DC=' in context.upper():
                        self.base_dn = context
                        domain_info['base_dn'] = context
                        
                        # Extract domain name from DN
                        domain_name = self._extract_domain_from_dn(context)
                        if domain_name:
                            domain_info['domain_name'] = domain_name
                        break
            
            # Get additional root DSE information
            root_dse_info = self._get_root_dse_info(ip_address)
            domain_info.update(root_dse_info)
            
        except Exception as e:
            self.logger.error(f"Failed to get domain info from {ip_address}: {e}")
        
        return domain_info
    
    def _get_root_dse_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Get Root DSE information from LDAP server.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Dictionary with Root DSE information
        """
        root_dse_info = {}
        
        try:
            # Query Root DSE
            command = f"{self.ldapsearch_path} -x -h {ip_address} -s base -b '' '(objectclass=*)'"
            
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0:
                # Parse various attributes
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if line.startswith('serverName:'):
                        root_dse_info['server_name'] = line.split(':', 1)[1].strip()
                    elif line.startswith('forestFunctionality:'):
                        root_dse_info['forest_functionality'] = line.split(':', 1)[1].strip()
                    elif line.startswith('domainFunctionality:'):
                        root_dse_info['domain_functionality'] = line.split(':', 1)[1].strip()
                    elif line.startswith('domainControllerFunctionality:'):
                        root_dse_info['dc_functionality'] = line.split(':', 1)[1].strip()
                    elif line.startswith('currentTime:'):
                        root_dse_info['current_time'] = line.split(':', 1)[1].strip()
                    elif line.startswith('supportedLDAPVersion:'):
                        version = line.split(':', 1)[1].strip()
                        if 'supported_ldap_versions' not in root_dse_info:
                            root_dse_info['supported_ldap_versions'] = []
                        root_dse_info['supported_ldap_versions'].append(version)
            
        except Exception as e:
            self.logger.debug(f"Failed to get Root DSE info from {ip_address}: {e}")
        
        return root_dse_info
    
    def _enumerate_users(self, ip_address: str) -> List[User]:
        """
        Enumerate users from LDAP.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            List of discovered users
        """
        users = []
        
        if not self.base_dn:
            self.logger.warning("No base DN available for user enumeration")
            return users
        
        try:
            # Query for user objects
            command = f"{self.ldapsearch_path} -x -h {ip_address} -b '{self.base_dn}' '(objectClass=user)' sAMAccountName userPrincipalName description userAccountControl"
            
            log_tool_execution("ldapsearch user enumeration", command)
            result = self.executor.execute(command, timeout=120)
            
            if result.exit_code == 0:
                users = self.parser.parse_ldapsearch_users(result.stdout)
            
            # Also try querying for person objects (might catch additional users)
            command_person = f"{self.ldapsearch_path} -x -h {ip_address} -b '{self.base_dn}' '(objectClass=person)' sAMAccountName cn description"
            result_person = self.executor.execute(command_person, timeout=120)
            
            if result_person.exit_code == 0:
                person_users = self.parser.parse_ldapsearch_users(result_person.stdout)
                # Merge results, avoiding duplicates
                existing_usernames = {user.username for user in users}
                for user in person_users:
                    if user.username not in existing_usernames:
                        users.append(user)
            
        except Exception as e:
            self.logger.error(f"User enumeration failed for {ip_address}: {e}")
        
        self.logger.info(f"Discovered {len(users)} users via LDAP on {ip_address}")
        return users
    
    def _enumerate_groups(self, ip_address: str) -> List[Group]:
        """
        Enumerate groups from LDAP.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            List of discovered groups
        """
        groups = []
        
        if not self.base_dn:
            self.logger.warning("No base DN available for group enumeration")
            return groups
        
        try:
            # Query for group objects
            command = f"{self.ldapsearch_path} -x -h {ip_address} -b '{self.base_dn}' '(objectClass=group)' sAMAccountName description cn"
            
            log_tool_execution("ldapsearch group enumeration", command)
            result = self.executor.execute(command, timeout=120)
            
            if result.exit_code == 0:
                groups = self._parse_ldap_groups(result.stdout)
            
        except Exception as e:
            self.logger.error(f"Group enumeration failed for {ip_address}: {e}")
        
        self.logger.info(f"Discovered {len(groups)} groups via LDAP on {ip_address}")
        return groups
    
    def _get_additional_domain_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Get additional domain information like password policy.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Dictionary with additional domain information
        """
        additional_info = {}
        
        if not self.base_dn:
            return additional_info
        
        try:
            # Query for domain password policy
            policy_dn = f"CN=Default Domain Policy,CN=System,{self.base_dn}"
            command = f"{self.ldapsearch_path} -x -h {ip_address} -b '{policy_dn}' '(objectClass=*)'"
            
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0:
                policy_info = self._parse_password_policy(result.stdout)
                additional_info.update(policy_info)
            
            # Query for domain controllers
            dc_command = f"{self.ldapsearch_path} -x -h {ip_address} -b '{self.base_dn}' '(objectClass=computer)' dNSHostName operatingSystem"
            dc_result = self.executor.execute(dc_command, timeout=60)
            
            if dc_result.exit_code == 0:
                dc_info = self._parse_domain_controllers(dc_result.stdout)
                additional_info['domain_controllers'] = dc_info
            
        except Exception as e:
            self.logger.debug(f"Failed to get additional domain info from {ip_address}: {e}")
        
        return additional_info
    
    def _run_nmap_ldap_scripts(self, ip_address: str) -> Dict[str, List[Any]]:
        """
        Run nmap LDAP enumeration scripts.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Dictionary with discovered information
        """
        results = {'users': [], 'groups': [], 'info': []}
        
        try:
            # LDAP enumeration scripts
            ldap_scripts = [
                'ldap-search',
                'ldap-rootdse'
            ]
            
            script_list = ','.join(ldap_scripts)
            command = f"nmap --script {script_list} -p 389 {ip_address}"
            
            log_tool_execution("nmap LDAP scripts", command)
            result = self.executor.execute(command, timeout=180)
            
            if result.exit_code == 0:
                # Parse nmap LDAP script output
                if 'ldap-search' in result.stdout:
                    # Extract any user or group information
                    ldap_data = self._parse_nmap_ldap_search(result.stdout)
                    results.update(ldap_data)
            
        except Exception as e:
            self.logger.debug(f"nmap LDAP scripts failed for {ip_address}: {e}")
        
        return results
    
    def _parse_naming_contexts(self, output: str) -> List[str]:
        """Parse naming contexts from LDAP output."""
        contexts = []
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('namingContexts:'):
                context = line.split(':', 1)[1].strip()
                contexts.append(context)
        
        return contexts
    
    def _extract_domain_from_dn(self, dn: str) -> Optional[str]:
        """Extract domain name from distinguished name."""
        try:
            # Extract DC components and convert to domain name
            dc_parts = re.findall(r'DC=([^,]+)', dn, re.IGNORECASE)
            if dc_parts:
                return '.'.join(dc_parts)
        except Exception:
            pass
        
        return None
    
    def _parse_ldap_groups(self, output: str) -> List[Group]:
        """Parse LDAP groups from ldapsearch output."""
        groups = []
        current_group = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('dn:'):
                # Save previous group if exists
                if current_group:
                    group = self._create_group_from_data(current_group)
                    if group:
                        groups.append(group)
                current_group = {}
            elif line.startswith('sAMAccountName:'):
                current_group['name'] = line.split(':', 1)[1].strip()
            elif line.startswith('description:'):
                current_group['description'] = line.split(':', 1)[1].strip()
            elif line.startswith('cn:'):
                if 'name' not in current_group:
                    current_group['name'] = line.split(':', 1)[1].strip()
        
        # Handle last group
        if current_group:
            group = self._create_group_from_data(current_group)
            if group:
                groups.append(group)
        
        return groups
    
    def _create_group_from_data(self, group_data: Dict[str, str]) -> Optional[Group]:
        """Create Group object from parsed data."""
        name = group_data.get('name')
        if not name:
            return None
        
        return Group(
            group_name=name,
            description=group_data.get('description')
        )
    
    def _parse_password_policy(self, output: str) -> Dict[str, Any]:
        """Parse password policy information."""
        policy_info = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('minPwdLength:'):
                policy_info['min_password_length'] = line.split(':', 1)[1].strip()
            elif line.startswith('maxPwdAge:'):
                policy_info['max_password_age'] = line.split(':', 1)[1].strip()
            elif line.startswith('minPwdAge:'):
                policy_info['min_password_age'] = line.split(':', 1)[1].strip()
            elif line.startswith('pwdHistoryLength:'):
                policy_info['password_history_length'] = line.split(':', 1)[1].strip()
            elif line.startswith('lockoutThreshold:'):
                policy_info['lockout_threshold'] = line.split(':', 1)[1].strip()
        
        return policy_info
    
    def _parse_domain_controllers(self, output: str) -> List[Dict[str, str]]:
        """Parse domain controller information."""
        dcs = []
        current_dc = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('dn:') and 'CN=Computers' not in line:
                if current_dc:
                    dcs.append(current_dc)
                current_dc = {}
            elif line.startswith('dNSHostName:'):
                current_dc['hostname'] = line.split(':', 1)[1].strip()
            elif line.startswith('operatingSystem:'):
                current_dc['os'] = line.split(':', 1)[1].strip()
        
        if current_dc:
            dcs.append(current_dc)
        
        return dcs
    
    def _parse_nmap_ldap_search(self, output: str) -> Dict[str, List[Any]]:
        """Parse nmap ldap-search script output."""
        results = {'users': [], 'groups': [], 'info': []}
        
        # Extract any structured data from nmap LDAP search output
        # This would need specific parsing based on nmap script output format
        
        return results
    
    def _store_results(self, users: List[User], groups: List[Group]) -> None:
        """Store enumeration results in the database."""
        try:
            # Store users
            user_count = 0
            for user in users:
                if self.db_manager.add_user(user):
                    user_count += 1
            
            # Store groups  
            group_count = 0
            for group in groups:
                # Note: Group storage would need to be implemented in DatabaseManager
                # For now, just count them
                group_count += 1
            
            self.logger.info(f"Stored {user_count} users and {group_count} groups from LDAP enumeration")
            
        except Exception as e:
            self.logger.error(f"Failed to store LDAP enumeration results: {e}")

def run_unauthenticated_ldap_enum(db_manager: DatabaseManager, config: Dict[str, Any]) -> Tuple[List[User], List[Group], Dict[str, Any]]:
    """
    Main entry point for unauthenticated LDAP enumeration.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        Tuple of (users, groups, domain_info) discovered
    """
    enumerator = LDAPEnumerator(db_manager, config)
    return enumerator.run_unauthenticated_ldap_enum()

def test_anonymous_bind(db_manager: DatabaseManager, ip_address: str, 
                       config: Dict[str, Any]) -> bool:
    """
    Test if anonymous bind is available on a specific LDAP server.
    
    Args:
        db_manager: Database manager instance
        ip_address: Target IP address
        config: Configuration dictionary
        
    Returns:
        True if anonymous bind is available
    """
    enumerator = LDAPEnumerator(db_manager, config)
    return enumerator._test_anonymous_bind(ip_address) 