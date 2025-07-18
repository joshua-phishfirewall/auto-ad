#!/usr/bin/env python3
"""
SMB Enumeration Module for AD-Automaton
Performs unauthenticated SMB enumeration including null sessions, share discovery, and user enumeration.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional, Tuple

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Host, User, Share
from executor import CommandExecutor
from parsers import SMBParser, CrackMapExecParser
from logger import log_discovery, log_tool_execution, log_tool_result

class SMBEnumerator:
    """
    Handles unauthenticated SMB enumeration using various techniques.
    Implements null session enumeration, share discovery, and user enumeration.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the SMB enumerator.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.smb_parser = SMBParser()
        self.cme_parser = CrackMapExecParser()
        
        # Get tool configurations
        self.smbclient_config = config.get('tools', {}).get('smbclient', {})
        self.enum4linux_config = config.get('tools', {}).get('enum4linux_ng', {})
        self.cme_config = config.get('tools', {}).get('crackmapexec', {})
        
        self.smbclient_path = self.smbclient_config.get('path', 'smbclient')
        self.enum4linux_path = self.enum4linux_config.get('path', 'enum4linux-ng')
        self.cme_path = self.cme_config.get('path', 'crackmapexec')
        
        # OPSEC settings
        self.opsec_profile = config.get('opsec_profile', 'normal')
        self.enumeration_method = config.get('features', {}).get('smb_enumeration_method', 'auto')
    
    def run_unauthenticated_smb_enum(self) -> Tuple[List[User], List[Share]]:
        """
        Main method to run unauthenticated SMB enumeration.
        
        Returns:
            Tuple of (users, shares) discovered
        """
        self.logger.info("Starting unauthenticated SMB enumeration")
        
        discovered_users = []
        discovered_shares = []
        
        # Get SMB hosts from database
        smb_hosts = self._get_smb_hosts()
        
        if not smb_hosts:
            self.logger.warning("No SMB hosts found in database")
            return [], []
        
        self.logger.info(f"Found {len(smb_hosts)} SMB hosts to enumerate")
        
        for host in smb_hosts:
            try:
                # Test for null session capability
                if self._test_null_session(host.ip_address):
                    self.logger.info(f"Null session available on {host.ip_address}")
                    
                    # Enumerate shares
                    shares = self._enumerate_shares(host.ip_address)
                    if shares:
                        discovered_shares.extend([(host, share) for share in shares])
                    
                    # Enumerate users based on OPSEC profile
                    users = self._enumerate_users(host.ip_address)
                    if users:
                        discovered_users.extend(users)
                
                # Try enum4linux-ng for comprehensive enumeration
                if self._should_use_enum4linux():
                    enum_users, enum_shares = self._run_enum4linux(host.ip_address)
                    discovered_users.extend(enum_users)
                    discovered_shares.extend([(host, share) for share in enum_shares])
                
                # Use nmap scripts for additional enumeration
                nmap_results = self._run_nmap_smb_scripts(host.ip_address)
                discovered_users.extend(nmap_results.get('users', []))
                
            except Exception as e:
                self.logger.error(f"SMB enumeration failed for {host.ip_address}: {e}")
                continue
        
        # Store results in database
        self._store_results(discovered_users, discovered_shares)
        
        log_discovery("users via SMB", len(discovered_users))
        log_discovery("shares via SMB", len(discovered_shares))
        
        return discovered_users, discovered_shares
    
    def _get_smb_hosts(self) -> List[Host]:
        """Get hosts with SMB services from the database."""
        # Look for SMB on standard ports
        smb_hosts = []
        
        # Port 445 (Microsoft-DS)
        hosts_445 = self.db_manager.get_hosts_by_service('microsoft-ds', 445)
        smb_hosts.extend(hosts_445)
        
        # Port 139 (NetBIOS-SSN)
        hosts_139 = self.db_manager.get_hosts_by_service('netbios-ssn', 139)
        smb_hosts.extend(hosts_139)
        
        # Remove duplicates based on IP address
        seen_ips = set()
        unique_hosts = []
        for host in smb_hosts:
            if host.ip_address not in seen_ips:
                unique_hosts.append(host)
                seen_ips.add(host.ip_address)
        
        return unique_hosts
    
    def _test_null_session(self, ip_address: str) -> bool:
        """
        Test if null session is available on the target.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            True if null session is available
        """
        try:
            # Test with smbclient
            command = f"{self.smbclient_path} -L \\\\{ip_address} -N"
            
            log_tool_execution("smbclient null session test", command)
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0 and 'Sharename' in result.stdout:
                self.logger.info(f"Null session successful on {ip_address}")
                return True
            
            # Test with crackmapexec if available
            if self._tool_available('crackmapexec'):
                cme_command = f"{self.cme_path} smb {ip_address} -u '' -p ''"
                cme_result = self.executor.execute(cme_command, timeout=30)
                
                if cme_result.exit_code == 0 and '[+]' in cme_result.stdout:
                    self.logger.info(f"Null session confirmed via CME on {ip_address}")
                    return True
            
        except Exception as e:
            self.logger.debug(f"Null session test failed for {ip_address}: {e}")
        
        return False
    
    def _enumerate_shares(self, ip_address: str) -> List[Share]:
        """
        Enumerate SMB shares on the target.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            List of discovered shares
        """
        shares = []
        
        try:
            # Method 1: smbclient
            command = f"{self.smbclient_path} -L \\\\{ip_address} -N"
            
            log_tool_execution("smbclient share enumeration", command)
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0:
                shares.extend(self._parse_smbclient_shares(result.stdout))
            
            # Method 2: nmap SMB shares script
            nmap_command = f"nmap --script smb-enum-shares -p 445 {ip_address}"
            nmap_result = self.executor.execute(nmap_command, timeout=60)
            
            if nmap_result.exit_code == 0:
                nmap_shares = self._parse_nmap_smb_shares(nmap_result.stdout)
                shares.extend(nmap_shares)
            
            # Method 3: smbmap if available
            if self._tool_available('smbmap'):
                smbmap_command = f"smbmap -H {ip_address} -u null"
                smbmap_result = self.executor.execute(smbmap_command, timeout=30)
                
                if smbmap_result.exit_code == 0:
                    smbmap_shares = self._parse_smbmap_output(smbmap_result.stdout)
                    shares.extend(smbmap_shares)
            
        except Exception as e:
            self.logger.error(f"Share enumeration failed for {ip_address}: {e}")
        
        # Remove duplicates
        unique_shares = []
        seen_shares = set()
        for share in shares:
            share_key = (share.share_name, share.permissions)
            if share_key not in seen_shares:
                unique_shares.append(share)
                seen_shares.add(share_key)
        
        self.logger.info(f"Discovered {len(unique_shares)} shares on {ip_address}")
        return unique_shares
    
    def _enumerate_users(self, ip_address: str) -> List[User]:
        """
        Enumerate users based on OPSEC profile.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            List of discovered users
        """
        users = []
        
        if self.enumeration_method == 'samr_only' or self.opsec_profile == 'stealth':
            # Stealth mode: Use SAMR enumeration only
            users = self._enumerate_users_samr(ip_address)
        elif self.enumeration_method == 'lsa_brute' or self.opsec_profile == 'noisy':
            # Noisy mode: Use LSA brute force
            users = self._enumerate_users_lsa_brute(ip_address)
        else:
            # Auto mode: Try SAMR first, fall back to LSA if needed
            users = self._enumerate_users_samr(ip_address)
            if not users and self.opsec_profile != 'stealth':
                users = self._enumerate_users_lsa_brute(ip_address)
        
        return users
    
    def _enumerate_users_samr(self, ip_address: str) -> List[User]:
        """
        Enumerate users using SAMR (quiet method).
        
        Args:
            ip_address: Target IP address
            
        Returns:
            List of discovered users
        """
        users = []
        
        try:
            # Use nmap smb-enum-users script with samronly
            command = f"nmap --script smb-enum-users --script-args samronly=1 -p 445 {ip_address}"
            
            log_tool_execution("nmap SAMR user enumeration", command)
            result = self.executor.execute(command, timeout=120)
            
            if result.exit_code == 0:
                users = self._parse_nmap_users(result.stdout)
            
        except Exception as e:
            self.logger.debug(f"SAMR user enumeration failed for {ip_address}: {e}")
        
        return users
    
    def _enumerate_users_lsa_brute(self, ip_address: str) -> List[User]:
        """
        Enumerate users using LSA brute force (noisy method).
        
        Args:
            ip_address: Target IP address
            
        Returns:
            List of discovered users
        """
        users = []
        
        # Warn about noisy operation
        self.logger.warning(f"Using noisy LSA brute force enumeration on {ip_address}")
        
        try:
            # Use nmap smb-enum-users script with lsaonly
            command = f"nmap --script smb-enum-users --script-args lsaonly=1 -p 445 {ip_address}"
            
            log_tool_execution("nmap LSA user enumeration", command)
            result = self.executor.execute(command, timeout=300)  # Longer timeout for brute force
            
            if result.exit_code == 0:
                users = self._parse_nmap_users(result.stdout)
            
        except Exception as e:
            self.logger.debug(f"LSA user enumeration failed for {ip_address}: {e}")
        
        return users
    
    def _run_enum4linux(self, ip_address: str) -> Tuple[List[User], List[Share]]:
        """
        Run enum4linux-ng for comprehensive enumeration.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Tuple of (users, shares) discovered
        """
        users = []
        shares = []
        
        try:
            # Run enum4linux-ng with appropriate options
            timeout = self.enum4linux_config.get('timeout', 120)
            command = f"{self.enum4linux_path} -A {ip_address}"
            
            log_tool_execution("enum4linux-ng", command)
            result = self.executor.execute(command, timeout=timeout)
            
            log_tool_result("enum4linux-ng", result.exit_code, 
                          len(result.stdout.splitlines()) if result.stdout else 0)
            
            if result.exit_code == 0:
                enum_users, enum_shares = self.smb_parser.parse_enum4linux_output(result.stdout)
                users.extend(enum_users)
                shares.extend(enum_shares)
            
        except Exception as e:
            self.logger.error(f"enum4linux-ng failed for {ip_address}: {e}")
        
        return users, shares
    
    def _run_nmap_smb_scripts(self, ip_address: str) -> Dict[str, List[Any]]:
        """
        Run comprehensive nmap SMB scripts.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Dictionary with discovered information
        """
        results = {'users': [], 'shares': [], 'info': []}
        
        try:
            # Comprehensive SMB enumeration script list
            smb_scripts = [
                'smb-enum-shares',
                'smb-enum-users',
                'smb-os-discovery',
                'smb-security-mode',
                'smb-server-stats',
                'smb-system-info'
            ]
            
            script_list = ','.join(smb_scripts)
            command = f"nmap --script {script_list} -p 445 {ip_address}"
            
            log_tool_execution("nmap SMB scripts", command)
            result = self.executor.execute(command, timeout=180)
            
            if result.exit_code == 0:
                # Parse various script outputs
                if 'smb-enum-users' in result.stdout:
                    users = self._parse_nmap_users(result.stdout)
                    results['users'].extend(users)
                
                if 'smb-enum-shares' in result.stdout:
                    shares = self._parse_nmap_smb_shares(result.stdout)
                    results['shares'].extend(shares)
            
        except Exception as e:
            self.logger.debug(f"nmap SMB scripts failed for {ip_address}: {e}")
        
        return results
    
    def _parse_smbclient_shares(self, output: str) -> List[Share]:
        """Parse smbclient share listing output."""
        shares = []
        
        lines = output.split('\n')
        in_share_section = False
        
        for line in lines:
            line = line.strip()
            
            if 'Sharename' in line and 'Type' in line:
                in_share_section = True
                continue
            
            if in_share_section and line.startswith('-'):
                in_share_section = False
                continue
            
            if in_share_section and line:
                # Parse share line format: "ShareName    Type    Comment"
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1]
                    comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                    
                    # Skip administrative shares in stealth mode
                    if self.opsec_profile == 'stealth' and share_name.endswith('$'):
                        continue
                    
                    share = Share(
                        host_id=0,  # Will be set when storing
                        share_name=share_name,
                        permissions='UNKNOWN',  # Will be determined later
                        comment=comment
                    )
                    shares.append(share)
        
        return shares
    
    def _parse_nmap_smb_shares(self, output: str) -> List[Share]:
        """Parse nmap smb-enum-shares output."""
        shares = []
        
        # Pattern for nmap share enumeration
        share_pattern = r'(\S+):\s*\n.*?Type:\s*(\S+).*?\n.*?Comment:\s*(.*?)\n'
        
        for match in re.finditer(share_pattern, output, re.DOTALL):
            share_name, share_type, comment = match.groups()
            
            share = Share(
                host_id=0,
                share_name=share_name,
                permissions='UNKNOWN',
                comment=comment.strip() if comment else None
            )
            shares.append(share)
        
        return shares
    
    def _parse_smbmap_output(self, output: str) -> List[Share]:
        """Parse smbmap output."""
        shares = []
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse smbmap format
            if 'READ' in line or 'WRITE' in line or 'NO ACCESS' in line:
                parts = line.split()
                if len(parts) >= 3:
                    share_name = parts[0]
                    permissions = parts[1]
                    comment = ' '.join(parts[2:])
                    
                    share = Share(
                        host_id=0,
                        share_name=share_name,
                        permissions=permissions,
                        comment=comment if comment else None
                    )
                    shares.append(share)
        
        return shares
    
    def _parse_nmap_users(self, output: str) -> List[User]:
        """Parse nmap smb-enum-users output."""
        users = []
        
        # Pattern for nmap user enumeration
        user_pattern = r'(\S+)\s+\(Local User\)|(\S+)\s+\(Domain User\)'
        
        for match in re.finditer(user_pattern, output):
            username = match.group(1) or match.group(2)
            
            if username:
                user = User(
                    username=username,
                    is_enabled=True  # Assume enabled unless proven otherwise
                )
                users.append(user)
        
        return users
    
    def _should_use_enum4linux(self) -> bool:
        """Determine if enum4linux-ng should be used based on configuration."""
        return (self._tool_available('enum4linux-ng') and 
                self.opsec_profile in ['normal', 'noisy'])
    
    def _tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        try:
            import shutil
            return shutil.which(tool_name) is not None
        except Exception:
            return False
    
    def _store_results(self, users: List[User], shares: List[Tuple[Host, Share]]) -> None:
        """Store enumeration results in the database."""
        try:
            # Store users
            user_count = 0
            for user in users:
                if self.db_manager.add_user(user):
                    user_count += 1
            
            # Store shares
            share_count = 0
            for host, share in shares:
                # Get host_id for the share
                hosts = self.db_manager.get_hosts()
                host_id = None
                for h in hosts:
                    if h.ip_address == host.ip_address:
                        host_id = h.host_id
                        break
                
                if host_id:
                    share.host_id = host_id
                    if self.db_manager.add_share(share):
                        share_count += 1
            
            self.logger.info(f"Stored {user_count} users and {share_count} shares from SMB enumeration")
            
        except Exception as e:
            self.logger.error(f"Failed to store SMB enumeration results: {e}")

def run_unauthenticated_smb_enum(db_manager: DatabaseManager, config: Dict[str, Any]) -> Tuple[List[User], List[Share]]:
    """
    Main entry point for unauthenticated SMB enumeration.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        Tuple of (users, shares) discovered
    """
    enumerator = SMBEnumerator(db_manager, config)
    return enumerator.run_unauthenticated_smb_enum()

def test_null_session(db_manager: DatabaseManager, ip_address: str, 
                     config: Dict[str, Any]) -> bool:
    """
    Test if null session is available on a specific host.
    
    Args:
        db_manager: Database manager instance
        ip_address: Target IP address
        config: Configuration dictionary
        
    Returns:
        True if null session is available
    """
    enumerator = SMBEnumerator(db_manager, config)
    return enumerator._test_null_session(ip_address) 