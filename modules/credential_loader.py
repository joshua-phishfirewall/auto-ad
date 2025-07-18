#!/usr/bin/env python3
"""
Credential Loader Module for AD-Automaton
Handles loading credentials from various file formats.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional
import csv

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential

class CredentialLoader:
    """
    Loads credentials from various file formats and stores them in the database.
    Supports multiple formats: plain text, CSV, colon-separated, etc.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize the credential loader.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
    
    def load_credentials_from_file(self, file_path: str) -> int:
        """
        Load credentials from a file, auto-detecting the format.
        
        Args:
            file_path: Path to the credentials file
            
        Returns:
            Number of credentials loaded
        """
        if not os.path.exists(file_path):
            self.logger.error(f"Credentials file not found: {file_path}")
            return 0
        
        self.logger.info(f"Loading credentials from: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Auto-detect format
            credentials = self._auto_detect_and_parse(content, file_path)
            
            # Store credentials in database
            stored_count = 0
            for credential in credentials:
                if self.db_manager.add_credential(credential):
                    stored_count += 1
            
            self.logger.info(f"Loaded {stored_count} credentials from {file_path}")
            return stored_count
            
        except Exception as e:
            self.logger.error(f"Failed to load credentials from {file_path}: {e}")
            return 0
    
    def _auto_detect_and_parse(self, content: str, file_path: str) -> List[Credential]:
        """
        Auto-detect file format and parse credentials.
        
        Args:
            content: File content
            file_path: File path for format hints
            
        Returns:
            List of parsed credentials
        """
        lines = content.strip().split('\n')
        if not lines:
            return []
        
        # Try different parsers in order of complexity
        parsers = [
            self._parse_csv_format,
            self._parse_colon_separated,
            self._parse_domain_user_pass,
            self._parse_hash_format,
            self._parse_simple_format
        ]
        
        for parser in parsers:
            try:
                credentials = parser(lines)
                if credentials:
                    self.logger.info(f"Detected format and parsed {len(credentials)} credentials")
                    return credentials
            except Exception as e:
                self.logger.debug(f"Parser failed: {e}")
                continue
        
        # Fallback to simple password list
        return self._parse_password_list(lines)
    
    def _parse_csv_format(self, lines: List[str]) -> List[Credential]:
        """Parse CSV format: username,password,domain or username,hash,domain"""
        credentials = []
        
        # Skip header if present
        start_idx = 0
        if lines[0].lower().startswith(('username', 'user', 'login')):
            start_idx = 1
        
        for i, line in enumerate(lines[start_idx:], start_idx + 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                # Try CSV parsing
                import csv
                import io
                
                reader = csv.reader(io.StringIO(line))
                row = next(reader)
                
                if len(row) >= 2:
                    username = row[0].strip()
                    password_or_hash = row[1].strip()
                    domain = row[2].strip() if len(row) > 2 else None
                    
                    # Determine if it's a hash or password
                    if self._looks_like_hash(password_or_hash):
                        hash_type = self._detect_hash_type(password_or_hash)
                        credential = Credential(
                            username=username,
                            domain=domain,
                            hash_value=password_or_hash,
                            hash_type=hash_type,
                            source_tool="file_load"
                        )
                    else:
                        credential = Credential(
                            username=username,
                            domain=domain,
                            password=password_or_hash,
                            source_tool="file_load"
                        )
                    
                    credentials.append(credential)
                    
            except Exception as e:
                self.logger.debug(f"Failed to parse CSV line {i}: {line} - {e}")
                continue
        
        return credentials
    
    def _parse_colon_separated(self, lines: List[str]) -> List[Credential]:
        """Parse colon-separated format: domain\\username:password or username:password"""
        credentials = []
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ':' not in line:
                continue
            
            try:
                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue
                
                user_part = parts[0].strip()
                password_or_hash = parts[1].strip()
                
                # Parse user part for domain
                domain = None
                if '\\' in user_part:
                    domain, username = user_part.split('\\', 1)
                elif '@' in user_part:
                    username, domain = user_part.split('@', 1)
                else:
                    username = user_part
                
                # Determine if it's a hash or password
                if self._looks_like_hash(password_or_hash):
                    hash_type = self._detect_hash_type(password_or_hash)
                    credential = Credential(
                        username=username,
                        domain=domain,
                        hash_value=password_or_hash,
                        hash_type=hash_type,
                        source_tool="file_load"
                    )
                else:
                    credential = Credential(
                        username=username,
                        domain=domain,
                        password=password_or_hash,
                        source_tool="file_load"
                    )
                
                credentials.append(credential)
                
            except Exception as e:
                self.logger.debug(f"Failed to parse colon-separated line {i}: {line} - {e}")
                continue
        
        return credentials
    
    def _parse_domain_user_pass(self, lines: List[str]) -> List[Credential]:
        """Parse format: domain username password (space-separated)"""
        credentials = []
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            try:
                if len(parts) == 2:
                    # username password
                    username, password_or_hash = parts
                    domain = None
                elif len(parts) >= 3:
                    # domain username password
                    domain, username, password_or_hash = parts[0], parts[1], parts[2]
                
                # Determine if it's a hash or password
                if self._looks_like_hash(password_or_hash):
                    hash_type = self._detect_hash_type(password_or_hash)
                    credential = Credential(
                        username=username,
                        domain=domain,
                        hash_value=password_or_hash,
                        hash_type=hash_type,
                        source_tool="file_load"
                    )
                else:
                    credential = Credential(
                        username=username,
                        domain=domain,
                        password=password_or_hash,
                        source_tool="file_load"
                    )
                
                credentials.append(credential)
                
            except Exception as e:
                self.logger.debug(f"Failed to parse space-separated line {i}: {line} - {e}")
                continue
        
        return credentials
    
    def _parse_hash_format(self, lines: List[str]) -> List[Credential]:
        """Parse hash-only format (NTDS dumps, etc.)"""
        credentials = []
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                # NTDS format: username:rid:lm_hash:nt_hash:::
                if ':::' in line and line.count(':') >= 6:
                    parts = line.split(':')
                    username = parts[0]
                    lm_hash = parts[2]
                    nt_hash = parts[3]
                    
                    # Extract domain from username if present
                    domain = None
                    if '\\' in username:
                        domain, username = username.split('\\', 1)
                    
                    credential = Credential(
                        username=username,
                        domain=domain,
                        hash_value=f"{lm_hash}:{nt_hash}",
                        hash_type="NTLM",
                        source_tool="file_load"
                    )
                    credentials.append(credential)
                
                # Single hash format
                elif self._looks_like_hash(line):
                    # Try to extract username from context or use generic
                    hash_type = self._detect_hash_type(line)
                    credential = Credential(
                        username="unknown",
                        hash_value=line,
                        hash_type=hash_type,
                        source_tool="file_load"
                    )
                    credentials.append(credential)
                
            except Exception as e:
                self.logger.debug(f"Failed to parse hash line {i}: {line} - {e}")
                continue
        
        return credentials
    
    def _parse_simple_format(self, lines: List[str]) -> List[Credential]:
        """Parse simple username or password lists"""
        credentials = []
        
        # Check if all lines look like usernames or passwords
        non_empty_lines = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        
        if not non_empty_lines:
            return []
        
        # Heuristic: if most lines contain @ or \, treat as usernames
        user_indicators = sum(1 for line in non_empty_lines if '@' in line or '\\' in line)
        user_ratio = user_indicators / len(non_empty_lines)
        
        if user_ratio > 0.3:  # Treat as username list
            for line in non_empty_lines:
                line = line.strip()
                
                domain = None
                if '\\' in line:
                    domain, username = line.split('\\', 1)
                elif '@' in line:
                    username, domain = line.split('@', 1)
                else:
                    username = line
                
                credential = Credential(
                    username=username,
                    domain=domain,
                    source_tool="file_load"
                )
                credentials.append(credential)
        
        return credentials
    
    def _parse_password_list(self, lines: List[str]) -> List[Credential]:
        """Parse as a simple password list"""
        credentials = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Create a generic credential for password spraying
            credential = Credential(
                username="",  # Will be filled during spraying
                password=line,
                source_tool="password_list"
            )
            credentials.append(credential)
        
        return credentials
    
    def _looks_like_hash(self, value: str) -> bool:
        """Determine if a value looks like a cryptographic hash"""
        value = value.strip()
        
        # Common hash patterns
        patterns = [
            r'^[a-fA-F0-9]{32}$',  # MD5
            r'^[a-fA-F0-9]{40}$',  # SHA1
            r'^[a-fA-F0-9]{64}$',  # SHA256
            r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$',  # NTLM (LM:NT)
            r'^\$krb5.*\$',  # Kerberos
            r'^\$2[ayb]\$.*',  # bcrypt
            r'^\$1\$.*',  # MD5 crypt
            r'^\$6\$.*',  # SHA512 crypt
        ]
        
        return any(re.match(pattern, value) for pattern in patterns)
    
    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect the type of hash"""
        hash_value = hash_value.strip()
        
        if re.match(r'^[a-fA-F0-9]{32}$', hash_value):
            return "MD5"
        elif re.match(r'^[a-fA-F0-9]{40}$', hash_value):
            return "SHA1"
        elif re.match(r'^[a-fA-F0-9]{64}$', hash_value):
            return "SHA256"
        elif re.match(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$', hash_value):
            return "NTLM"
        elif hash_value.startswith('$krb5'):
            return "Kerberos"
        elif hash_value.startswith('$2'):
            return "bcrypt"
        elif hash_value.startswith('$1$'):
            return "MD5_crypt"
        elif hash_value.startswith('$6$'):
            return "SHA512_crypt"
        else:
            return "Unknown"

def load_credentials_from_file(db_manager: DatabaseManager, file_path: str) -> int:
    """
    Load credentials from a file.
    
    Args:
        db_manager: Database manager instance
        file_path: Path to credentials file
        
    Returns:
        Number of credentials loaded
    """
    loader = CredentialLoader(db_manager)
    return loader.load_credentials_from_file(file_path)

def load_password_list(db_manager: DatabaseManager, file_path: str) -> int:
    """
    Load a password list for spraying attacks.
    
    Args:
        db_manager: Database manager instance
        file_path: Path to password list file
        
    Returns:
        Number of passwords loaded
    """
    loader = CredentialLoader(db_manager)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        credentials = loader._parse_password_list(lines)
        
        stored_count = 0
        for credential in credentials:
            if db_manager.add_credential(credential):
                stored_count += 1
        
        return stored_count
        
    except Exception as e:
        loader.logger.error(f"Failed to load password list from {file_path}: {e}")
        return 0 