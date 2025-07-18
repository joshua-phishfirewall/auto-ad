#!/usr/bin/env python3
"""
Database module for AD-Automaton
Handles all SQLite database operations and schema management.
"""

import sqlite3
import logging
import os
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Host:
    """Data class representing a host record."""
    ip_address: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    is_dc: bool = False
    smb_signing: Optional[str] = None
    host_id: Optional[int] = None

@dataclass
class Service:
    """Data class representing a service record."""
    host_id: int
    port: int
    protocol: str
    service_name: Optional[str] = None
    banner: Optional[str] = None
    service_id: Optional[int] = None

@dataclass
class User:
    """Data class representing a user record."""
    username: str
    domain: Optional[str] = None
    sid: Optional[str] = None
    description: Optional[str] = None
    is_enabled: bool = True
    is_admin: bool = False
    user_id: Optional[int] = None

@dataclass
class Group:
    """Data class representing a group record."""
    group_name: str
    domain: Optional[str] = None
    description: Optional[str] = None
    group_id: Optional[int] = None

@dataclass
class Share:
    """Data class representing an SMB share record."""
    host_id: int
    share_name: str
    permissions: Optional[str] = None
    comment: Optional[str] = None
    share_id: Optional[int] = None

@dataclass
class Credential:
    """Data class representing a credential record."""
    username: str
    domain: Optional[str] = None
    password: Optional[str] = None
    hash_value: Optional[str] = None
    hash_type: Optional[str] = None
    source_tool: Optional[str] = None
    cred_id: Optional[int] = None

@dataclass
class ValidCredential:
    """Data class representing a valid credential mapping."""
    host_id: int
    cred_id: int
    access_level: str

@dataclass
class Vulnerability:
    """Data class representing a vulnerability record."""
    host_id: int
    vuln_name: str
    description: Optional[str] = None
    cve: Optional[str] = None
    source_tool: Optional[str] = None
    vuln_id: Optional[int] = None

@dataclass
class Loot:
    """Data class representing captured data/loot."""
    host_id: int
    data_type: str
    content: bytes
    source_file: Optional[str] = None
    loot_id: Optional[int] = None

class DatabaseManager:
    """
    Central database manager for AD-Automaton framework.
    Handles all SQLite database operations with an idempotent schema.
    """
    
    def __init__(self, db_path: str):
        """Initialize the database manager with the given database path."""
        self.db_path = db_path
        self.connection = None
        self.logger = logging.getLogger(__name__)
    
    def connect(self) -> bool:
        """Establish a connection to the SQLite database."""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row  # Enable dict-like access to rows
            self.logger.debug(f"Connected to database: {self.db_path}")
            return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to connect to database: {e}")
            return False
    
    def disconnect(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.logger.debug("Disconnected from database")
    
    def init_database(self) -> bool:
        """
        Initialize the database with the complete AD-Automaton schema.
        Uses CREATE TABLE IF NOT EXISTS for idempotent operation.
        """
        if not self.connect():
            return False
        
        try:
            cursor = self.connection.cursor()
            
            # Hosts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Hosts (
                    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    os TEXT,
                    is_dc BOOLEAN DEFAULT 0,
                    smb_signing TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Services table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Services (
                    service_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service_name TEXT,
                    banner TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES Hosts(host_id)
                )
            """)
            
            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    domain TEXT,
                    sid TEXT UNIQUE,
                    description TEXT,
                    is_enabled BOOLEAN DEFAULT 1,
                    is_admin BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Groups table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Groups (
                    group_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_name TEXT NOT NULL,
                    domain TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Group_Memberships junction table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Group_Memberships (
                    user_id INTEGER,
                    group_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, group_id),
                    FOREIGN KEY (user_id) REFERENCES Users(user_id),
                    FOREIGN KEY (group_id) REFERENCES Groups(group_id)
                )
            """)
            
            # Shares table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Shares (
                    share_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    share_name TEXT NOT NULL,
                    permissions TEXT,
                    comment TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES Hosts(host_id)
                )
            """)
            
            # Credentials table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Credentials (
                    cred_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    domain TEXT,
                    password TEXT,
                    hash TEXT,
                    hash_type TEXT,
                    source_tool TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Valid_Credentials junction table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Valid_Credentials (
                    host_id INTEGER,
                    cred_id INTEGER,
                    access_level TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (host_id, cred_id),
                    FOREIGN KEY (host_id) REFERENCES Hosts(host_id),
                    FOREIGN KEY (cred_id) REFERENCES Credentials(cred_id)
                )
            """)
            
            # Vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Vulnerabilities (
                    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    vuln_name TEXT NOT NULL,
                    description TEXT,
                    cve TEXT,
                    source_tool TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES Hosts(host_id)
                )
            """)
            
            # Loot table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Loot (
                    loot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    data_type TEXT,
                    content BLOB,
                    source_file TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES Hosts(host_id)
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON Hosts(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_dc ON Hosts(is_dc)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_services_host ON Services(host_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_services_port ON Services(port)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON Users(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_credentials_username ON Credentials(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_valid_creds_host ON Valid_Credentials(host_id)")
            
            self.connection.commit()
            self.logger.info("Database schema initialized successfully")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to initialize database schema: {e}")
            self.connection.rollback()
            return False
        finally:
            self.disconnect()
    
    # Host operations
    def add_host(self, host: Host) -> Optional[int]:
        """Add a host to the database. Returns the host_id if successful."""
        if not self.connect():
            return None
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO Hosts (ip_address, hostname, os, is_dc, smb_signing)
                VALUES (?, ?, ?, ?, ?)
            """, (host.ip_address, host.hostname, host.os, host.is_dc, host.smb_signing))
            
            if cursor.rowcount > 0:
                host_id = cursor.lastrowid
                self.connection.commit()
                self.logger.debug(f"Added host: {host.ip_address} (ID: {host_id})")
                return host_id
            else:
                # Host already exists, get its ID
                cursor.execute("SELECT host_id FROM Hosts WHERE ip_address = ?", (host.ip_address,))
                result = cursor.fetchone()
                return result['host_id'] if result else None
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add host {host.ip_address}: {e}")
            self.connection.rollback()
            return None
        finally:
            self.disconnect()
    
    def get_hosts(self, is_dc: Optional[bool] = None) -> List[Host]:
        """Retrieve hosts from the database. Optionally filter by DC status."""
        if not self.connect():
            return []
        
        try:
            cursor = self.connection.cursor()
            if is_dc is not None:
                cursor.execute("SELECT * FROM Hosts WHERE is_dc = ?", (is_dc,))
            else:
                cursor.execute("SELECT * FROM Hosts")
            
            hosts = []
            for row in cursor.fetchall():
                hosts.append(Host(
                    host_id=row['host_id'],
                    ip_address=row['ip_address'],
                    hostname=row['hostname'],
                    os=row['os'],
                    is_dc=bool(row['is_dc']),
                    smb_signing=row['smb_signing']
                ))
            
            return hosts
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve hosts: {e}")
            return []
        finally:
            self.disconnect()
    
    def get_dcs(self) -> List[Host]:
        """Get all Domain Controllers."""
        return self.get_hosts(is_dc=True)
    
    def update_host_dc_status(self, ip_address: str, is_dc: bool) -> bool:
        """Update the DC status of a host."""
        if not self.connect():
            return False
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE Hosts SET is_dc = ? WHERE ip_address = ?
            """, (is_dc, ip_address))
            
            self.connection.commit()
            self.logger.debug(f"Updated DC status for {ip_address}: {is_dc}")
            return cursor.rowcount > 0
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to update DC status for {ip_address}: {e}")
            self.connection.rollback()
            return False
        finally:
            self.disconnect()
    
    # Service operations
    def add_service(self, service: Service) -> Optional[int]:
        """Add a service to the database."""
        if not self.connect():
            return None
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO Services (host_id, port, protocol, service_name, banner)
                VALUES (?, ?, ?, ?, ?)
            """, (service.host_id, service.port, service.protocol, service.service_name, service.banner))
            
            if cursor.rowcount > 0:
                service_id = cursor.lastrowid
                self.connection.commit()
                self.logger.debug(f"Added service: {service.host_id}:{service.port}/{service.protocol}")
                return service_id
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add service: {e}")
            self.connection.rollback()
            return None
        finally:
            self.disconnect()
    
    def get_services_by_host(self, host_id: int) -> List[Service]:
        """Get all services for a specific host."""
        if not self.connect():
            return []
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM Services WHERE host_id = ?", (host_id,))
            
            services = []
            for row in cursor.fetchall():
                services.append(Service(
                    service_id=row['service_id'],
                    host_id=row['host_id'],
                    port=row['port'],
                    protocol=row['protocol'],
                    service_name=row['service_name'],
                    banner=row['banner']
                ))
            
            return services
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve services for host {host_id}: {e}")
            return []
        finally:
            self.disconnect()
    
    def get_hosts_by_service(self, service_name: str, port: Optional[int] = None) -> List[Host]:
        """Get hosts running a specific service."""
        if not self.connect():
            return []
        
        try:
            cursor = self.connection.cursor()
            if port:
                cursor.execute("""
                    SELECT h.* FROM Hosts h
                    JOIN Services s ON h.host_id = s.host_id
                    WHERE s.service_name = ? AND s.port = ?
                """, (service_name, port))
            else:
                cursor.execute("""
                    SELECT h.* FROM Hosts h
                    JOIN Services s ON h.host_id = s.host_id
                    WHERE s.service_name = ?
                """, (service_name,))
            
            hosts = []
            for row in cursor.fetchall():
                hosts.append(Host(
                    host_id=row['host_id'],
                    ip_address=row['ip_address'],
                    hostname=row['hostname'],
                    os=row['os'],
                    is_dc=bool(row['is_dc']),
                    smb_signing=row['smb_signing']
                ))
            
            return hosts
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve hosts by service {service_name}: {e}")
            return []
        finally:
            self.disconnect()
    
    # Credential operations
    def add_credential(self, credential: Credential) -> Optional[int]:
        """Add a credential to the database."""
        if not self.connect():
            return None
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO Credentials (username, domain, password, hash, hash_type, source_tool)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (credential.username, credential.domain, credential.password, 
                  credential.hash_value, credential.hash_type, credential.source_tool))
            
            cred_id = cursor.lastrowid
            self.connection.commit()
            self.logger.debug(f"Added credential for {credential.domain}\\{credential.username}")
            return cred_id
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add credential: {e}")
            self.connection.rollback()
            return None
        finally:
            self.disconnect()
    
    def get_credentials(self, include_hashes: bool = True) -> List[Credential]:
        """Retrieve all credentials from the database."""
        if not self.connect():
            return []
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM Credentials")
            
            credentials = []
            for row in cursor.fetchall():
                credentials.append(Credential(
                    cred_id=row['cred_id'],
                    username=row['username'],
                    domain=row['domain'],
                    password=row['password'],
                    hash_value=row['hash'] if include_hashes else None,
                    hash_type=row['hash_type'],
                    source_tool=row['source_tool']
                ))
            
            return credentials
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve credentials: {e}")
            return []
        finally:
            self.disconnect()
    
    def add_valid_credential(self, valid_cred: ValidCredential) -> bool:
        """Add a valid credential mapping."""
        if not self.connect():
            return False
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO Valid_Credentials (host_id, cred_id, access_level)
                VALUES (?, ?, ?)
            """, (valid_cred.host_id, valid_cred.cred_id, valid_cred.access_level))
            
            self.connection.commit()
            self.logger.debug(f"Added valid credential mapping: host {valid_cred.host_id}, cred {valid_cred.cred_id}")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add valid credential mapping: {e}")
            self.connection.rollback()
            return False
        finally:
            self.disconnect()
    
    def has_valid_credentials(self) -> bool:
        """Check if any valid credentials exist in the database."""
        if not self.connect():
            return False
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM Valid_Credentials")
            result = cursor.fetchone()
            return result['count'] > 0
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to check for valid credentials: {e}")
            return False
        finally:
            self.disconnect()
    
    def has_domain_admin_credentials(self) -> bool:
        """Check if any Domain Admin credentials exist."""
        if not self.connect():
            return False
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count FROM Valid_Credentials vc
                JOIN Credentials c ON vc.cred_id = c.cred_id
                JOIN Users u ON c.username = u.username
                JOIN Group_Memberships gm ON u.user_id = gm.user_id
                JOIN Groups g ON gm.group_id = g.group_id
                WHERE g.group_name LIKE '%Domain Admins%' OR g.group_name LIKE '%Enterprise Admins%'
                   OR vc.access_level = 'ADMIN'
            """)
            result = cursor.fetchone()
            return result['count'] > 0
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to check for Domain Admin credentials: {e}")
            return False
        finally:
            self.disconnect()
    
    def get_untested_credentials(self) -> List[Credential]:
        """Get credentials that haven't been tested yet."""
        if not self.connect():
            return []
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT c.* FROM Credentials c
                LEFT JOIN Valid_Credentials vc ON c.cred_id = vc.cred_id
                WHERE vc.cred_id IS NULL
            """)
            
            credentials = []
            for row in cursor.fetchall():
                credentials.append(Credential(
                    cred_id=row['cred_id'],
                    username=row['username'],
                    domain=row['domain'],
                    password=row['password'],
                    hash_value=row['hash'],
                    hash_type=row['hash_type'],
                    source_tool=row['source_tool']
                ))
            
            return credentials
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve untested credentials: {e}")
            return []
        finally:
            self.disconnect()
    
    # User operations
    def add_user(self, user: User) -> Optional[int]:
        """Add a user to the database."""
        if not self.connect():
            return None
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO Users (username, domain, sid, description, is_enabled, is_admin)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user.username, user.domain, user.sid, user.description, user.is_enabled, user.is_admin))
            
            if cursor.rowcount > 0:
                user_id = cursor.lastrowid
                self.connection.commit()
                self.logger.debug(f"Added user: {user.domain}\\{user.username}")
                return user_id
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add user: {e}")
            self.connection.rollback()
            return None
        finally:
            self.disconnect()
    
    # Vulnerability operations
    def add_vulnerability(self, vuln: Vulnerability) -> Optional[int]:
        """Add a vulnerability to the database."""
        if not self.connect():
            return None
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO Vulnerabilities (host_id, vuln_name, description, cve, source_tool)
                VALUES (?, ?, ?, ?, ?)
            """, (vuln.host_id, vuln.vuln_name, vuln.description, vuln.cve, vuln.source_tool))
            
            vuln_id = cursor.lastrowid
            self.connection.commit()
            self.logger.debug(f"Added vulnerability: {vuln.vuln_name} for host {vuln.host_id}")
            return vuln_id
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add vulnerability: {e}")
            self.connection.rollback()
            return None
        finally:
            self.disconnect()
    
    # Share operations
    def add_share(self, share: Share) -> Optional[int]:
        """Add a share to the database."""
        if not self.connect():
            return None
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO Shares (host_id, share_name, permissions, comment)
                VALUES (?, ?, ?, ?)
            """, (share.host_id, share.share_name, share.permissions, share.comment))
            
            if cursor.rowcount > 0:
                share_id = cursor.lastrowid
                self.connection.commit()
                self.logger.debug(f"Added share: {share.share_name} on host {share.host_id}")
                return share_id
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add share: {e}")
            self.connection.rollback()
            return None
        finally:
            self.disconnect()
    
    def execute_query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a custom SQL query and return results."""
        if not self.connect():
            return []
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                results.append(dict(row))
            
            return results
            
        except sqlite3.Error as e:
            self.logger.error(f"Failed to execute query: {e}")
            return []
        finally:
            self.disconnect()
    
    def get_statistics(self) -> Dict[str, int]:
        """Get database statistics for reporting."""
        stats = {}
        
        tables = ['Hosts', 'Services', 'Users', 'Credentials', 'Valid_Credentials', 
                 'Vulnerabilities', 'Shares', 'Groups']
        
        for table in tables:
            count_query = f"SELECT COUNT(*) as count FROM {table}"
            result = self.execute_query(count_query)
            stats[table.lower()] = result[0]['count'] if result else 0
        
        # Special counts
        dc_query = "SELECT COUNT(*) as count FROM Hosts WHERE is_dc = 1"
        result = self.execute_query(dc_query)
        stats['domain_controllers'] = result[0]['count'] if result else 0
        
        admin_query = "SELECT COUNT(*) as count FROM Valid_Credentials WHERE access_level = 'ADMIN'"
        result = self.execute_query(admin_query)
        stats['admin_access'] = result[0]['count'] if result else 0
        
        return stats 