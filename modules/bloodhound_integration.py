#!/usr/bin/env python3
"""
BloodHound Integration Module for AD-Automaton
Integrates with BloodHound for target prioritization and attack path analysis.
Based on the field manual's Cypher queries and strategic targeting methodology.
"""

import os
import json
import logging
import tempfile
from typing import List, Dict, Any, Optional, Tuple

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Credential, User, Host, Vulnerability
from executor import CommandExecutor
from logger import log_discovery, log_tool_execution, log_tool_result

class BloodHoundIntegrator:
    """
    Integrates AD-Automaton with BloodHound for intelligent target prioritization.
    Implements Cypher queries for AS-REP roasting, Kerberoasting, and attack path analysis.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the BloodHound integrator.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        
        # Get BloodHound configurations
        self.bloodhound_config = config.get('tools', {}).get('bloodhound', {})
        self.neo4j_uri = self.bloodhound_config.get('neo4j_uri', 'bolt://localhost:7687')
        self.neo4j_user = self.bloodhound_config.get('neo4j_user', 'neo4j')
        self.neo4j_password = self.bloodhound_config.get('neo4j_password', 'BloodHound')
        
        self.sharphound_config = config.get('tools', {}).get('sharphound', {})
        self.sharphound_path = self.sharphound_config.get('path', 'SharpHound.exe')
        
        # Feature flags
        self.enabled = config.get('features', {}).get('enable_bloodhound', True)
        self.auto_collect = config.get('features', {}).get('auto_bloodhound_collect', True)
        self.auto_mark_owned = config.get('features', {}).get('auto_mark_owned', True)
        
        # OPSEC settings
        self.opsec_profile = config.get('opsec_profile', 'normal')
        
        # Output directory
        self.output_dir = config.get('output', {}).get('bloodhound_dir', '/tmp/ad-automaton-bloodhound')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Cypher queries from the field manual
        self.cypher_queries = self._initialize_cypher_queries()
        
        # Neo4j connection
        self.neo4j_driver = None
    
    def run_bloodhound_integration(self) -> Dict[str, Any]:
        """
        Main method to run BloodHound integration operations.
        
        Returns:
            Dictionary containing BloodHound analysis results
        """
        if not self.enabled:
            self.logger.info("BloodHound integration is disabled in configuration")
            return {'targets': [], 'paths': [], 'owned_marked': []}
        
        self.logger.info("Starting BloodHound integration")
        
        results = {
            'targets': [],
            'paths': [],
            'owned_marked': [],
            'collection_success': False
        }
        
        # Phase 1: Data collection (if enabled and credentials available)
        if self.auto_collect:
            collection_success = self._run_bloodhound_collection()
            results['collection_success'] = collection_success
        
        # Phase 2: Connect to Neo4j and analyze
        if self._connect_to_neo4j():
            try:
                # Phase 3: Identify high-value targets
                targets = self._identify_priority_targets()
                results['targets'] = targets
                
                # Phase 4: Analyze attack paths
                paths = self._analyze_attack_paths()
                results['paths'] = paths
                
                # Phase 5: Mark owned nodes
                if self.auto_mark_owned:
                    owned_marked = self._mark_owned_nodes()
                    results['owned_marked'] = owned_marked
                
            finally:
                self._disconnect_from_neo4j()
        
        log_discovery("BloodHound priority targets", len(results['targets']))
        log_discovery("BloodHound attack paths", len(results['paths']))
        
        return results
    
    def _run_bloodhound_collection(self) -> bool:
        """
        Run BloodHound data collection using SharpHound.
        
        Returns:
            True if collection successful, False otherwise
        """
        # Check if we have valid credentials for collection
        credentials = self._get_collection_credentials()
        
        if not credentials:
            self.logger.warning("No valid credentials for BloodHound collection")
            return False
        
        if not self._is_windows() or not os.path.exists(self.sharphound_path):
            self.logger.warning("BloodHound collection requires Windows and SharpHound")
            return False
        
        credential = credentials[0]  # Use first available credential
        
        # Construct SharpHound command
        cmd_parts = [
            self.sharphound_path,
            '-c', 'All',  # Collect all data
            '--outputdirectory', self.output_dir,
            '--randomfilenames',  # OPSEC: randomize output filenames
            '--throttle', '1000' if self.opsec_profile == 'stealth' else '500',  # OPSEC: throttle requests
            '--jitter', '20',  # OPSEC: add jitter to requests
        ]
        
        # Add authentication if we have credentials
        if credential.domain and credential.username:
            if credential.password:
                cmd_parts.extend([
                    '--domain', credential.domain,
                    '--username', credential.username,
                    '--password', credential.password
                ])
            elif credential.hash_value:
                cmd_parts.extend([
                    '--domain', credential.domain,
                    '--username', credential.username,
                    '--passwordhash', credential.hash_value
                ])
        
        cmd = ' '.join(cmd_parts)
        
        try:
            log_tool_execution("SharpHound", f"BloodHound collection as {credential.username}")
            result = self.executor.execute_command(cmd, timeout=1800)  # 30 minute timeout
            
            if result.returncode == 0:
                log_tool_result("SharpHound", True)
                self.logger.info("BloodHound collection completed successfully")
                return True
            else:
                log_tool_result("SharpHound", False)
                self.logger.warning(f"BloodHound collection failed: {result.stderr}")
        
        except Exception as e:
            self.logger.error(f"Error running BloodHound collection: {e}")
        
        return False
    
    def _connect_to_neo4j(self) -> bool:
        """
        Connect to Neo4j database.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Try to import neo4j driver
            from neo4j import GraphDatabase
            
            self.neo4j_driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            )
            
            # Test connection
            with self.neo4j_driver.session() as session:
                result = session.run("RETURN 1")
                result.single()
            
            self.logger.info("Connected to BloodHound Neo4j database")
            return True
            
        except ImportError:
            self.logger.error("Neo4j Python driver not installed. Install with: pip install neo4j")
            return False
        except Exception as e:
            self.logger.error(f"Failed to connect to Neo4j: {e}")
            return False
    
    def _disconnect_from_neo4j(self) -> None:
        """Disconnect from Neo4j database."""
        if self.neo4j_driver:
            self.neo4j_driver.close()
            self.neo4j_driver = None
    
    def _identify_priority_targets(self) -> List[Dict[str, Any]]:
        """
        Identify priority targets using BloodHound Cypher queries.
        
        Returns:
            List of priority target information
        """
        priority_targets = []
        
        self.logger.info("Identifying priority targets with BloodHound")
        
        # Execute each priority query
        for query_name, query_info in self.cypher_queries['priority_targets'].items():
            try:
                targets = self._execute_cypher_query(query_info['query'])
                
                for target in targets:
                    priority_targets.append({
                        'type': query_name,
                        'name': target.get('name', 'Unknown'),
                        'priority': query_info.get('priority', 'MEDIUM'),
                        'description': query_info.get('description', ''),
                        'properties': dict(target)
                    })
                
                self.logger.info(f"Found {len(targets)} targets for {query_name}")
                
            except Exception as e:
                self.logger.error(f"Error executing query {query_name}: {e}")
                continue
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        priority_targets.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return priority_targets
    
    def _analyze_attack_paths(self) -> List[Dict[str, Any]]:
        """
        Analyze attack paths using BloodHound.
        
        Returns:
            List of attack path information
        """
        attack_paths = []
        
        self.logger.info("Analyzing attack paths with BloodHound")
        
        # Get owned nodes first
        owned_nodes = self._get_owned_nodes()
        
        if not owned_nodes:
            self.logger.info("No owned nodes found, using default attack path queries")
            owned_nodes = ['DOMAIN USERS@DOMAIN.LOCAL']  # Default starting point
        
        # Execute path analysis queries
        for query_name, query_info in self.cypher_queries['attack_paths'].items():
            try:
                # Replace placeholders in query
                query = query_info['query']
                
                for owned_node in owned_nodes[:5]:  # Limit to first 5 owned nodes
                    node_query = query.replace('{owned_node}', owned_node)
                    paths = self._execute_cypher_query(node_query)
                    
                    for path in paths:
                        attack_paths.append({
                            'type': query_name,
                            'source': owned_node,
                            'target': path.get('target', 'Unknown'),
                            'length': path.get('length', 0),
                            'description': query_info.get('description', ''),
                            'path_data': dict(path)
                        })
                
                self.logger.info(f"Found {len(paths)} paths for {query_name}")
                
            except Exception as e:
                self.logger.error(f"Error analyzing paths for {query_name}: {e}")
                continue
        
        # Sort by path length (shorter paths first)
        attack_paths.sort(key=lambda x: x.get('length', 999))
        
        return attack_paths
    
    def _mark_owned_nodes(self) -> List[str]:
        """
        Mark compromised nodes as owned in BloodHound.
        
        Returns:
            List of nodes marked as owned
        """
        marked_nodes = []
        
        self.logger.info("Marking compromised credentials as owned in BloodHound")
        
        # Get compromised credentials from database
        compromised_creds = self._get_compromised_credentials()
        
        for cred in compromised_creds:
            try:
                # Mark user as owned
                user_identifier = f"{cred.username.upper()}@{cred.domain.upper()}"
                
                mark_query = f"""
                MATCH (u:User {{name: "{user_identifier}"}})
                SET u.owned = true
                RETURN u.name
                """
                
                result = self._execute_cypher_query(mark_query)
                
                if result:
                    marked_nodes.append(user_identifier)
                    self.logger.debug(f"Marked {user_identifier} as owned")
                
            except Exception as e:
                self.logger.error(f"Error marking {cred.username} as owned: {e}")
                continue
        
        self.logger.info(f"Marked {len(marked_nodes)} nodes as owned")
        return marked_nodes
    
    def _execute_cypher_query(self, query: str) -> List[Dict[str, Any]]:
        """
        Execute a Cypher query against the Neo4j database.
        
        Args:
            query: Cypher query to execute
            
        Returns:
            List of query results
        """
        if not self.neo4j_driver:
            return []
        
        results = []
        
        try:
            with self.neo4j_driver.session() as session:
                result = session.run(query)
                
                for record in result:
                    # Convert neo4j record to dictionary
                    record_dict = {}
                    for key in record.keys():
                        value = record[key]
                        if hasattr(value, '_properties'):
                            # Neo4j node/relationship object
                            record_dict[key] = dict(value._properties)
                            record_dict[key]['labels'] = list(value.labels) if hasattr(value, 'labels') else []
                        else:
                            # Simple value
                            record_dict[key] = value
                    
                    results.append(record_dict)
        
        except Exception as e:
            self.logger.error(f"Error executing Cypher query: {e}")
            self.logger.debug(f"Query: {query}")
        
        return results
    
    def _initialize_cypher_queries(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Initialize Cypher queries from the field manual."""
        return {
            'priority_targets': {
                'asrep_roastable_users': {
                    'query': 'MATCH (u:User {donotreqpreauth: true}) RETURN u.name as name',
                    'priority': 'HIGH',
                    'description': 'Users with Kerberos pre-authentication disabled'
                },
                'asrep_roastable_enabled': {
                    'query': 'MATCH (u:User {donotreqpreauth: true, enabled: true}) RETURN u.name as name',
                    'priority': 'HIGH',
                    'description': 'Enabled users vulnerable to AS-REP roasting'
                },
                'asrep_roastable_highvalue': {
                    'query': 'MATCH (u:User {donotreqpreauth: true, highvalue: true}) RETURN u.name as name',
                    'priority': 'CRITICAL',
                    'description': 'High-value users vulnerable to AS-REP roasting'
                },
                'kerberoastable_users': {
                    'query': 'MATCH (u:User) WHERE u.hasspn = true RETURN u.name as name',
                    'priority': 'HIGH',
                    'description': 'Users with Service Principal Names (Kerberoastable)'
                },
                'kerberoastable_highvalue': {
                    'query': 'MATCH (u:User {hasspn: true, highvalue: true}) RETURN u.name as name',
                    'priority': 'CRITICAL',
                    'description': 'High-value Kerberoastable users'
                },
                'kerberoastable_sql_services': {
                    'query': '''MATCH (u:User) WHERE u.hasspn=true AND ANY (x IN u.serviceprincipalnames WHERE toUpper(x) CONTAINS 'SQL') 
                             RETURN u.name as name, u.serviceprincipalnames as spns''',
                    'priority': 'HIGH',
                    'description': 'Users running SQL services (often high-privilege)'
                },
                'unconstrained_delegation': {
                    'query': 'MATCH (c:Computer {unconstraineddelegation: true}) RETURN c.name as name',
                    'priority': 'CRITICAL',
                    'description': 'Computers with unconstrained delegation'
                },
                'domain_admins': {
                    'query': 'MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name CONTAINS "DOMAIN ADMINS" RETURN u.name as name',
                    'priority': 'CRITICAL',
                    'description': 'Domain administrator accounts'
                }
            },
            'attack_paths': {
                'path_to_domain_admins': {
                    'query': '''MATCH p=shortestPath((u:User {name: "{owned_node}"})-[*1..]->(g:Group))
                             WHERE g.name CONTAINS "DOMAIN ADMINS" 
                             RETURN g.name as target, length(p) as length''',
                    'description': 'Shortest paths from owned users to Domain Admins'
                },
                'path_to_high_value': {
                    'query': '''MATCH p=shortestPath((u:User {name: "{owned_node}"})-[*1..]->(t))
                             WHERE t.highvalue = true AND t <> u
                             RETURN t.name as target, labels(t) as target_type, length(p) as length''',
                    'description': 'Paths from owned users to high-value targets'
                },
                'local_admin_paths': {
                    'query': '''MATCH p=(u:User {name: "{owned_node}"})-[:AdminTo]->(c:Computer)
                             RETURN c.name as target, length(p) as length''',
                    'description': 'Computers where owned user has local admin rights'
                },
                'rdp_access_paths': {
                    'query': '''MATCH p=(u:User {name: "{owned_node}"})-[:CanRDP]->(c:Computer)
                             RETURN c.name as target, length(p) as length''',
                    'description': 'Computers accessible via RDP'
                },
                'dcsync_paths': {
                    'query': '''MATCH p=(u:User {name: "{owned_node}"})-[:DCSync]->(d:Domain)
                             RETURN d.name as target, length(p) as length''',
                    'description': 'DCSync privileges from owned users'
                }
            }
        }
    
    def _get_collection_credentials(self) -> List[Credential]:
        """Get credentials suitable for BloodHound collection."""
        query = """
            SELECT DISTINCT c.* FROM Credentials c
            LEFT JOIN Valid_Credentials vc ON c.cred_id = vc.cred_id
            WHERE c.domain IS NOT NULL AND (c.password IS NOT NULL OR c.hash_value IS NOT NULL)
            ORDER BY vc.access_level DESC, c.created_at DESC
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
    
    def _get_compromised_credentials(self) -> List[Credential]:
        """Get all compromised credentials for marking as owned."""
        query = "SELECT * FROM Credentials WHERE domain IS NOT NULL"
        rows = self.db_manager.execute_query(query)
        
        credentials = []
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
    
    def _get_owned_nodes(self) -> List[str]:
        """Get currently owned nodes from BloodHound."""
        if not self.neo4j_driver:
            return []
        
        query = "MATCH (n) WHERE n.owned = true RETURN n.name as name"
        results = self._execute_cypher_query(query)
        
        return [result['name'] for result in results if 'name' in result]
    
    def _is_windows(self) -> bool:
        """Check if running on Windows platform."""
        import platform
        return platform.system().lower() == 'windows'


def run_bloodhound_integration(db_manager: DatabaseManager, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for BloodHound integration module.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        Dictionary containing BloodHound analysis results
    """
    integrator = BloodHoundIntegrator(db_manager, config)
    return integrator.run_bloodhound_integration() 