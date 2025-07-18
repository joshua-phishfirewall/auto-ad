#!/usr/bin/env python3
"""
Domain Controller Identifier Module for AD-Automaton
Identifies Domain Controllers using multiple methods (DNS SRV, nltest, port analysis).
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional, Set
import dns.resolver
import dns.exception

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Host
from executor import CommandExecutor
from logger import log_discovery, log_tool_execution, log_tool_result

class DomainControllerIdentifier:
    """
    Identifies Domain Controllers using multiple redundant methods.
    Implements DNS SRV queries, nltest utility, and port-based identification.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the DC identifier.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        
        # Common DC ports for identification
        self.dc_ports = {
            53: 'DNS',
            88: 'Kerberos',
            135: 'RPC Endpoint Mapper',
            389: 'LDAP',
            445: 'SMB',
            464: 'Kerberos Password Change',
            636: 'LDAPS',
            3268: 'Global Catalog',
            3269: 'Global Catalog SSL'
        }
        
        # Domains discovered during enumeration
        self.discovered_domains: Set[str] = set()
    
    def identify_domain_controllers(self) -> List[str]:
        """
        Main method to identify Domain Controllers using all available methods.
        
        Returns:
            List of DC IP addresses
        """
        self.logger.info("Starting Domain Controller identification")
        
        dc_ips: Set[str] = set()
        
        # Method 1: DNS SRV record queries
        srv_dcs = self._identify_via_dns_srv()
        dc_ips.update(srv_dcs)
        
        # Method 2: nltest utility (if available)
        nltest_dcs = self._identify_via_nltest()
        dc_ips.update(nltest_dcs)
        
        # Method 3: Port-based identification
        port_dcs = self._identify_via_ports()
        dc_ips.update(port_dcs)
        
        # Method 4: SMB enumeration for DC roles
        smb_dcs = self._identify_via_smb()
        dc_ips.update(smb_dcs)
        
        # Update database with DC flags
        self._update_dc_status(list(dc_ips))
        
        log_discovery("domain controllers", len(dc_ips), 
                     f"using multiple identification methods")
        
        return list(dc_ips)
    
    def _identify_via_dns_srv(self) -> List[str]:
        """
        Identify DCs using DNS SRV record queries.
        
        Returns:
            List of DC IP addresses
        """
        self.logger.info("Identifying DCs via DNS SRV records")
        
        dc_ips = []
        dns_servers = self._get_dns_servers()
        
        # Common AD SRV records to query
        srv_queries = [
            '_ldap._tcp.dc._msdcs.{domain}',
            '_kerberos._tcp.dc._msdcs.{domain}',
            '_ldap._tcp.{domain}',
            '_kerberos._tcp.{domain}',
            '_gc._tcp.{domain}',
            '_kpasswd._tcp.{domain}'
        ]
        
        # Try to discover domains first
        domains = self._discover_domains_from_dns()
        
        for domain in domains:
            self.logger.info(f"Querying SRV records for domain: {domain}")
            
            for srv_template in srv_queries:
                srv_query = srv_template.format(domain=domain)
                
                try:
                    # Try each DNS server
                    for dns_server in dns_servers:
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.nameservers = [dns_server]
                            resolver.timeout = 5
                            resolver.lifetime = 10
                            
                            answers = resolver.resolve(srv_query, 'SRV')
                            
                            for answer in answers:
                                target = str(answer.target).rstrip('.')
                                if target and target != '.':
                                    # Resolve hostname to IP
                                    try:
                                        ip_answers = resolver.resolve(target, 'A')
                                        for ip_answer in ip_answers:
                                            ip = str(ip_answer)
                                            if ip not in dc_ips:
                                                dc_ips.append(ip)
                                                self.logger.info(f"Found DC via SRV: {target} ({ip})")
                                    except dns.exception.DNSException:
                                        continue
                            
                            break  # Successfully queried this DNS server
                            
                        except dns.exception.DNSException:
                            continue  # Try next DNS server
                            
                except Exception as e:
                    self.logger.debug(f"SRV query failed for {srv_query}: {e}")
                    continue
        
        return dc_ips
    
    def _identify_via_nltest(self) -> List[str]:
        """
        Identify DCs using the nltest utility.
        
        Returns:
            List of DC IP addresses
        """
        self.logger.info("Identifying DCs via nltest")
        
        dc_ips = []
        
        # Try to discover domains first
        domains = self._discover_domains_from_hosts()
        
        for domain in domains:
            try:
                command = f"nltest /dclist:{domain}"
                log_tool_execution("nltest", command)
                
                result = self.executor.execute(command, timeout=30)
                log_tool_result("nltest", result.exit_code)
                
                if result.exit_code == 0:
                    dc_hostnames = self._parse_nltest_output(result.stdout)
                    
                    # Resolve hostnames to IPs
                    for hostname in dc_hostnames:
                        ip = self._resolve_hostname(hostname)
                        if ip and ip not in dc_ips:
                            dc_ips.append(ip)
                            self.logger.info(f"Found DC via nltest: {hostname} ({ip})")
                
            except Exception as e:
                self.logger.debug(f"nltest failed for domain {domain}: {e}")
                continue
        
        return dc_ips
    
    def _identify_via_ports(self) -> List[str]:
        """
        Identify potential DCs based on open ports characteristic of Domain Controllers.
        
        Returns:
            List of potential DC IP addresses
        """
        self.logger.info("Identifying DCs via port analysis")
        
        dc_candidates = []
        
        # Get all hosts from database
        hosts = self.db_manager.get_hosts()
        
        for host in hosts:
            # Get services for this host
            services = self.db_manager.get_services_by_host(host.host_id)
            
            open_ports = {service.port for service in services}
            dc_port_matches = open_ports.intersection(self.dc_ports.keys())
            
            # Consider it a DC if it has multiple characteristic ports
            # Minimum criteria: LDAP (389) + Kerberos (88) or DNS (53) + LDAP
            ldap_open = 389 in open_ports
            kerberos_open = 88 in open_ports
            dns_open = 53 in open_ports
            gc_open = 3268 in open_ports
            
            dc_score = 0
            if ldap_open:
                dc_score += 3
            if kerberos_open:
                dc_score += 3
            if dns_open:
                dc_score += 2
            if gc_open:
                dc_score += 4  # Global Catalog is very DC-specific
            if 445 in open_ports:  # SMB
                dc_score += 1
            if 135 in open_ports:  # RPC
                dc_score += 1
            
            # Threshold for considering a host as a DC
            if dc_score >= 5:
                dc_candidates.append(host.ip_address)
                self.logger.info(f"Potential DC identified via ports: {host.ip_address} "
                               f"(score: {dc_score}, ports: {sorted(dc_port_matches)})")
        
        return dc_candidates
    
    def _identify_via_smb(self) -> List[str]:
        """
        Identify DCs by checking SMB shares and server info.
        
        Returns:
            List of DC IP addresses
        """
        self.logger.info("Identifying DCs via SMB enumeration")
        
        dc_ips = []
        
        # Get hosts that have SMB (port 445) open
        smb_hosts = self.db_manager.get_hosts_by_service('microsoft-ds', 445)
        if not smb_hosts:
            smb_hosts = self.db_manager.get_hosts_by_service('netbios-ssn', 139)
        
        for host in smb_hosts:
            if self._check_smb_for_dc_role(host.ip_address):
                dc_ips.append(host.ip_address)
        
        return dc_ips
    
    def _check_smb_for_dc_role(self, ip_address: str) -> bool:
        """
        Check if a host has DC role via SMB enumeration.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if host appears to be a DC
        """
        try:
            # Try to enumerate shares to look for SYSVOL and NETLOGON
            command = f"smbclient -L \\\\{ip_address} -N"
            result = self.executor.execute(command, timeout=30)
            
            if result.exit_code == 0:
                output_lower = result.stdout.lower()
                
                # Look for DC-specific shares
                dc_shares = ['sysvol', 'netlogon']
                found_shares = sum(1 for share in dc_shares if share in output_lower)
                
                if found_shares >= 1:  # At least one DC share found
                    self.logger.info(f"DC role confirmed via SMB shares: {ip_address}")
                    return True
            
        except Exception as e:
            self.logger.debug(f"SMB enumeration failed for {ip_address}: {e}")
        
        return False
    
    def _get_dns_servers(self) -> List[str]:
        """
        Get DNS servers to query from configuration and discovered hosts.
        
        Returns:
            List of DNS server IP addresses
        """
        dns_servers = []
        
        # Add configured DNS servers
        config_dns = self.config.get('network', {}).get('dns_servers', [])
        dns_servers.extend(config_dns)
        
        # Add discovered DNS servers (hosts with port 53 open)
        dns_hosts = self.db_manager.get_hosts_by_service('domain', 53)
        dns_servers.extend([host.ip_address for host in dns_hosts])
        
        # Remove duplicates
        return list(set(dns_servers))
    
    def _discover_domains_from_dns(self) -> List[str]:
        """
        Attempt to discover domain names from DNS queries.
        
        Returns:
            List of discovered domain names
        """
        domains = []
        
        # Try reverse DNS lookups on discovered hosts to find domain names
        hosts = self.db_manager.get_hosts()
        
        for host in hosts[:10]:  # Limit to first 10 hosts to avoid too many queries
            try:
                import socket
                hostname = socket.gethostbyaddr(host.ip_address)[0]
                
                if '.' in hostname and not hostname.endswith('.in-addr.arpa'):
                    # Extract domain from FQDN
                    parts = hostname.split('.')
                    if len(parts) >= 2:
                        domain = '.'.join(parts[-2:])  # Get last two parts
                        if domain not in domains:
                            domains.append(domain)
                            self.discovered_domains.add(domain)
                            
            except Exception:
                continue
        
        return domains
    
    def _discover_domains_from_hosts(self) -> List[str]:
        """
        Discover domain names from hostnames in the database.
        
        Returns:
            List of discovered domain names
        """
        domains = []
        
        hosts = self.db_manager.get_hosts()
        
        for host in hosts:
            if host.hostname and '.' in host.hostname:
                parts = host.hostname.split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[-2:])
                    if domain not in domains and not domain.endswith('.local'):
                        domains.append(domain)
                        self.discovered_domains.add(domain)
        
        # Also try common domain patterns
        common_domains = ['domain.local', 'ad.local', 'corp.local', 'internal.local']
        domains.extend(common_domains)
        
        return list(set(domains))
    
    def _parse_nltest_output(self, output: str) -> List[str]:
        """
        Parse nltest output to extract DC hostnames.
        
        Args:
            output: Raw nltest output
            
        Returns:
            List of DC hostnames
        """
        hostnames = []
        
        # Pattern for nltest DC list output
        dc_pattern = r'\\\\(\S+)\s+'
        
        for match in re.finditer(dc_pattern, output):
            hostname = match.group(1)
            if hostname and hostname not in hostnames:
                hostnames.append(hostname)
        
        return hostnames
    
    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            IP address or None if resolution fails
        """
        try:
            import socket
            ip = socket.gethostbyname(hostname)
            return ip
        except Exception:
            return None
    
    def _update_dc_status(self, dc_ips: List[str]) -> None:
        """
        Update the database to mark identified DCs.
        
        Args:
            dc_ips: List of DC IP addresses
        """
        for ip in dc_ips:
            success = self.db_manager.update_host_dc_status(ip, True)
            if success:
                self.logger.info(f"Marked {ip} as Domain Controller in database")
            else:
                self.logger.warning(f"Failed to update DC status for {ip}")
    
    def get_discovered_domains(self) -> List[str]:
        """
        Get list of domains discovered during DC identification.
        
        Returns:
            List of domain names
        """
        return list(self.discovered_domains)

def identify_domain_controllers(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[str]:
    """
    Main entry point for Domain Controller identification.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of identified DC IP addresses
    """
    identifier = DomainControllerIdentifier(db_manager, config)
    return identifier.identify_domain_controllers()

def get_domain_controllers_from_db(db_manager: DatabaseManager) -> List[Host]:
    """
    Retrieve Domain Controllers from the database.
    
    Args:
        db_manager: Database manager instance
        
    Returns:
        List of DC Host objects
    """
    return db_manager.get_dcs() 