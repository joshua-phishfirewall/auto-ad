#!/usr/bin/env python3
"""
DNS Enumeration Module for AD-Automaton
Performs DNS zone transfers and DNS-based host discovery.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional, Set
import dns.resolver
import dns.exception
import dns.zone
import dns.query

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Host
from executor import CommandExecutor
from parsers import DNSParser
from logger import log_discovery, log_tool_execution, log_tool_result

class DNSEnumerator:
    """
    Handles DNS enumeration including zone transfers and DNS-based discovery.
    Targets misconfigured DNS servers that allow zone transfers.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the DNS enumerator.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.parser = DNSParser()
        
        # Get tool configurations
        self.dig_config = config.get('tools', {}).get('dig', {})
        self.nslookup_config = config.get('tools', {}).get('nslookup', {})
        
        self.dig_path = self.dig_config.get('path', 'dig')
        self.nslookup_path = self.nslookup_config.get('path', 'nslookup')
        
        # Discovered domains and DNS servers
        self.discovered_domains: Set[str] = set()
        self.dns_servers: List[str] = []
    
    def run_dns_enumeration(self) -> List[Host]:
        """
        Main method to run DNS enumeration.
        
        Returns:
            List of newly discovered hosts
        """
        self.logger.info("Starting DNS enumeration")
        
        discovered_hosts = []
        
        # Get DNS servers from database (hosts with port 53 open)
        self._identify_dns_servers()
        
        # Discover domains
        self._discover_domains()
        
        # Attempt zone transfers
        for domain in self.discovered_domains:
            hosts = self._attempt_zone_transfer(domain)
            discovered_hosts.extend(hosts)
        
        # DNS subdomain enumeration
        for domain in self.discovered_domains:
            hosts = self._enumerate_subdomains(domain)
            discovered_hosts.extend(hosts)
        
        # Reverse DNS enumeration
        reverse_hosts = self._reverse_dns_enumeration()
        discovered_hosts.extend(reverse_hosts)
        
        # Store results in database
        self._store_discovered_hosts(discovered_hosts)
        
        log_discovery("hosts via DNS", len(discovered_hosts), 
                     f"across {len(self.discovered_domains)} domains")
        
        return discovered_hosts
    
    def _identify_dns_servers(self) -> None:
        """Identify DNS servers from the database."""
        dns_hosts = self.db_manager.get_hosts_by_service('domain', 53)
        self.dns_servers = [host.ip_address for host in dns_hosts]
        
        # Add configured DNS servers
        config_dns = self.config.get('network', {}).get('dns_servers', [])
        self.dns_servers.extend(config_dns)
        
        # Remove duplicates
        self.dns_servers = list(set(self.dns_servers))
        
        self.logger.info(f"Identified {len(self.dns_servers)} DNS servers: {self.dns_servers}")
    
    def _discover_domains(self) -> None:
        """Discover domain names from various sources."""
        # Get domains from hostnames in database
        hosts = self.db_manager.get_hosts()
        
        for host in hosts:
            if host.hostname and '.' in host.hostname:
                # Extract domain from FQDN
                parts = host.hostname.split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[-2:])
                    self.discovered_domains.add(domain)
        
        # Try reverse DNS lookups to discover more domains
        for host in hosts[:20]:  # Limit to first 20 hosts
            try:
                import socket
                hostname = socket.gethostbyaddr(host.ip_address)[0]
                if '.' in hostname and not hostname.endswith('.arpa'):
                    parts = hostname.split('.')
                    if len(parts) >= 2:
                        domain = '.'.join(parts[-2:])
                        self.discovered_domains.add(domain)
            except Exception:
                continue
        
        # Add common internal domain patterns
        common_domains = [
            'domain.local', 'ad.local', 'corp.local', 'internal.local',
            'company.local', 'test.local', 'lab.local'
        ]
        self.discovered_domains.update(common_domains)
        
        self.logger.info(f"Discovered {len(self.discovered_domains)} potential domains: {list(self.discovered_domains)}")
    
    def _attempt_zone_transfer(self, domain: str) -> List[Host]:
        """
        Attempt DNS zone transfer for a domain.
        
        Args:
            domain: Domain to attempt zone transfer for
            
        Returns:
            List of hosts discovered via zone transfer
        """
        self.logger.info(f"Attempting zone transfer for domain: {domain}")
        
        discovered_hosts = []
        
        for dns_server in self.dns_servers:
            try:
                # Method 1: Using dig command
                hosts_dig = self._zone_transfer_with_dig(domain, dns_server)
                discovered_hosts.extend(hosts_dig)
                
                # Method 2: Using dnspython (if dig fails)
                if not hosts_dig:
                    hosts_dns = self._zone_transfer_with_dnspython(domain, dns_server)
                    discovered_hosts.extend(hosts_dns)
                
                if hosts_dig or hosts_dns:
                    self.logger.info(f"Successful zone transfer from {dns_server} for {domain}")
                    break  # Stop trying other servers for this domain
                    
            except Exception as e:
                self.logger.debug(f"Zone transfer failed for {domain} on {dns_server}: {e}")
                continue
        
        return discovered_hosts
    
    def _zone_transfer_with_dig(self, domain: str, dns_server: str) -> List[Host]:
        """
        Attempt zone transfer using dig command.
        
        Args:
            domain: Domain name
            dns_server: DNS server IP
            
        Returns:
            List of discovered hosts
        """
        command = f"{self.dig_path} AXFR @{dns_server} {domain}"
        
        try:
            log_tool_execution("dig AXFR", command)
            result = self.executor.execute(command, timeout=30)
            
            log_tool_result("dig AXFR", result.exit_code, 
                          len(result.stdout.splitlines()) if result.stdout else 0)
            
            if result.exit_code == 0 and result.stdout:
                # Check for successful zone transfer indicators
                if 'XFR size' in result.stdout or '; Transfer failed' not in result.stdout:
                    return self.parser.parse_zone_transfer(result.stdout)
            
        except Exception as e:
            self.logger.debug(f"dig zone transfer failed: {e}")
        
        return []
    
    def _zone_transfer_with_dnspython(self, domain: str, dns_server: str) -> List[Host]:
        """
        Attempt zone transfer using dnspython library.
        
        Args:
            domain: Domain name
            dns_server: DNS server IP
            
        Returns:
            List of discovered hosts
        """
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(dns_server, domain, timeout=30))
            
            hosts = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    if rdataset.rdtype == dns.rdatatype.A:
                        for rdata in rdataset:
                            hostname = str(name) if str(name) != '@' else domain
                            if hostname.endswith('.'):
                                hostname = hostname[:-1]
                            
                            host = Host(
                                ip_address=str(rdata),
                                hostname=hostname
                            )
                            hosts.append(host)
            
            self.logger.info(f"DNS zone transfer via dnspython returned {len(hosts)} hosts")
            return hosts
            
        except Exception as e:
            self.logger.debug(f"dnspython zone transfer failed: {e}")
            return []
    
    def _enumerate_subdomains(self, domain: str) -> List[Host]:
        """
        Enumerate common subdomains for a domain.
        
        Args:
            domain: Domain to enumerate subdomains for
            
        Returns:
            List of discovered hosts
        """
        self.logger.info(f"Enumerating subdomains for {domain}")
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'ns3',
            'test', 'dev', 'stage', 'staging', 'prod', 'production', 'admin', 'administrator',
            'secure', 'sql', 'database', 'db', 'mysql', 'oracle', 'backup', 'old', 'new',
            'vpn', 'firewall', 'gateway', 'router', 'switch', 'ap', 'wifi', 'wireless',
            'dc', 'dc1', 'dc2', 'dc01', 'dc02', 'ad', 'ldap', 'dns', 'dhcp', 'tftp',
            'file', 'files', 'share', 'shares', 'nfs', 'cifs', 'smb', 'print', 'printer',
            'web', 'app', 'api', 'portal', 'intranet', 'extranet', 'citrix', 'rdp', 'ts',
            'exchange', 'owa', 'outlook', 'imap', 'pop3', 'calendar', 'contacts',
            'monitor', 'monitoring', 'nagios', 'zabbix', 'cacti', 'backup', 'bacula'
        ]
        
        discovered_hosts = []
        
        for subdomain in common_subdomains:
            fqdn = f"{subdomain}.{domain}"
            
            try:
                # Try to resolve the subdomain
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                
                # Use discovered DNS servers if available
                if self.dns_servers:
                    resolver.nameservers = self.dns_servers[:3]  # Use first 3 DNS servers
                
                answers = resolver.resolve(fqdn, 'A')
                
                for answer in answers:
                    host = Host(
                        ip_address=str(answer),
                        hostname=fqdn
                    )
                    discovered_hosts.append(host)
                    
            except dns.exception.DNSException:
                continue
            except Exception as e:
                self.logger.debug(f"Subdomain resolution failed for {fqdn}: {e}")
                continue
        
        self.logger.info(f"Discovered {len(discovered_hosts)} hosts via subdomain enumeration")
        return discovered_hosts
    
    def _reverse_dns_enumeration(self) -> List[Host]:
        """
        Perform reverse DNS enumeration on discovered IP ranges.
        
        Returns:
            List of hosts with resolved hostnames
        """
        self.logger.info("Performing reverse DNS enumeration")
        
        # Get all known hosts
        hosts = self.db_manager.get_hosts()
        discovered_hosts = []
        
        # Extract IP ranges from known hosts
        ip_networks = self._extract_ip_networks(hosts)
        
        for network in ip_networks[:5]:  # Limit to first 5 networks
            self.logger.info(f"Reverse DNS scan on network: {network}")
            
            try:
                import ipaddress
                net = ipaddress.ip_network(network, strict=False)
                
                # Limit reverse DNS to first 50 IPs per network
                for ip in list(net.hosts())[:50]:
                    try:
                        import socket
                        hostname = socket.gethostbyaddr(str(ip))[0]
                        
                        if hostname and not hostname.endswith('.arpa'):
                            host = Host(
                                ip_address=str(ip),
                                hostname=hostname
                            )
                            discovered_hosts.append(host)
                            
                    except Exception:
                        continue
                        
            except Exception as e:
                self.logger.debug(f"Reverse DNS enumeration failed for {network}: {e}")
                continue
        
        self.logger.info(f"Discovered {len(discovered_hosts)} hosts via reverse DNS")
        return discovered_hosts
    
    def _extract_ip_networks(self, hosts: List[Host]) -> List[str]:
        """
        Extract IP networks from discovered hosts.
        
        Args:
            hosts: List of known hosts
            
        Returns:
            List of IP network ranges
        """
        networks = set()
        
        for host in hosts:
            try:
                import ipaddress
                ip = ipaddress.ip_address(host.ip_address)
                
                # Assume /24 networks for private IP ranges
                if ip.is_private:
                    network = ipaddress.ip_network(f"{host.ip_address}/24", strict=False)
                    networks.add(str(network))
                    
            except Exception:
                continue
        
        return list(networks)
    
    def _store_discovered_hosts(self, hosts: List[Host]) -> None:
        """
        Store discovered hosts in the database.
        
        Args:
            hosts: List of hosts to store
        """
        stored_count = 0
        
        for host in hosts:
            host_id = self.db_manager.add_host(host)
            if host_id:
                stored_count += 1
        
        self.logger.info(f"Stored {stored_count} new hosts from DNS enumeration")
    
    def query_dns_records(self, domain: str, record_type: str = 'A') -> List[str]:
        """
        Query specific DNS record types for a domain.
        
        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, TXT, etc.)
            
        Returns:
            List of record values
        """
        records = []
        
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_servers:
                resolver.nameservers = self.dns_servers
            
            answers = resolver.resolve(domain, record_type)
            
            for answer in answers:
                records.append(str(answer))
                
        except Exception as e:
            self.logger.debug(f"DNS query failed for {domain} {record_type}: {e}")
        
        return records
    
    def get_srv_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get SRV records for Active Directory services.
        
        Args:
            domain: Domain to query SRV records for
            
        Returns:
            List of SRV record dictionaries
        """
        srv_records = []
        
        # Common AD SRV record queries
        srv_queries = [
            f'_ldap._tcp.{domain}',
            f'_ldap._tcp.dc._msdcs.{domain}',
            f'_kerberos._tcp.{domain}',
            f'_kerberos._tcp.dc._msdcs.{domain}',
            f'_gc._tcp.{domain}',
            f'_kpasswd._tcp.{domain}',
            f'_sip._tcp.{domain}',
            f'_sipfederationtls._tcp.{domain}'
        ]
        
        for srv_query in srv_queries:
            try:
                resolver = dns.resolver.Resolver()
                if self.dns_servers:
                    resolver.nameservers = self.dns_servers
                
                answers = resolver.resolve(srv_query, 'SRV')
                
                for answer in answers:
                    srv_record = {
                        'query': srv_query,
                        'priority': answer.priority,
                        'weight': answer.weight,
                        'port': answer.port,
                        'target': str(answer.target).rstrip('.')
                    }
                    srv_records.append(srv_record)
                    
            except Exception as e:
                self.logger.debug(f"SRV query failed for {srv_query}: {e}")
                continue
        
        return srv_records

def run_dns_enumeration(db_manager: DatabaseManager, config: Dict[str, Any]) -> List[Host]:
    """
    Main entry point for DNS enumeration.
    
    Args:
        db_manager: Database manager instance
        config: Configuration dictionary
        
    Returns:
        List of newly discovered hosts
    """
    enumerator = DNSEnumerator(db_manager, config)
    return enumerator.run_dns_enumeration()

def attempt_zone_transfer(db_manager: DatabaseManager, domain: str, 
                         config: Dict[str, Any]) -> List[Host]:
    """
    Attempt zone transfer for a specific domain.
    
    Args:
        db_manager: Database manager instance
        domain: Domain to attempt zone transfer for
        config: Configuration dictionary
        
    Returns:
        List of hosts discovered via zone transfer
    """
    enumerator = DNSEnumerator(db_manager, config)
    enumerator._identify_dns_servers()
    return enumerator._attempt_zone_transfer(domain) 