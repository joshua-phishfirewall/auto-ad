#!/usr/bin/env python3
"""
Nmap Scanner Module for AD-Automaton
Handles network discovery and service enumeration using nmap.
"""

import os
import tempfile
import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Host, Service
from executor import CommandExecutor, ExecutionResult
from parsers import NmapParser
from logger import log_discovery, log_tool_execution, log_tool_result

class NmapScanner:
    """
    Handles nmap-based network discovery and service enumeration.
    Implements the two-stage scanning approach described in the specification.
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize the nmap scanner.
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.executor = CommandExecutor()
        self.parser = NmapParser()
        
        # Get nmap configuration
        self.nmap_config = config.get('tools', {}).get('nmap', {})
        self.nmap_path = self.nmap_config.get('path', 'nmap')
        
    def run_network_discovery(self, targets: str) -> List[Host]:
        """
        Execute the complete network discovery process.
        
        Args:
            targets: Target network range (e.g., "192.168.1.0/24")
            
        Returns:
            List of discovered hosts
        """
        self.logger.info(f"Starting network discovery for targets: {targets}")
        
        # Stage 1: Host discovery (ping sweep)
        live_hosts = self._ping_sweep(targets)
        
        if not live_hosts:
            self.logger.warning("No live hosts found during ping sweep")
            return []
        
        log_discovery("live hosts", len(live_hosts), f"from {targets}")
        
        # Stage 2: Port scanning and service detection
        all_services = []
        for host in live_hosts:
            services = self._port_scan(host.ip_address)
            all_services.extend([(host, service) for service in services])
        
        # Store results in database
        self._store_results(live_hosts, all_services)
        
        self.logger.info(f"Network discovery completed: {len(live_hosts)} hosts, {len(all_services)} services")
        return live_hosts
    
    def _ping_sweep(self, targets: str) -> List[Host]:
        """
        Perform ping sweep to identify live hosts.
        
        Args:
            targets: Target network range
            
        Returns:
            List of live hosts
        """
        self.logger.info(f"Performing ping sweep on {targets}")
        
        # Build ping sweep command
        timing = self.nmap_config.get('timing_template', '-T3')
        max_rate = self.nmap_config.get('max_rate', '1000')
        ping_args = self.nmap_config.get('ping_sweep_args', '-sn')
        additional_args = self.nmap_config.get('additional_args', '')
        
        # Create temporary file for XML output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output_path = temp_file.name
        
        command = f"{self.nmap_path} {timing} --max-rate {max_rate} {ping_args} -oX {xml_output_path}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {targets}"
        
        try:
            log_tool_execution("nmap ping sweep", command)
            result = self.executor.execute(command, timeout=600)  # 10 minute timeout
            
            log_tool_result("nmap ping sweep", result.exit_code, 
                          len(result.stdout.splitlines()), 
                          len(result.stderr.splitlines()) if result.stderr else 0)
            
            if result.exit_code != 0:
                self.logger.error(f"Nmap ping sweep failed: {result.stderr}")
                return []
            
            # Parse XML output
            hosts = self._parse_nmap_xml(xml_output_path)
            
            return hosts
            
        except Exception as e:
            self.logger.error(f"Error during ping sweep: {e}")
            return []
        finally:
            # Clean up temporary file
            try:
                os.unlink(xml_output_path)
            except OSError:
                pass
    
    def _port_scan(self, target_ip: str) -> List[Service]:
        """
        Perform comprehensive port scan and service detection on a host.
        
        Args:
            target_ip: IP address to scan
            
        Returns:
            List of discovered services
        """
        self.logger.info(f"Port scanning {target_ip}")
        
        # Build port scan command
        timing = self.nmap_config.get('timing_template', '-T3')
        max_rate = self.nmap_config.get('max_rate', '1000')
        port_args = self.nmap_config.get('port_scan_args', '-sV --open -p-')
        script_args = self.nmap_config.get('script_args', '--script-timeout=30s')
        additional_args = self.nmap_config.get('additional_args', '')
        
        # Create temporary file for XML output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output_path = temp_file.name
        
        command = f"{self.nmap_path} {timing} --max-rate {max_rate} {port_args} {script_args} -oX {xml_output_path}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {target_ip}"
        
        try:
            log_tool_execution("nmap port scan", f"{command} (target: {target_ip})")
            result = self.executor.execute(command, timeout=1800)  # 30 minute timeout
            
            log_tool_result("nmap port scan", result.exit_code, 
                          len(result.stdout.splitlines()),
                          len(result.stderr.splitlines()) if result.stderr else 0)
            
            if result.exit_code != 0:
                self.logger.warning(f"Nmap port scan failed for {target_ip}: {result.stderr}")
                return []
            
            # Parse XML output for services
            _, services = self._parse_nmap_xml_with_services(xml_output_path)
            
            return services
            
        except Exception as e:
            self.logger.error(f"Error during port scan of {target_ip}: {e}")
            return []
        finally:
            # Clean up temporary file
            try:
                os.unlink(xml_output_path)
            except OSError:
                pass
    
    def _parse_nmap_xml(self, xml_file_path: str) -> List[Host]:
        """
        Parse nmap XML output for host information only.
        
        Args:
            xml_file_path: Path to nmap XML output file
            
        Returns:
            List of Host objects
        """
        try:
            with open(xml_file_path, 'r') as f:
                xml_content = f.read()
            
            hosts, _ = self.parser.parse_xml(xml_content)
            return hosts
            
        except Exception as e:
            self.logger.error(f"Failed to parse nmap XML: {e}")
            return []
    
    def _parse_nmap_xml_with_services(self, xml_file_path: str) -> Tuple[List[Host], List[Service]]:
        """
        Parse nmap XML output for both hosts and services.
        
        Args:
            xml_file_path: Path to nmap XML output file
            
        Returns:
            Tuple of (hosts, services) lists
        """
        try:
            with open(xml_file_path, 'r') as f:
                xml_content = f.read()
            
            return self.parser.parse_xml(xml_content)
            
        except Exception as e:
            self.logger.error(f"Failed to parse nmap XML with services: {e}")
            return [], []
    
    def _store_results(self, hosts: List[Host], services: List[Tuple[Host, Service]]) -> None:
        """
        Store discovery results in the database.
        
        Args:
            hosts: List of discovered hosts
            services: List of (host, service) tuples
        """
        try:
            # Store hosts and create a mapping of IP to host_id
            ip_to_host_id = {}
            
            for host in hosts:
                host_id = self.db_manager.add_host(host)
                if host_id:
                    ip_to_host_id[host.ip_address] = host_id
            
            # Store services
            services_added = 0
            for host, service in services:
                host_id = ip_to_host_id.get(host.ip_address)
                if host_id:
                    service.host_id = host_id
                    if self.db_manager.add_service(service):
                        services_added += 1
            
            self.logger.info(f"Stored {len(ip_to_host_id)} hosts and {services_added} services in database")
            
        except Exception as e:
            self.logger.error(f"Failed to store nmap results: {e}")
    
    def scan_specific_ports(self, targets: str, ports: str) -> List[Service]:
        """
        Scan specific ports on target hosts.
        
        Args:
            targets: Target hosts or networks
            ports: Port specification (e.g., "80,443,22" or "1-1000")
            
        Returns:
            List of discovered services
        """
        self.logger.info(f"Scanning specific ports {ports} on {targets}")
        
        timing = self.nmap_config.get('timing_template', '-T3')
        max_rate = self.nmap_config.get('max_rate', '1000')
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output_path = temp_file.name
        
        command = f"{self.nmap_path} {timing} --max-rate {max_rate} -sV --open -p {ports} -oX {xml_output_path} {targets}"
        
        try:
            log_tool_execution("nmap specific ports", command)
            result = self.executor.execute(command, timeout=900)  # 15 minute timeout
            
            if result.exit_code != 0:
                self.logger.error(f"Specific port scan failed: {result.stderr}")
                return []
            
            # Parse results
            hosts, services = self._parse_nmap_xml_with_services(xml_output_path)
            
            # Store in database
            self._store_results(hosts, [(host, service) for host in hosts for service in services])
            
            return [service for _, service in services]
            
        except Exception as e:
            self.logger.error(f"Error during specific port scan: {e}")
            return []
        finally:
            try:
                os.unlink(xml_output_path)
            except OSError:
                pass
    
    def scan_for_service(self, service_name: str, port_range: str = "1-65535") -> List[Host]:
        """
        Scan for a specific service across the network.
        
        Args:
            service_name: Name of service to scan for
            port_range: Port range to scan
            
        Returns:
            List of hosts running the service
        """
        self.logger.info(f"Scanning for {service_name} service")
        
        # Get known hosts from database
        hosts = self.db_manager.get_hosts()
        if not hosts:
            self.logger.warning("No hosts in database to scan")
            return []
        
        target_ips = [host.ip_address for host in hosts]
        targets = " ".join(target_ips)
        
        timing = self.nmap_config.get('timing_template', '-T3')
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output_path = temp_file.name
        
        command = f"{self.nmap_path} {timing} -sV --open -p {port_range} -oX {xml_output_path} {targets}"
        
        try:
            result = self.executor.execute(command, timeout=1800)
            
            if result.exit_code != 0:
                self.logger.error(f"Service scan failed: {result.stderr}")
                return []
            
            # Parse and filter for specific service
            hosts, services = self._parse_nmap_xml_with_services(xml_output_path)
            
            service_hosts = []
            for host, service in services:
                if service.service_name and service_name.lower() in service.service_name.lower():
                    service_hosts.append(host)
            
            return service_hosts
            
        except Exception as e:
            self.logger.error(f"Error during service scan: {e}")
            return []
        finally:
            try:
                os.unlink(xml_output_path)
            except OSError:
                pass

def run_network_discovery(db_manager: DatabaseManager, targets: str, config: Dict[str, Any]) -> List[Host]:
    """
    Main entry point for network discovery.
    
    Args:
        db_manager: Database manager instance
        targets: Target network range
        config: Configuration dictionary
        
    Returns:
        List of discovered hosts
    """
    scanner = NmapScanner(db_manager, config)
    return scanner.run_network_discovery(targets)

def scan_specific_service(db_manager: DatabaseManager, service_name: str, 
                         config: Dict[str, Any]) -> List[Host]:
    """
    Scan for a specific service across known hosts.
    
    Args:
        db_manager: Database manager instance
        service_name: Service to scan for
        config: Configuration dictionary
        
    Returns:
        List of hosts running the service
    """
    scanner = NmapScanner(db_manager, config)
    return scanner.scan_for_service(service_name) 