#!/usr/bin/env python3
"""
Reporter Module for AD-Automaton
Generates comprehensive penetration test reports from database findings.
"""

import os
import json
import csv
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import asdict

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

from database import DatabaseManager, Host, Service, User, Group, Share, Credential, Vulnerability

class ADAutomatonReporter:
    """
    Generates comprehensive reports from AD-Automaton database findings.
    Supports multiple output formats and provides executive summaries.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize the reporter.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        
        # Risk level mappings
        self.risk_levels = {
            'Golden Ticket Capability': 'CRITICAL',
            'AD CS ESC1': 'HIGH',
            'AD CS ESC8': 'HIGH',
            'PetitPotam': 'HIGH',
            'Kerberoastable': 'MEDIUM',
            'Null Session': 'MEDIUM',
            'Anonymous LDAP': 'MEDIUM',
            'SMB Signing Disabled': 'MEDIUM',
            'Weak Password': 'MEDIUM',
            'Open Share': 'LOW'
        }
    
    def generate_comprehensive_report(self, output_file: str = "ad_automaton_report.md") -> bool:
        """
        Generate a comprehensive penetration test report in Markdown format.
        
        Args:
            output_file: Output file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Gather all data from database
            report_data = self._gather_report_data()
            
            # Generate markdown report
            markdown_content = self._generate_markdown_report(report_data)
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            self.logger.info(f"Comprehensive report generated: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating comprehensive report: {e}")
            return False
    
    def export_to_csv(self, output_file: str = "ad_automaton_findings.csv") -> bool:
        """
        Export findings to CSV format for analysis.
        
        Args:
            output_file: Output CSV file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            report_data = self._gather_report_data()
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'finding_type', 'risk_level', 'host_ip', 'hostname', 
                    'description', 'recommendation', 'source_tool'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Write vulnerabilities
                for vuln in report_data['vulnerabilities']:
                    host = self._get_host_by_id(report_data['hosts'], vuln.host_id)
                    
                    writer.writerow({
                        'finding_type': 'Vulnerability',
                        'risk_level': self._get_risk_level(vuln.vuln_name),
                        'host_ip': host.ip_address if host else 'Unknown',
                        'hostname': host.hostname if host else 'Unknown',
                        'description': f"{vuln.vuln_name}: {vuln.description}",
                        'recommendation': self._get_recommendation(vuln.vuln_name),
                        'source_tool': vuln.source_tool
                    })
                
                # Write credential findings
                for cred in report_data['credentials']:
                    writer.writerow({
                        'finding_type': 'Credential',
                        'risk_level': 'HIGH' if cred.username.lower() == 'krbtgt' else 'MEDIUM',
                        'host_ip': 'Multiple' if cred.source_tool else 'Unknown',
                        'hostname': 'Domain-wide',
                        'description': f"Compromised credential: {cred.domain}\\{cred.username} ({cred.hash_type})",
                        'recommendation': 'Force password reset and review access',
                        'source_tool': cred.source_tool
                    })
            
            self.logger.info(f"CSV export completed: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def export_to_json(self, output_file: str = "ad_automaton_data.json") -> bool:
        """
        Export all findings to JSON format.
        
        Args:
            output_file: Output JSON file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            report_data = self._gather_report_data()
            
            # Convert dataclasses to dictionaries for JSON serialization
            json_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'framework': 'AD-Automaton',
                    'version': '1.0'
                },
                'summary': self._generate_executive_summary(report_data),
                'hosts': [asdict(host) for host in report_data['hosts']],
                'services': [asdict(service) for service in report_data['services']],
                'users': [asdict(user) for user in report_data['users']],
                'groups': [asdict(group) for group in report_data['groups']],
                'shares': [asdict(share) for share in report_data['shares']],
                'credentials': [asdict(cred) for cred in report_data['credentials']],
                'vulnerabilities': [asdict(vuln) for vuln in report_data['vulnerabilities']]
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"JSON export completed: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {e}")
            return False
    
    def _gather_report_data(self) -> Dict[str, List]:
        """Gather all data from the database for reporting."""
        return {
            'hosts': self._get_all_hosts(),
            'services': self._get_all_services(),
            'users': self._get_all_users(),
            'groups': self._get_all_groups(),
            'shares': self._get_all_shares(),
            'credentials': self._get_all_credentials(),
            'vulnerabilities': self._get_all_vulnerabilities()
        }
    
    def _generate_markdown_report(self, report_data: Dict[str, List]) -> str:
        """Generate a comprehensive markdown report."""
        
        # Calculate statistics
        stats = self._calculate_statistics(report_data)
        exec_summary = self._generate_executive_summary(report_data)
        
        report = f"""# AD-Automaton Penetration Test Report

## Executive Summary

**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Framework:** AD-Automaton v1.0  
**Assessment Type:** Active Directory Security Assessment

### Key Findings

{exec_summary['key_findings']}

### Risk Assessment

- **Critical Risk Findings:** {exec_summary['risk_counts']['CRITICAL']}
- **High Risk Findings:** {exec_summary['risk_counts']['HIGH']}
- **Medium Risk Findings:** {exec_summary['risk_counts']['MEDIUM']}
- **Low Risk Findings:** {exec_summary['risk_counts']['LOW']}

### Scope Summary

- **Total Hosts Discovered:** {stats['total_hosts']}
- **Domain Controllers:** {stats['domain_controllers']}
- **Services Identified:** {stats['total_services']}
- **Domain Users:** {stats['total_users']}
- **Compromised Credentials:** {stats['total_credentials']}
- **Vulnerabilities Found:** {stats['total_vulnerabilities']}

---

## Detailed Findings

### 1. Infrastructure Discovery

#### 1.1 Network Hosts
"""

        # Add host information
        dc_hosts = [h for h in report_data['hosts'] if h.is_dc]
        regular_hosts = [h for h in report_data['hosts'] if not h.is_dc]
        
        if dc_hosts:
            report += "\n**Domain Controllers:**\n\n"
            for host in dc_hosts:
                report += f"- **{host.ip_address}** ({host.hostname or 'Unknown'})\n"
                report += f"  - OS: {host.os or 'Unknown'}\n"
                report += f"  - SMB Signing: {host.smb_signing or 'Unknown'}\n\n"
        
        if regular_hosts:
            report += "\n**Member Servers/Workstations:**\n\n"
            for host in regular_hosts[:10]:  # Limit to first 10
                report += f"- **{host.ip_address}** ({host.hostname or 'Unknown'})\n"
            
            if len(regular_hosts) > 10:
                report += f"\n*... and {len(regular_hosts) - 10} additional hosts*\n"

        # Add vulnerability section
        report += "\n### 2. Security Vulnerabilities\n\n"
        
        # Group vulnerabilities by risk level
        vuln_by_risk = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for vuln in report_data['vulnerabilities']:
            risk_level = self._get_risk_level(vuln.vuln_name)
            vuln_by_risk[risk_level].append(vuln)
        
        for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if vuln_by_risk[risk_level]:
                report += f"\n#### 2.{list(vuln_by_risk.keys()).index(risk_level) + 1} {risk_level} Risk Vulnerabilities\n\n"
                
                for vuln in vuln_by_risk[risk_level]:
                    host = self._get_host_by_id(report_data['hosts'], vuln.host_id)
                    report += f"**{vuln.vuln_name}**\n\n"
                    report += f"- **Host:** {host.ip_address if host else 'Unknown'} ({host.hostname if host else 'Unknown'})\n"
                    report += f"- **Description:** {vuln.description}\n"
                    report += f"- **Risk Level:** {risk_level}\n"
                    report += f"- **Source Tool:** {vuln.source_tool}\n"
                    report += f"- **Recommendation:** {self._get_recommendation(vuln.vuln_name)}\n\n"

        # Add credentials section
        if report_data['credentials']:
            report += "\n### 3. Compromised Credentials\n\n"
            
            # Group by source tool
            cred_by_source = {}
            for cred in report_data['credentials']:
                source = cred.source_tool or 'Unknown'
                if source not in cred_by_source:
                    cred_by_source[source] = []
                cred_by_source[source].append(cred)
            
            for source, creds in cred_by_source.items():
                report += f"#### 3.{list(cred_by_source.keys()).index(source) + 1} Credentials from {source}\n\n"
                
                for cred in creds:
                    risk_indicator = "🎯 CRITICAL" if cred.username.lower() == 'krbtgt' else "⚠️  HIGH"
                    report += f"- {risk_indicator}: **{cred.domain}\\{cred.username}** ({cred.hash_type})\n"
                
                report += "\n"

        # Add recommendations section
        report += self._generate_recommendations_section(report_data)
        
        # Add appendix
        report += self._generate_appendix_section(report_data)
        
        return report
    
    def _generate_executive_summary(self, report_data: Dict[str, List]) -> Dict[str, Any]:
        """Generate executive summary data."""
        
        # Count risks by level
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in report_data['vulnerabilities']:
            risk_level = self._get_risk_level(vuln.vuln_name)
            risk_counts[risk_level] += 1
        
        # Add high-risk credentials to count
        for cred in report_data['credentials']:
            if cred.username.lower() == 'krbtgt':
                risk_counts['CRITICAL'] += 1
            else:
                risk_counts['HIGH'] += 1
        
        # Generate key findings
        key_findings = []
        
        if risk_counts['CRITICAL'] > 0:
            key_findings.append(f"🚨 **{risk_counts['CRITICAL']} CRITICAL** security issues identified requiring immediate attention")
        
        if any(cred.username.lower() == 'krbtgt' for cred in report_data['credentials']):
            key_findings.append("🎯 **Domain compromise achieved** - krbtgt account hash extracted")
        
        if any('ESC1' in vuln.vuln_name for vuln in report_data['vulnerabilities']):
            key_findings.append("📜 **Certificate Services vulnerabilities** found enabling privilege escalation")
        
        if len(report_data['credentials']) > 10:
            key_findings.append(f"🔑 **{len(report_data['credentials'])} credentials compromised** across the domain")
        
        if not key_findings:
            key_findings.append("✅ No critical security issues identified during assessment")
        
        return {
            'risk_counts': risk_counts,
            'key_findings': '\n'.join([f"- {finding}" for finding in key_findings])
        }
    
    def _calculate_statistics(self, report_data: Dict[str, List]) -> Dict[str, int]:
        """Calculate summary statistics."""
        return {
            'total_hosts': len(report_data['hosts']),
            'domain_controllers': len([h for h in report_data['hosts'] if h.is_dc]),
            'total_services': len(report_data['services']),
            'total_users': len(report_data['users']),
            'total_credentials': len(report_data['credentials']),
            'total_vulnerabilities': len(report_data['vulnerabilities'])
        }
    
    def _generate_recommendations_section(self, report_data: Dict[str, List]) -> str:
        """Generate recommendations section."""
        
        recommendations = []
        
        # Check for common issues and generate recommendations
        if any(cred.username.lower() == 'krbtgt' for cred in report_data['credentials']):
            recommendations.append({
                'priority': 'IMMEDIATE',
                'title': 'Reset krbtgt Account Password',
                'description': 'The krbtgt account password has been compromised. This enables Golden Ticket attacks.',
                'action': 'Reset the krbtgt account password immediately and monitor for unauthorized Kerberos ticket usage.'
            })
        
        if any('ESC1' in vuln.vuln_name for vuln in report_data['vulnerabilities']):
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Fix Certificate Template Vulnerabilities',
                'description': 'Vulnerable certificate templates allow privilege escalation.',
                'action': 'Review and harden certificate template configurations, remove unnecessary SAN permissions.'
            })
        
        if any('PetitPotam' in vuln.vuln_name for vuln in report_data['vulnerabilities']):
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Apply PetitPotam Mitigations',
                'description': 'Domain controllers are vulnerable to authentication coercion attacks.',
                'action': 'Apply Microsoft patches and configure appropriate RPC restrictions.'
            })
        
        # Always include general recommendations
        recommendations.extend([
            {
                'priority': 'MEDIUM',
                'title': 'Implement Credential Hygiene',
                'description': 'Multiple credentials were compromised during assessment.',
                'action': 'Enforce strong password policies, implement LAPS for local accounts, and use privileged access workstations.'
            },
            {
                'priority': 'MEDIUM',
                'title': 'Enable Advanced Logging',
                'description': 'Improve detection capabilities for future attacks.',
                'action': 'Enable PowerShell logging, Sysmon, and Windows Event Forwarding. Deploy SIEM for centralized monitoring.'
            },
            {
                'priority': 'LOW',
                'title': 'Regular Security Assessments',
                'description': 'Maintain security posture through regular testing.',
                'action': 'Conduct quarterly penetration tests and implement continuous security monitoring.'
            }
        ])
        
        report = "\n### 4. Recommendations\n\n"
        
        for i, rec in enumerate(recommendations, 1):
            priority_emoji = {
                'IMMEDIATE': '🚨',
                'HIGH': '⚠️',
                'MEDIUM': '⚡',
                'LOW': 'ℹ️'
            }
            
            report += f"#### 4.{i} {priority_emoji.get(rec['priority'], '')} {rec['title']} ({rec['priority']} Priority)\n\n"
            report += f"**Issue:** {rec['description']}\n\n"
            report += f"**Recommended Action:** {rec['action']}\n\n"
        
        return report
    
    def _generate_appendix_section(self, report_data: Dict[str, List]) -> str:
        """Generate appendix with technical details."""
        
        report = "\n---\n\n## Appendix\n\n"
        
        # Add tool information
        report += "### A. Tools Used\n\n"
        tools_used = set()
        
        for vuln in report_data['vulnerabilities']:
            if vuln.source_tool:
                tools_used.add(vuln.source_tool)
        
        for cred in report_data['credentials']:
            if cred.source_tool:
                tools_used.add(cred.source_tool)
        
        tool_descriptions = {
            'nmap': 'Network discovery and port scanning',
            'crackmapexec': 'SMB enumeration and credential validation',
            'responder': 'LLMNR/NBT-NS poisoning for credential capture',
            'certipy': 'Active Directory Certificate Services enumeration and exploitation',
            'secretsdump': 'DCSync attack for credential extraction',
            'kerberoasting': 'Kerberos service ticket extraction',
            'petitpotam': 'NTLM authentication coercion'
        }
        
        for tool in sorted(tools_used):
            description = tool_descriptions.get(tool, 'Security assessment tool')
            report += f"- **{tool}**: {description}\n"
        
        # Add technical details
        report += "\n### B. Technical Details\n\n"
        report += "This assessment was conducted using the AD-Automaton framework, an automated Active Directory penetration testing tool.\n\n"
        report += "**Assessment Methodology:**\n"
        report += "1. Network discovery and service enumeration\n"
        report += "2. Unauthenticated information gathering\n"
        report += "3. Credential-based enumeration and lateral movement\n"
        report += "4. Privilege escalation and domain compromise\n"
        report += "5. Post-exploitation credential harvesting\n\n"
        
        return report
    
    def _get_risk_level(self, vuln_name: str) -> str:
        """Get risk level for a vulnerability."""
        for key in self.risk_levels:
            if key.lower() in vuln_name.lower():
                return self.risk_levels[key]
        return 'MEDIUM'  # Default risk level
    
    def _get_recommendation(self, vuln_name: str) -> str:
        """Get recommendation for a vulnerability."""
        recommendations = {
            'Golden Ticket': 'Reset krbtgt password immediately and review all high-privilege accounts',
            'ESC1': 'Review certificate template configurations and remove Subject Alternative Name permissions',
            'ESC8': 'Disable web enrollment or implement proper authentication controls',
            'PetitPotam': 'Apply Microsoft security updates and configure RPC restrictions',
            'Kerberoastable': 'Use managed service accounts and complex passwords for service accounts',
            'Null Session': 'Disable null session access via registry or Group Policy',
            'Anonymous LDAP': 'Configure LDAP to require authentication',
            'SMB Signing': 'Enable SMB signing on all domain controllers and servers',
            'Weak Password': 'Implement and enforce strong password policies',
            'Open Share': 'Review share permissions and remove unnecessary access'
        }
        
        for key in recommendations:
            if key.lower() in vuln_name.lower():
                return recommendations[key]
        
        return 'Review and remediate according to security best practices'
    
    def _get_host_by_id(self, hosts: List[Host], host_id: int) -> Optional[Host]:
        """Get host by ID from hosts list."""
        return next((h for h in hosts if h.host_id == host_id), None)
    
    # Database query methods
    def _get_all_hosts(self) -> List[Host]:
        """Get all hosts from database."""
        query = "SELECT * FROM Hosts ORDER BY is_dc DESC, ip_address"
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
    
    def _get_all_services(self) -> List[Service]:
        """Get all services from database."""
        query = "SELECT * FROM Services ORDER BY host_id, port"
        rows = self.db_manager.execute_query(query)
        
        services = []
        for row in rows:
            service = Service(
                service_id=row[0],
                host_id=row[1],
                port=row[2],
                protocol=row[3],
                service_name=row[4],
                banner=row[5]
            )
            services.append(service)
        
        return services
    
    def _get_all_users(self) -> List[User]:
        """Get all users from database."""
        query = "SELECT * FROM Users ORDER BY domain, username"
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
    
    def _get_all_groups(self) -> List[Group]:
        """Get all groups from database."""
        query = "SELECT * FROM Groups ORDER BY domain, group_name"
        rows = self.db_manager.execute_query(query)
        
        groups = []
        for row in rows:
            group = Group(
                group_id=row[0],
                group_name=row[1],
                domain=row[2],
                description=row[3]
            )
            groups.append(group)
        
        return groups
    
    def _get_all_shares(self) -> List[Share]:
        """Get all shares from database."""
        query = "SELECT * FROM Shares ORDER BY host_id, share_name"
        rows = self.db_manager.execute_query(query)
        
        shares = []
        for row in rows:
            share = Share(
                share_id=row[0],
                host_id=row[1],
                share_name=row[2],
                permissions=row[3],
                comment=row[4]
            )
            shares.append(share)
        
        return shares
    
    def _get_all_credentials(self) -> List[Credential]:
        """Get all credentials from database."""
        query = "SELECT * FROM Credentials ORDER BY domain, username"
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
    
    def _get_all_vulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from database."""
        query = "SELECT * FROM Vulnerabilities ORDER BY vuln_name"
        rows = self.db_manager.execute_query(query)
        
        vulnerabilities = []
        for row in rows:
            vulnerability = Vulnerability(
                vuln_id=row[0],
                host_id=row[1],
                vuln_name=row[2],
                description=row[3],
                cve=row[4],
                source_tool=row[5]
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities


def generate_comprehensive_report(db_manager: DatabaseManager, output_file: str = "ad_automaton_report.md") -> bool:
    """
    Main entry point for comprehensive report generation.
    
    Args:
        db_manager: Database manager instance
        output_file: Output file path
        
    Returns:
        True if successful, False otherwise
    """
    reporter = ADAutomatonReporter(db_manager)
    return reporter.generate_comprehensive_report(output_file)


def export_to_csv(db_manager: DatabaseManager, output_file: str = "ad_automaton_findings.csv") -> bool:
    """
    Main entry point for CSV export.
    
    Args:
        db_manager: Database manager instance
        output_file: Output CSV file path
        
    Returns:
        True if successful, False otherwise
    """
    reporter = ADAutomatonReporter(db_manager)
    return reporter.export_to_csv(output_file)


def export_to_json(db_manager: DatabaseManager, output_file: str = "ad_automaton_data.json") -> bool:
    """
    Main entry point for JSON export.
    
    Args:
        db_manager: Database manager instance
        output_file: Output JSON file path
        
    Returns:
        True if successful, False otherwise
    """
    reporter = ADAutomatonReporter(db_manager)
    return reporter.export_to_json(output_file) 