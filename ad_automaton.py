#!/usr/bin/env python3
"""
AD-Automaton: Automated Active Directory Attack Framework
A modular, intelligence-driven framework for automating AD penetration tests.

This framework is intended exclusively for authorized security assessments.
Unauthorized use is illegal and unethical.
"""

import argparse
import sys
import os
import logging
from pathlib import Path

# Add lib directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

def init_database(args):
    """Initialize a new database for the engagement."""
    from database import DatabaseManager
    
    db_path = args.db_path
    if os.path.exists(db_path) and not args.force:
        print(f"Database {db_path} already exists. Use --force to overwrite.")
        return False
    
    db_manager = DatabaseManager(db_path)
    if db_manager.init_database():
        print(f"Database initialized successfully at {db_path}")
        return True
    else:
        print(f"Failed to initialize database at {db_path}")
        return False

def run_recon(args):
    """Execute Phase I: Initial Reconnaissance and Network Mapping."""
    from database import DatabaseManager
    from config_manager import ConfigManager
    from modules.nmap_scanner import run_network_discovery
    from modules.dc_identifier import identify_domain_controllers
    from modules.dns_enum import run_dns_enumeration
    from modules.smb_enum import run_unauthenticated_smb_enum
    from modules.ldap_enum import run_unauthenticated_ldap_enum
    
    db_manager = DatabaseManager(args.db_path)
    config = ConfigManager().get_config()
    
    logging.info("Starting Phase I: Unauthenticated Reconnaissance")
    
    # Network Discovery
    if args.targets:
        logging.info(f"Running network discovery against {args.targets}")
        run_network_discovery(db_manager, args.targets, config)
    
    # DC Identification
    logging.info("Identifying Domain Controllers")
    identify_domain_controllers(db_manager, config)
    
    # DNS Enumeration
    logging.info("Attempting DNS zone transfers")
    run_dns_enumeration(db_manager, config)
    
    # SMB Enumeration
    logging.info("Running unauthenticated SMB enumeration")
    run_unauthenticated_smb_enum(db_manager, config)
    
    # LDAP Enumeration
    logging.info("Running unauthenticated LDAP enumeration")
    run_unauthenticated_ldap_enum(db_manager, config)
    
    logging.info("Phase I reconnaissance completed")

def run_enum(args):
    """Execute Phase II: Credential-Based Attacks and Enumeration."""
    from database import DatabaseManager
    from config_manager import ConfigManager
    from modules.cme_enum import run_credential_validation
    from modules.kerberoasting import run_kerberoasting
    from modules.timeroasting import run_timeroasting
    
    db_manager = DatabaseManager(args.db_path)
    config = ConfigManager().get_config()
    
    logging.info("Starting Phase II: Authenticated Enumeration")
    
    # Load credentials from file if provided
    if args.creds_file:
        from modules.credential_loader import load_credentials_from_file
        load_credentials_from_file(db_manager, args.creds_file)
    
    # Mass credential validation and enumeration
    logging.info("Running mass authentication and access mapping")
    run_credential_validation(db_manager, config)
    
    # Kerberoasting
    logging.info("Running Kerberoasting attacks")
    run_kerberoasting(db_manager, config)
    
    # Timeroasting
    logging.info("Running Timeroasting attacks")
    run_timeroasting(db_manager, config)
    
    logging.info("Phase II enumeration completed")

def run_mitm(args):
    """Execute Phase III: Network Man-in-the-Middle Attacks."""
    from database import DatabaseManager
    from config_manager import ConfigManager
    from modules.responder import run_responder_attack
    from modules.mitm6_relay import run_mitm6_ntlmrelay
    
    db_manager = DatabaseManager(args.db_path)
    config = ConfigManager().get_config()
    
    # Warn about noisy nature of these attacks
    if config.get('opsec_profile') != 'noisy':
        logging.warning("MitM attacks are inherently noisy and may be detected!")
        response = input("Continue? (y/N): ")
        if response.lower() != 'y':
            return
    
    logging.info("Starting Phase III: Network Man-in-the-Middle Attacks")
    
    if args.attack_type in ['responder', 'all']:
        logging.info("Starting LLMNR/NBT-NS poisoning with Responder")
        run_responder_attack(db_manager, config, args.interface)
    
    if args.attack_type in ['mitm6', 'all']:
        logging.info("Starting IPv6 DNS takeover with mitm6")
        run_mitm6_ntlmrelay(db_manager, config, args.interface)
    
    logging.info("Phase III MitM attacks completed")

def run_adcs(args):
    """Execute Phase IV: AD CS Enumeration and Abuse."""
    from database import DatabaseManager
    from config_manager import ConfigManager
    from modules.certipy_enum import run_certipy_enumeration
    from modules.petitpotam import run_petitpotam_coercion
    
    db_manager = DatabaseManager(args.db_path)
    config = ConfigManager().get_config()
    
    logging.info("Starting Phase IV: AD CS Enumeration and Abuse")
    
    # Certipy enumeration and exploitation
    logging.info("Running AD CS enumeration with Certipy")
    run_certipy_enumeration(db_manager, config)
    
    # PetitPotam coercion attacks
    if args.enable_coercion:
        logging.info("Running PetitPotam coercion attacks")
        run_petitpotam_coercion(db_manager, config)
    
    logging.info("Phase IV AD CS attacks completed")

def run_dcsync(args):
    """Execute DCSync attack with secretsdump.py."""
    from database import DatabaseManager
    from config_manager import ConfigManager
    from modules.dcsync import run_dcsync_attack
    
    db_manager = DatabaseManager(args.db_path)
    config = ConfigManager().get_config()
    
    logging.info("Starting DCSync attack")
    run_dcsync_attack(db_manager, config)
    logging.info("DCSync attack completed")

def run_full_chain(args):
    """Execute the complete attack chain sequentially."""
    from database import DatabaseManager
    
    logging.info("Starting full attack chain execution")
    
    # Phase I: Reconnaissance
    logging.info("=== PHASE I: RECONNAISSANCE ===")
    run_recon(args)
    
    # Phase III: MitM (if requested and we don't have creds yet)
    db_manager = DatabaseManager(args.db_path)
    if not db_manager.has_valid_credentials() and args.enable_mitm:
        logging.info("=== PHASE III: MitM ATTACKS ===")
        run_mitm(args)
    
    # Phase II: Authenticated Enumeration
    if db_manager.has_valid_credentials():
        logging.info("=== PHASE II: AUTHENTICATED ENUMERATION ===")
        run_enum(args)
    
    # Phase IV: AD CS and Advanced Attacks
    if db_manager.has_valid_credentials():
        logging.info("=== PHASE IV: AD CS ATTACKS ===")
        run_adcs(args)
    
    # DCSync if we have DA privileges
    if db_manager.has_domain_admin_credentials():
        logging.info("=== DCSYNC ATTACK ===")
        run_dcsync(args)
    
    logging.info("Full attack chain completed")

def generate_report(args):
    """Generate reports from the database."""
    from database import DatabaseManager
    from modules.reporter import generate_comprehensive_report
    
    db_manager = DatabaseManager(args.db_path)
    
    if args.format == 'csv':
        from modules.reporter import export_to_csv
        export_to_csv(db_manager, args.output or 'ad_automaton_report.csv')
    elif args.format == 'json':
        from modules.reporter import export_to_json
        export_to_json(db_manager, args.output or 'ad_automaton_report.json')
    else:
        generate_comprehensive_report(db_manager, args.output or 'ad_automaton_report.md')

def main():
    """Main entry point for AD-Automaton."""
    parser = argparse.ArgumentParser(
        description="AD-Automaton: Automated Active Directory Attack Framework",
        epilog="""
Examples:
  # Initialize new database
  python ad_automaton.py init --db project_alpha.db
  
  # Run reconnaissance
  python ad_automaton.py recon --db project_alpha.db -t 10.10.0.0/16
  
  # Run authenticated enumeration
  python ad_automaton.py enum --db project_alpha.db --creds-file creds.txt
  
  # Run MitM attacks
  python ad_automaton.py mitm --db project_alpha.db -i eth0 --attack-type mitm6
  
  # Run full attack chain
  python ad_automaton.py full-run --db project_alpha.db -t 10.10.0.0/16
  
  # Generate report
  python ad_automaton.py report --db project_alpha.db --format csv
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global arguments
    parser.add_argument('--db', dest='db_path', required=True,
                       help='Path to the SQLite database file')
    parser.add_argument('--config', default='config/default.yaml',
                       help='Path to configuration file')
    parser.add_argument('--profile', choices=['stealth', 'normal', 'noisy'],
                       help='OPSEC profile to use')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--log-file', help='Log file path')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize new database')
    init_parser.add_argument('--force', action='store_true',
                           help='Overwrite existing database')
    
    # Recon command
    recon_parser = subparsers.add_parser('recon', help='Phase I: Reconnaissance')
    recon_parser.add_argument('-t', '--targets', required=True,
                            help='Target network range (e.g., 192.168.1.0/24)')
    
    # Enum command
    enum_parser = subparsers.add_parser('enum', help='Phase II: Authenticated enumeration')
    enum_parser.add_argument('--creds-file', help='File containing credentials')
    
    # MitM command
    mitm_parser = subparsers.add_parser('mitm', help='Phase III: Man-in-the-Middle attacks')
    mitm_parser.add_argument('-i', '--interface', required=True,
                           help='Network interface to use')
    mitm_parser.add_argument('--attack-type', choices=['responder', 'mitm6', 'all'],
                           default='all', help='Type of MitM attack to run')
    
    # ADCS command
    adcs_parser = subparsers.add_parser('adcs', help='Phase IV: AD CS attacks')
    adcs_parser.add_argument('--enable-coercion', action='store_true',
                           help='Enable PetitPotam coercion attacks')
    
    # DCSync command
    dcsync_parser = subparsers.add_parser('dcsync', help='DCSync attack')
    
    # Full-run command
    full_parser = subparsers.add_parser('full-run', help='Execute complete attack chain')
    full_parser.add_argument('-t', '--targets', required=True,
                           help='Target network range')
    full_parser.add_argument('-i', '--interface', help='Network interface for MitM attacks')
    full_parser.add_argument('--enable-mitm', action='store_true',
                           help='Enable MitM attacks if no credentials found')
    full_parser.add_argument('--creds-file', help='Initial credentials file')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate reports')
    report_parser.add_argument('--format', choices=['markdown', 'csv', 'json'],
                             default='markdown', help='Report format')
    report_parser.add_argument('--output', help='Output file path')
    report_parser.add_argument('--show-credentials', action='store_true',
                             help='Include credentials in report')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup logging
    from logger import setup_logging
    setup_logging(args.verbose, args.log_file)
    
    # Load configuration
    from config_manager import ConfigManager
    config_manager = ConfigManager(args.config)
    if args.profile:
        config_manager.set_profile(args.profile)
    
    # Execute command
    try:
        if args.command == 'init':
            init_database(args)
        elif args.command == 'recon':
            run_recon(args)
        elif args.command == 'enum':
            run_enum(args)
        elif args.command == 'mitm':
            run_mitm(args)
        elif args.command == 'adcs':
            run_adcs(args)
        elif args.command == 'dcsync':
            run_dcsync(args)
        elif args.command == 'full-run':
            run_full_chain(args)
        elif args.command == 'report':
            generate_report(args)
    except KeyboardInterrupt:
        logging.info("Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        if args.verbose:
            logging.exception("Full traceback:")
        sys.exit(1)

if __name__ == "__main__":
    main()
