# AD-Automaton: Automated Active Directory Attack Framework

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AD-Automaton** is a modular, intelligence-driven framework for automating Active Directory penetration tests. It transforms traditional linear attack scripts into a sophisticated, state-aware system that can adapt to environmental variations, recover from tool failures, and capitalize on unforeseen opportunities.

## ⚠️ **LEGAL DISCLAIMER**

**This framework is intended exclusively for authorized security assessments. Unauthorized use against any network is illegal and unethical. The purpose of this framework is to identify and help remediate security vulnerabilities, not to cause harm.**

Users must obtain explicit, written consent from the target organization before using this tool. The developers are not responsible for any misuse or illegal activities.

## 🎯 Key Features

- **Modular Architecture**: Each attack phase is implemented as independent, interoperable modules
- **Intelligence-Driven**: Centralized SQLite database serves as the operational intelligence backbone
- **State Management**: Persistent state allows operations to be paused, resumed, and analyzed
- **OPSEC Profiles**: Configurable stealth, normal, and noisy operation modes
- **Comprehensive Coverage**: Implements the complete AD attack chain from reconnaissance to domain compromise
- **Tool Integration**: Seamlessly integrates nmap, CrackMapExec, Impacket, Responder, Certipy, and more

## 🏗️ Architecture

The framework consists of four main phases:

### Phase I: Initial Reconnaissance (Unauthenticated)
- Network discovery with nmap
- Domain Controller identification via DNS SRV records and port analysis
- DNS zone transfer attempts
- Unauthenticated SMB and LDAP enumeration

### Phase II: Credential-Based Attacks and Enumeration
- Mass authentication testing with CrackMapExec
- Automated lateral movement discovery
- Kerberoasting attacks
- Timeroasting attacks

### Phase III: Network Man-in-the-Middle Attacks
- LLMNR/NBT-NS poisoning with Responder
- IPv6 DNS takeover with mitm6
- NTLM relay attacks with intelligent targeting

### Phase IV: Coercion, Certificate Abuse, and Domain Compromise
- PetitPotam authentication coercion
- AD CS enumeration and exploitation with Certipy
- DCSync attacks with secretsdump.py

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- Kali Linux (recommended) or compatible penetration testing distribution
- Root/administrator privileges for some operations

### Required Tools

Ensure the following tools are installed and available in your PATH:

```bash
# Core tools
sudo apt update
sudo apt install nmap smbclient ldap-utils dnsutils

# Python tools (install via pip)
pip install impacket crackmapexec responder mitm6 certipy-ad

# Optional but recommended
sudo apt install enum4linux-ng
```

### Install AD-Automaton

1. Clone the repository:
```bash
git clone https://github.com/your-org/ad-automaton.git
cd ad-automaton
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Make the main script executable:
```bash
chmod +x ad_automaton.py
```

4. Create default configuration:
```bash
python ad_automaton.py init --db test.db
```

## 🚀 Quick Start

### 1. Initialize Database
```bash
python ad_automaton.py init --db engagement.db
```

### 2. Run Network Reconnaissance
```bash
python ad_automaton.py recon --db engagement.db -t 192.168.1.0/24 --profile stealth
```

### 3. Authenticated Enumeration (if you have credentials)
```bash
python ad_automaton.py enum --db engagement.db --creds-file credentials.txt
```

### 4. Full Attack Chain
```bash
python ad_automaton.py full-run --db engagement.db -t 192.168.1.0/24 --enable-mitm -i eth0
```

### 5. Generate Report
```bash
python ad_automaton.py report --db engagement.db --format markdown --output report.md
```

## 📖 Usage Examples

### Stealth Reconnaissance
```bash
# Minimal footprint scanning
python ad_automaton.py recon --db stealth_test.db -t 10.0.0.0/16 --profile stealth
```

### Aggressive Enumeration
```bash
# Maximum speed, all techniques enabled
python ad_automaton.py full-run --db aggressive_test.db -t 192.168.1.0/24 --profile noisy
```

### Credential Spraying
```bash
# Test known credentials across the network
python ad_automaton.py enum --db test.db --creds-file passwords.txt
```

### Man-in-the-Middle Attacks
```bash
# Launch IPv6 DNS takeover and NTLM relay
python ad_automaton.py mitm --db test.db -i eth0 --attack-type mitm6
```

### Certificate Attacks
```bash
# Enumerate and exploit AD CS vulnerabilities
python ad_automaton.py adcs --db test.db --enable-coercion
```

## ⚙️ Configuration

The framework uses YAML configuration files for customization. The default configuration is located at `config/default.yaml`.

### OPSEC Profiles

- **Stealth**: Minimal footprint, slower scans, avoids detection
- **Normal**: Balanced approach between speed and stealth
- **Noisy**: Maximum speed, all techniques enabled

### Tool Configuration

Customize tool paths and arguments in the configuration file:

```yaml
tools:
  nmap:
    path: nmap
    timing_template: -T3
    max_rate: 1000
  crackmapexec:
    path: crackmapexec
    threads: 50
    timeout: 30
```

## 🗄️ Database Schema

AD-Automaton uses SQLite for persistent state management. The database schema includes:

- **Hosts**: Network hosts and their properties
- **Services**: Open ports and service information
- **Users**: Domain user accounts
- **Groups**: Domain groups and memberships
- **Credentials**: Discovered passwords and hashes
- **Valid_Credentials**: Mapping of credentials to hosts
- **Vulnerabilities**: Security findings
- **Shares**: SMB shares and permissions
- **Loot**: Captured data and files

## 📊 Reporting

Generate comprehensive reports in multiple formats:

```bash
# Markdown report
python ad_automaton.py report --db test.db --format markdown

# CSV export for credentials
python ad_automaton.py report --db test.db --format csv --show-credentials

# JSON export for programmatic analysis
python ad_automaton.py report --db test.db --format json
```

## 🔧 Advanced Usage

### Custom Module Development

Extend the framework by creating custom modules in the `modules/` directory. Each module should implement the standard interface and integrate with the database manager.

### Configuration Profiles

Create custom OPSEC profiles by modifying the configuration file:

```yaml
profiles:
  custom:
    description: "Custom profile for specific engagement"
    tools:
      nmap:
        timing_template: -T2
        additional_args: "--source-port 443"
```

### Database Queries

Access the SQLite database directly for custom analysis:

```python
from lib.database import DatabaseManager

db = DatabaseManager('engagement.db')
hosts = db.get_hosts()
dcs = db.get_dcs()
stats = db.get_statistics()
```

## 🛡️ OPSEC Considerations

- **Stealth Profile**: Use for sensitive environments with strong security monitoring
- **Traffic Patterns**: The framework can randomize scan timing and source ports
- **Logging**: All activities are logged for audit purposes
- **Tool Selection**: Different enumeration methods can be selected based on environment

## 🐛 Troubleshooting

### Common Issues

1. **Tool Not Found**: Ensure all required tools are installed and in PATH
2. **Permission Denied**: Some operations require root privileges
3. **Database Locked**: Only one instance should access the database at a time
4. **Network Timeouts**: Adjust timeout values in configuration for slow networks

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
python ad_automaton.py --verbose recon --db test.db -t 192.168.1.0/24
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Module Development](docs/development.md)
- [Database Schema](docs/database.md)
- [API Reference](docs/api.md)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Active Directory Security](https://adsecurity.org/)
- [Red Team Field Manual](https://github.com/tanprathan/RTFM)

## 📞 Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Discussions**: Join community discussions in GitHub Discussions
- **Security**: Report security vulnerabilities privately to security@example.com

## 🙏 Acknowledgments

- The security research community for developing the techniques implemented
- Tool authors: nmap, Impacket, CrackMapExec, Responder, Certipy teams
- Contributors and beta testers

---

**Remember: Always obtain proper authorization before using this tool. Unauthorized access to computer systems is illegal.**
