#!/usr/bin/env python3
"""
Configuration Manager for AD-Automaton
Handles YAML configuration files and OPSEC profiles.
"""

import yaml
import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    """
    Manages configuration settings and OPSEC profiles for AD-Automaton.
    Handles loading YAML configuration files and profile switching.
    """
    
    DEFAULT_CONFIG = {
        'opsec_profile': 'normal',
        'tools': {
            'nmap': {
                'path': 'nmap',
                'timing_template': '-T3',
                'max_rate': '1000',
                'ping_sweep_args': '-sn',
                'port_scan_args': '-sV --open',
                'script_args': '--script-timeout=30s'
            },
            'crackmapexec': {
                'path': 'crackmapexec',
                'threads': '50',
                'timeout': '30',
                'delay': '0'
            },
            'impacket': {
                'base_path': '/usr/share/doc/python3-impacket/examples',
                'secretsdump_path': 'impacket-secretsdump',
                'getuserspns_path': 'impacket-GetUserSPNs',
                'ntlmrelayx_path': 'impacket-ntlmrelayx'
            },
            'responder': {
                'path': 'responder',
                'config_file': '/etc/responder/Responder.conf',
                'log_dir': '/var/log/responder'
            },
            'mitm6': {
                'path': 'mitm6',
                'log_file': '/tmp/mitm6.log'
            },
            'certipy': {
                'path': 'certipy',
                'timeout': '60'
            },
            'enum4linux_ng': {
                'path': 'enum4linux-ng',
                'timeout': '120'
            },
            'smbclient': {
                'path': 'smbclient',
                'timeout': '30'
            },
            'ldapsearch': {
                'path': 'ldapsearch',
                'timeout': '30'
            }
        },
        'network': {
            'timeout': '30',
            'retries': '3',
            'concurrent_threads': '10'
        },
        'database': {
            'backup_frequency': '1h',
            'max_backups': '5'
        },
        'reporting': {
            'include_screenshots': True,
            'include_raw_output': False,
            'redact_credentials': True
        }
    }
    
    OPSEC_PROFILES = {
        'stealth': {
            'name': 'Stealth',
            'description': 'Minimal footprint, slower scans, avoid detection',
            'settings': {
                'tools': {
                    'nmap': {
                        'timing_template': '-T1',
                        'max_rate': '100',
                        'additional_args': '--randomize-hosts --source-port 53'
                    },
                    'crackmapexec': {
                        'threads': '5',
                        'delay': '2'
                    }
                },
                'network': {
                    'concurrent_threads': '3',
                    'timeout': '60'
                },
                'features': {
                    'enable_responder': False,
                    'enable_mitm6': False,
                    'enable_coercion': False,
                    'smb_enumeration_method': 'samr_only'
                }
            }
        },
        'normal': {
            'name': 'Normal',
            'description': 'Balanced approach between speed and stealth',
            'settings': {
                'tools': {
                    'nmap': {
                        'timing_template': '-T3',
                        'max_rate': '1000'
                    },
                    'crackmapexec': {
                        'threads': '25',
                        'delay': '0'
                    }
                },
                'network': {
                    'concurrent_threads': '10'
                },
                'features': {
                    'enable_responder': True,
                    'enable_mitm6': True,
                    'enable_coercion': False,
                    'smb_enumeration_method': 'auto'
                }
            }
        },
        'noisy': {
            'name': 'Noisy',
            'description': 'Maximum speed, all techniques enabled',
            'settings': {
                'tools': {
                    'nmap': {
                        'timing_template': '-T4',
                        'max_rate': '5000',
                        'additional_args': '--min-parallelism 100'
                    },
                    'crackmapexec': {
                        'threads': '100',
                        'delay': '0'
                    }
                },
                'network': {
                    'concurrent_threads': '50'
                },
                'features': {
                    'enable_responder': True,
                    'enable_mitm6': True,
                    'enable_coercion': True,
                    'smb_enumeration_method': 'lsa_brute'
                }
            }
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the YAML configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path
        self.config = self.DEFAULT_CONFIG.copy()
        self.current_profile = 'normal'
        
        # Load configuration from file if provided
        if config_path and os.path.exists(config_path):
            self.load_config_file(config_path)
        elif config_path:
            self.logger.warning(f"Configuration file not found: {config_path}")
            self.logger.info("Using default configuration")
    
    def load_config_file(self, config_path: str) -> bool:
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the YAML configuration file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f)
            
            # Deep merge with default config
            self.config = self._deep_merge(self.DEFAULT_CONFIG.copy(), file_config)
            self.logger.info(f"Loaded configuration from {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration file {config_path}: {e}")
            return False
    
    def save_config_file(self, config_path: str) -> bool:
        """
        Save current configuration to a YAML file.
        
        Args:
            config_path: Path where to save the configuration
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(config_path)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with open(config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Saved configuration to {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration file {config_path}: {e}")
            return False
    
    def set_profile(self, profile_name: str) -> bool:
        """
        Set the OPSEC profile and apply its settings.
        
        Args:
            profile_name: Name of the profile ('stealth', 'normal', 'noisy')
            
        Returns:
            True if successful, False if profile not found
        """
        if profile_name not in self.OPSEC_PROFILES:
            self.logger.error(f"Unknown OPSEC profile: {profile_name}")
            self.logger.info(f"Available profiles: {list(self.OPSEC_PROFILES.keys())}")
            return False
        
        profile = self.OPSEC_PROFILES[profile_name]
        self.current_profile = profile_name
        
        # Apply profile settings
        self.config = self._deep_merge(self.config, profile['settings'])
        self.config['opsec_profile'] = profile_name
        
        self.logger.info(f"Applied OPSEC profile: {profile['name']} - {profile['description']}")
        return True
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get the current configuration.
        
        Returns:
            Current configuration dictionary
        """
        return self.config.copy()
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'tools.nmap.path')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'tools.nmap.path')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent dictionary
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
    
    def get_tool_path(self, tool_name: str) -> str:
        """
        Get the path for a specific tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Path to the tool executable
        """
        return self.get(f'tools.{tool_name}.path', tool_name)
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """
        Get the complete configuration for a tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool configuration dictionary
        """
        return self.get(f'tools.{tool_name}', {})
    
    def build_nmap_command(self, base_args: str, targets: str) -> str:
        """
        Build an nmap command with current profile settings.
        
        Args:
            base_args: Base nmap arguments
            targets: Target specification
            
        Returns:
            Complete nmap command string
        """
        nmap_config = self.get_tool_config('nmap')
        nmap_path = nmap_config.get('path', 'nmap')
        timing = nmap_config.get('timing_template', '-T3')
        max_rate = nmap_config.get('max_rate', '1000')
        additional_args = nmap_config.get('additional_args', '')
        
        command = f"{nmap_path} {timing} --max-rate {max_rate}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {base_args} {targets}"
        
        return command
    
    def build_cme_command(self, base_args: str) -> str:
        """
        Build a CrackMapExec command with current profile settings.
        
        Args:
            base_args: Base CME arguments
            
        Returns:
            Complete CME command string
        """
        cme_config = self.get_tool_config('crackmapexec')
        cme_path = cme_config.get('path', 'crackmapexec')
        threads = cme_config.get('threads', '25')
        timeout = cme_config.get('timeout', '30')
        delay = cme_config.get('delay', '0')
        
        command = f"{cme_path} --threads {threads} --timeout {timeout}"
        if delay != '0':
            command += f" --delay {delay}"
        command += f" {base_args}"
        
        return command
    
    def is_feature_enabled(self, feature_name: str) -> bool:
        """
        Check if a feature is enabled in the current profile.
        
        Args:
            feature_name: Name of the feature
            
        Returns:
            True if enabled, False otherwise
        """
        return self.get(f'features.{feature_name}', True)
    
    def get_profile_info(self) -> Dict[str, str]:
        """
        Get information about the current profile.
        
        Returns:
            Dictionary with profile name and description
        """
        if self.current_profile in self.OPSEC_PROFILES:
            profile = self.OPSEC_PROFILES[self.current_profile]
            return {
                'name': profile['name'],
                'description': profile['description'],
                'profile_key': self.current_profile
            }
        return {
            'name': 'Unknown',
            'description': 'Unknown profile',
            'profile_key': self.current_profile
        }
    
    def list_profiles(self) -> Dict[str, Dict[str, str]]:
        """
        List all available OPSEC profiles.
        
        Returns:
            Dictionary of profiles with their information
        """
        profiles = {}
        for key, profile in self.OPSEC_PROFILES.items():
            profiles[key] = {
                'name': profile['name'],
                'description': profile['description']
            }
        return profiles
    
    def validate_tools(self) -> Dict[str, bool]:
        """
        Validate that all configured tools are available.
        
        Returns:
            Dictionary mapping tool names to availability status
        """
        results = {}
        tools_config = self.get('tools', {})
        
        for tool_name, tool_config in tools_config.items():
            tool_path = tool_config.get('path', tool_name)
            
            # Check if tool is in PATH or absolute path exists
            if os.path.isabs(tool_path):
                results[tool_name] = os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)
            else:
                # Check PATH
                import shutil
                results[tool_name] = shutil.which(tool_path) is not None
        
        return results
    
    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge two dictionaries.
        
        Args:
            base: Base dictionary
            update: Dictionary to merge into base
            
        Returns:
            Merged dictionary
        """
        result = base.copy()
        
        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result

def create_default_config(config_path: str) -> bool:
    """
    Create a default configuration file.
    
    Args:
        config_path: Path where to create the configuration file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        config_manager = ConfigManager()
        return config_manager.save_config_file(config_path)
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to create default config: {e}")
        return False 