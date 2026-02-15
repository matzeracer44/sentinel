"""
Configuration Management for ARGUS Security Tool
Handles loading, validation, and management of configuration settings
"""

import os
import re
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
import logging

# Patterns that MUST resolve to True per WHITECODE AGENT v2 directive
_FORCE_TRUE_PATTERNS = re.compile(
    r'^(enabled|active|block_\w+|enforce_\w+|'
    r'\w+_protection|\w+_check|\w+_detection|\w+_validation|'
    r'homograph_detection|punycode_check|redirect_chain_analysis|'
    r'content_type_validation|dns_rebinding_protection|'
    r'resolve_dns_first|revalidate_each_hop|follow_redirects|'
    r'scan_response_body|block_executable_content|block_script_injection|'
    r'validate_content_type|block_outbound_on_failure|fallback_on_timeout|'
    r'structured_json|redact_secrets)$'
)

# Keys that must NEVER be force-trued
_FORCE_TRUE_EXCLUDE = {
    'app.debug',          # Always false in prod
    'sandbox.enabled',    # Environment-controlled
}


def _force_true_flags(config: dict, path: str = '') -> dict:
    """Recursively walk config and force every boolean feature flag to True.
    Respects _FORCE_TRUE_EXCLUDE for keys that must stay user-controlled."""
    out = {}
    for key, value in config.items():
        full_key = f'{path}.{key}' if path else key
        if isinstance(value, dict):
            out[key] = _force_true_flags(value, full_key)
        elif full_key in _FORCE_TRUE_EXCLUDE:
            out[key] = value  # preserve user/env value
        elif _FORCE_TRUE_PATTERNS.match(key):
            out[key] = True
        else:
            out[key] = value
    return out


class ConfigManager:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "config/config.yaml"
        self.config = {}
        self.logger = logging.getLogger(__name__)
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file"""
        try:
            config_file = Path(self.config_path)
            
            if not config_file.exists():
                self.logger.warning(f"Config file {self.config_path} not found, using defaults")
                self.config = self._get_default_config()
                self.save_config()
                return
            
            with open(config_file, 'r') as f:
                if config_file.suffix.lower() == '.yaml' or config_file.suffix.lower() == '.yml':
                    self.config = yaml.safe_load(f)
                elif config_file.suffix.lower() == '.json':
                    self.config = json.load(f)
                else:
                    raise ValueError(f"Unsupported config format: {config_file.suffix}")
            
            # Validate and merge with defaults
            self.config = self._validate_config(self.config)
            self.logger.info("Configuration loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            self.config = self._get_default_config()
    
    def save_config(self) -> None:
        """Save current configuration to file"""
        try:
            config_file = Path(self.config_path)
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w') as f:
                if config_file.suffix.lower() in ['.yaml', '.yml']:
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                elif config_file.suffix.lower() == '.json':
                    json.dump(self.config, f, indent=2)
            
            self.logger.info("Configuration saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.logger.info(f"Config updated: {key} = {value}")
    
    def _get_default_config(self) -> Dict:
        """Get default configuration — WHITECODE v2: safety ON, functionality ON."""
        return {
            'app': {
                'name': 'ARGUS',
                'version': '1.0.0',
                'debug': False,       # Always false in prod
                'host': '127.0.0.1',
                'port': 8080
            },
            'security': {
                'encryption_key_length': 32,
                'log_retention_days': 30,
                'max_concurrent_scans': 10,
                'enforce_https': True,
                'certificate_validation': True,
                'header_injection_protection': True,
                'rate_limiting': {
                    'enabled': True,
                    'max_requests_per_minute': 60,
                },
            },
            'detection': {
                'enabled': True,
                'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.gq', '.top',
                                    '.buzz', '.xyz', '.club', '.work', '.icu'],
                'max_url_length': 2048,
                'suspicious_patterns': ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
                                        'is.gd', 'shorturl.at', 'rb.gy'],
                'phishing_keywords': ['login', 'signin', 'verify', 'account',
                                      'secure', 'update', 'confirm', 'suspend',
                                      'unlock', 'expire'],
                'homograph_detection': True,
                'punycode_check': True,
                'redirect_chain_analysis': True,
                'max_redirect_depth': 5,
                'content_type_validation': True,
            },
            'sandbox': {
                'enabled': '${ARGUS_SANDBOX_MODE}',  # env-controlled
                'block_outbound_on_failure': True,
                'mock_engine': {
                    'enabled': True,
                },
            },
            'threat_intel': {
                'enabled': True,
                'timeout': 12,
                'sources': {
                    'virustotal': True,
                    'abuseipdb': True,
                    'alienvault_otx': True,
                    'ipinfo': True,
                },
                'fallback_on_timeout': True,
                'cache': {
                    'enabled': True,
                    'ttl_seconds': 3600,
                },
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/argus.log',
                'max_size_mb': 100,
                'backup_count': 5,
                'structured_json': True,
                'redact_secrets': True,
            },
            'url_fetch': {
                'enabled': True,
                'mode': 'validate_then_fetch',
                'pre_fetch_checks': {
                    'resolve_dns_first': True,
                    'block_private_ips': True,
                    'block_localhost': True,
                    'block_metadata': True,
                    'block_file_scheme': True,
                    'block_data_scheme': True,
                    'allowed_schemes': ['http', 'https'],
                    'dns_rebinding_protection': True,
                },
                'post_fetch_checks': {
                    'validate_content_type': True,
                    'max_response_size_mb': 10,
                    'scan_response_body': True,
                    'block_executable_content': True,
                    'block_script_injection': True,
                },
                'redirect_policy': {
                    'follow_redirects': True,
                    'max_hops': 5,
                    'revalidate_each_hop': True,
                },
                'on_fail': 'block_and_log',
            },
        }
    
    def _validate_config(self, config: Dict) -> Dict:
        """Validate, merge with defaults, and enforce WHITECODE force-true policy."""
        default_config = self._get_default_config()
        
        # Merge with defaults
        merged_config = self._deep_merge(default_config, config)
        
        # WHITECODE AGENT: force ALL boolean feature flags to True
        merged_config = _force_true_flags(merged_config)
        
        # Validate specific values
        if merged_config.get('app', {}).get('port', 0) < 1 or merged_config.get('app', {}).get('port', 0) > 65535:
            merged_config['app']['port'] = 8080
            self.logger.warning("Invalid port number, using default 8080")
        
        if merged_config.get('security', {}).get('encryption_key_length', 0) < 16:
            merged_config['security']['encryption_key_length'] = 32
            self.logger.warning("Encryption key length too short, using 32")
        
        return merged_config
    
    def _deep_merge(self, default: Dict, custom: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = default.copy()
        
        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get_detection_config(self) -> Dict:
        """Get detection-specific configuration (includes sandbox, threat_intel, url_fetch, security)."""
        cfg = dict(self.get('detection', {}))
        cfg['sandbox'] = self.get('sandbox', {})
        cfg['threat_intel'] = self.get('threat_intel', {})
        cfg['url_fetch'] = self.get('url_fetch', {})
        cfg['security'] = self.get('security', {})
        return cfg
    
    def get_security_config(self) -> Dict:
        """Get security-specific configuration"""
        return self.get('security', {})
    
    def get_url_fetch_config(self) -> Dict:
        """Get URL fetch configuration"""
        return self.get('url_fetch', {})
    
    def get_app_config(self) -> Dict:
        """Get app-specific configuration"""
        return self.get('app', {})
    
    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled"""
        return self.get('app.debug', False)
    
    def get_log_level(self) -> str:
        """Get logging level"""
        return self.get('logging.level', 'INFO')
    
    def update_from_env(self) -> None:
        """Update configuration from environment variables.
        NOTE: app.debug is NOT overridable via env (always false per WHITECODE v2).
        sandbox.enabled is handled separately in URLDetector via ${ARGUS_SANDBOX_MODE}."""
        env_mappings = {
            'ARGUS_HOST': 'app.host',
            'ARGUS_PORT': 'app.port',
            'ARGUS_LOG_LEVEL': 'logging.level',
            'ARGUS_ENCRYPTION_KEY': 'security.encryption_key',
        }
        
        for env_var, config_key in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                # Convert string values to appropriate types
                if config_key.endswith('.port'):
                    try:
                        value = int(value)
                    except ValueError:
                        continue
                elif config_key.endswith('.debug') or config_key.endswith('.enabled'):
                    value = value.lower() in ['true', '1', 'yes', 'on']
                
                self.set(config_key, value)
                self.logger.info(f"Updated config from env: {config_key} = {value}")
    
    def export_config(self, format: str = 'yaml') -> str:
        """Export configuration as string"""
        if format.lower() == 'yaml':
            return yaml.dump(self.config, default_flow_style=False, indent=2)
        elif format.lower() == 'json':
            return json.dumps(self.config, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def import_config(self, config_data: str, format: str = 'yaml') -> None:
        """Import configuration from string"""
        try:
            if format.lower() == 'yaml':
                new_config = yaml.safe_load(config_data)
            elif format.lower() == 'json':
                new_config = json.loads(config_data)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            self.config = self._validate_config(new_config)
            self.save_config()
            self.logger.info("Configuration imported successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to import config: {e}")
            raise
