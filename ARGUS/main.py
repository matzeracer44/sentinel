#!/usr/bin/env python3
"""
ARGUS - The All-Seeing Security Tool
Named after Argus Panoptes, the hundred-eyed giant of Greek mythology.
Local security tool for URL threat detection and encryption.
"""

import os
import sys
import argparse
import logging
import threading
from pathlib import Path
from dotenv import load_dotenv

# Load API keys from .env file (project root)
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.core.config_manager import ConfigManager
from src.core.scan_cache import ScanCache
from src.utils.encryption import EncryptionManager
from src.detectors.url_detector import URLDetector

class Argus:
    def __init__(self, config_path: str = None):
        # Initialize configuration
        self.config_manager = ConfigManager(config_path)
        self.config_manager.update_from_env()
        
        # Setup logging
        self._setup_logging()
        
        # Initialize components
        self.encryption = EncryptionManager()
        self.url_detector = URLDetector(self.config_manager.get_detection_config())
        self.scan_cache = ScanCache()
        
        self.logger.info("ARGUS initialized — all eyes open")
    
    def _setup_logging(self):
        """Setup application logging with structured JSON + secret redaction."""
        log_config = self.config_manager.get('logging', {})
        # Level from config; DEBUG only if app.debug=true, otherwise respect config (default INFO)
        cfg_level = log_config.get('level', 'INFO').upper()
        if self.config_manager.get('app.debug', False):
            cfg_level = 'DEBUG'
        log_level = getattr(logging, cfg_level, logging.INFO)
        log_file = log_config.get('file', 'logs/argus.log')
        use_json = log_config.get('structured_json', True)
        redact = log_config.get('redact_secrets', True)

        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        # Secret redaction filter
        if redact:
            _secrets = set()
            for env_key in ('ARGUS_VIRUSTOTAL_KEY', 'ARGUS_ABUSEIPDB_KEY',
                            'ARGUS_OTX_KEY', 'ARGUS_IPINFO_TOKEN', 'FLASK_SECRET_KEY'):
                v = os.environ.get(env_key, '')
                if v and len(v) > 6:
                    _secrets.add(v)

            class _RedactFilter(logging.Filter):
                def filter(self, record):
                    msg = record.getMessage()
                    for s in _secrets:
                        if s in msg:
                            record.msg = str(record.msg).replace(s, '***REDACTED***')
                            if record.args:
                                record.args = tuple(
                                    str(a).replace(s, '***REDACTED***') if isinstance(a, str) else a
                                    for a in record.args
                                ) if isinstance(record.args, tuple) else record.args
                    return True

            redact_filter = _RedactFilter()
        else:
            redact_filter = None

        # Format
        if use_json:
            fmt = '{"time":"%(asctime)s","logger":"%(name)s","level":"%(levelname)s","msg":"%(message)s"}'
        else:
            fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(fmt))
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        if redact_filter:
            file_handler.addFilter(redact_filter)
            stream_handler.addFilter(redact_filter)

        logging.basicConfig(
            level=log_level,
            handlers=[file_handler, stream_handler]
        )
        self.logger = logging.getLogger('argus')
    
    SCAN_TIMEOUT = 45  # seconds — hard limit so Flask never hangs

    def scan_url(self, url: str, force: bool = False) -> dict:
        """Scan a single URL for threats. Uses cache unless force=True."""
        self.logger.info(f"Scanning URL: {url}")
        
        # Check cache first (skip if forced re-scan)
        if not force:
            cached = self.scan_cache.get(url)
            if cached:
                self.logger.info(f"Cache hit for {url}")
                cached['from_cache'] = True
                return cached
        
        # Run the actual scan in a thread with a hard timeout
        result_box = [None]
        error_box = [None]

        def _do_scan():
            try:
                result_box[0] = self.url_detector.analyze_url(url)
            except Exception as e:
                error_box[0] = e

        t = threading.Thread(target=_do_scan, daemon=True)
        t.start()
        t.join(timeout=self.SCAN_TIMEOUT)

        if t.is_alive():
            self.logger.warning(f"Scan timed out after {self.SCAN_TIMEOUT}s for {url}")
            return {
                'url': url,
                'threat_level': 'UNKNOWN',
                'threat_score': 0,
                'reasons': [f'Scan timed out after {self.SCAN_TIMEOUT}s'],
                'intel': {},
                'error': f'Scan timed out after {self.SCAN_TIMEOUT} seconds'
            }

        if error_box[0]:
            self.logger.error(f"URL scan failed: {error_box[0]}")
            return {
                'url': url,
                'threat_level': 'UNKNOWN',
                'error': str(error_box[0])
            }

        result = result_box[0]
        if not result:
            return {'url': url, 'threat_level': 'UNKNOWN', 'error': 'No result'}

        try:
            # Strip large internal fields before caching/returning
            intel = result.get('intel', {})
            http_data = intel.get('http', {})
            if isinstance(http_data, dict):
                http_data.pop('_body_snippet', None)
                http_data.pop('all_headers', None)
            
            # Encrypt sensitive intel if threat is elevated
            if result['threat_level'] in ['SUSPICIOUS', 'MALICIOUS', 'CRITICAL']:
                encrypted_details = self.encryption.encrypt_dict(result.get('intel', {}))
                result['encrypted_intel'] = encrypted_details
            
            # Store in cache
            self.scan_cache.put(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"URL scan post-processing failed: {e}")
            return result
    
    def scan_urls(self, urls: list) -> list:
        """Scan multiple URLs"""
        self.logger.info(f"Scanning {len(urls)} URLs")
        
        results = []
        for url in urls:
            result = self.scan_url(url)
            results.append(result)
        
        return results
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        try:
            encrypted = self.encryption.encrypt(data)
            return encrypted
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        try:
            decrypted = self.encryption.decrypt(encrypted_data)
            return decrypted
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def start_web_interface(self):
        """Start the web interface"""
        try:
            from src.web.app import create_app
            app = create_app(self)
            
            host = self.config_manager.get('app.host', '127.0.0.1')
            port = self.config_manager.get('app.port', 8080)
            debug = self.config_manager.is_debug_mode()
            
            self.logger.info(f"Starting web interface on {host}:{port}")
            
            from werkzeug.serving import WSGIRequestHandler
            WSGIRequestHandler.server_version = 'ARGUS'
            WSGIRequestHandler.sys_version = ''
            app.run(host=host, port=port, debug=debug, threaded=True)
            
        except ImportError:
            self.logger.error("Web interface not available. Install Flask to enable web interface.")
            print("Web interface requires Flask. Install with: pip install flask")
        except Exception as e:
            self.logger.error(f"Failed to start web interface: {e}")
            raise
    
    def cleanup(self):
        """Cleanup resources — clear ephemeral scan cache"""
        self.logger.info("ARGUS shutting down")
        self.scan_cache.clear()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='ARGUS — The All-Seeing Security Tool')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--url', '-u', help='Scan single URL')
    parser.add_argument('--urls', '-l', help='File containing URLs to scan')
    parser.add_argument('--encrypt', '-e', help='Encrypt data')
    parser.add_argument('--decrypt', '-d', help='Decrypt data')
    parser.add_argument('--web', '-w', action='store_true', help='Start web interface')
    
    args = parser.parse_args()
    
    # Initialize tool
    tool = Argus(args.config)
    
    try:
        if args.url:
            # Scan single URL
            result = tool.scan_url(args.url)
            print(f"URL: {result['url']}")
            print(f"Threat Level: {result['threat_level']}")
            print(f"Threat Score: {result.get('threat_score', 0)}")
            if result.get('reasons'):
                print("Reasons:")
                for reason in result['reasons']:
                    print(f"  - {reason}")
        
        elif args.urls:
            # Scan URLs from file
            if os.path.exists(args.urls):
                with open(args.urls, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                
                results = tool.scan_urls(urls)
                
                for result in results:
                    status = "🔴" if result['threat_level'] == 'MALICIOUS' else \
                            "🟡" if result['threat_level'] == 'SUSPICIOUS' else "🟢"
                    print(f"{status} {result['url']} - {result['threat_level']}")
            else:
                print(f"File not found: {args.urls}")
        
        elif args.encrypt:
            # Encrypt data
            encrypted = tool.encrypt_data(args.encrypt)
            print(f"Encrypted: {encrypted}")
        
        elif args.decrypt:
            # Decrypt data
            try:
                decrypted = tool.decrypt_data(args.decrypt)
                print(f"Decrypted: {decrypted}")
            except Exception as e:
                print(f"Decryption failed: {e}")
        
        elif args.web:
            # Start web interface
            tool.start_web_interface()
        
        else:
            # Show help
            parser.print_help()
            print("\nExamples:")
            print("  python main.py --url https://example.com")
            print("  python main.py --urls urls.txt")
            print("  python main.py --encrypt 'sensitive data'")
            print("  python main.py --web")
            print("  python main.py --summary")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Application error: {e}")
    finally:
        tool.cleanup()

if __name__ == '__main__':
    main()
