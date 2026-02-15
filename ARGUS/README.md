# �️ ARGUS — The All-Seeing Security Tool

> *Named after [Argus Panoptes](https://en.wikipedia.org/wiki/Argus_Panoptes), the hundred-eyed giant of Greek mythology who was the ever-watchful guardian.*

A comprehensive local security tool for URL threat detection, encryption, and activity backtracing.

## Features

### 🔍 **Malicious URL Detection**
- Advanced threat analysis with multiple detection algorithms
- Phishing and malware detection
- Suspicious pattern recognition
- Domain reputation checking
- WHOIS and DNS analysis

### 🔐 **Encryption & Decryption**
- AES-256 encryption for sensitive data
- Secure key derivation using PBKDF2
- Hash generation for data integrity
- Dictionary encryption support

### 📊 **Activity Backtracing**
- Real-time system monitoring
- Network connection tracking
- Process monitoring
- Comprehensive activity logging
- Session management and export

### 🌐 **Web Interface**
- Modern Flask-based dashboard
- Real-time security monitoring
- Interactive URL scanner
- Encryption tools
- Activity visualization

## Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd ARGUS
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the tool:**
```bash
python main.py --help
```

## Usage

### Command Line Interface

#### **URL Scanning**
```bash
# Scan single URL
python main.py --url https://example.com

# Scan multiple URLs from file
python main.py --urls urls.txt
```

#### **Encryption/Decryption**
```bash
# Encrypt data
python main.py --encrypt "sensitive information"

# Decrypt data
python main.py --decrypt "gAAAAABh..."
```

#### **Web Interface**
```bash
# Start web dashboard
python main.py --web
```

#### **Session Management**
```bash
# View session summary
python main.py --summary

# View suspicious activities
python main.py --suspicious

# Export session data
python main.py --export json
```

### Web Interface

1. Start the web server:
```bash
python main.py --web
```

2. Open your browser and navigate to:
```
http://127.0.0.1:8080
```

3. Use the dashboard to:
- Scan URLs interactively
- Encrypt/decrypt data
- Monitor system activities
- View security statistics

## Configuration

The tool uses `config/config.yaml` for configuration. Key settings:

```yaml
app:
  host: "127.0.0.1"
  port: 8080
  debug: false

detection:
  suspicious_tlds: ['.tk', '.ml', '.ga']
  max_url_length: 2048
  phishing_keywords: ['login', 'signin', 'verify']

security:
  encryption_key_length: 32
  log_retention_days: 30

backtrace:
  enabled: true
  capture_network: true
  capture_processes: true
```

### Environment Variables

- `ARGUS_HOST` - Web server host
- `ARGUS_PORT` - Web server port
- `ARGUS_DEBUG` - Enable debug mode
- `ARGUS_ENCRYPTION_KEY` - Custom encryption key

## API Endpoints

### URL Scanning
```http
POST /api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

### Batch Scanning
```http
POST /api/batch_scan
Content-Type: application/json

{
  "urls": ["https://site1.com", "https://site2.com"]
}
```

### Encryption
```http
POST /api/encrypt
Content-Type: application/json

{
  "data": "sensitive information"
}
```

### Decryption
```http
POST /api/decrypt
Content-Type: application/json

{
  "encrypted_data": "gAAAAABh..."
}
```

### Session Data
```http
GET /api/session
GET /api/activities?hours=24
GET /api/suspicious
```

## Security Features

### **Threat Detection Levels**
- 🟢 **SAFE** - No threats detected
- 🟡 **SUSPICIOUS** - Potential risks found
- 🔴 **MALICIOUS** - Clear threats detected

### **Detection Methods**
- URL structure analysis
- Domain reputation checking
- Suspicious TLD detection
- Phishing keyword matching
- Network monitoring
- Process tracking

### **Data Protection**
- All sensitive data encrypted at rest
- Secure key derivation
- Activity logging with integrity checks
- Configurable data retention

## Project Structure

```
ARGUS/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── config/
│   └── config.yaml        # Configuration file
├── src/
│   ├── core/
│   │   └── config_manager.py
│   ├── detectors/
│   │   └── url_detector.py
│   ├── utils/
│   │   └── encryption.py
│   ├── backtrace/
│   │   └── backtracer.py
│   └── web/
│       └── app.py
├── data/
│   └── backtrace/         # Activity logs
├── logs/                   # Application logs
└── README.md
```

## Examples

### **Basic URL Scan**
```python
from main import Argus

tool = Argus()
result = tool.scan_url("https://suspicious-site.com")

if result['threat_level'] == 'MALICIOUS':
    print("⚠️ Malicious URL detected!")
    print(f"Reasons: {', '.join(result['reasons'])}")
```

### **Batch Processing**
```python
urls = [
    "https://legitimate-site.com",
    "https://suspicious-site.net",
    "https://malware-domain.org"
]

results = tool.scan_urls(urls)
for result in results:
    status = "🔴" if result['threat_level'] == 'MALICIOUS' else "🟡" if result['threat_level'] == 'SUSPICIOUS' else "🟢"
    print(f"{status} {result['url']} - {result['threat_level']}")
```

### **Data Encryption**
```python
sensitive_data = "user_credentials_123"
encrypted = tool.encrypt_data(sensitive_data)
print(f"Encrypted: {encrypted}")

decrypted = tool.decrypt_data(encrypted)
print(f"Decrypted: {decrypted}")
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Default Encryption Key**: Change the default encryption key before production use
2. **Network Access**: The tool runs locally and doesn't require internet for basic operations
3. **Data Storage**: All sensitive data is encrypted before storage
4. **Monitoring**: System monitoring captures process and network information
5. **Logs**: Activity logs contain sensitive information and should be protected

## Troubleshooting

### **Common Issues**

1. **Port Already in Use**
```bash
# Change port in config.yaml or use environment variable
set ARGUS_PORT=8081
python main.py --web
```

2. **Missing Dependencies**
```bash
# Install all required packages
pip install -r requirements.txt
```

3. **Permission Errors**
```bash
# Run with appropriate permissions
sudo python main.py --web
```

4. **Configuration Issues**
```bash
# Reset to default configuration
rm config/config.yaml
python main.py  # Will recreate with defaults
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is for educational and research purposes. Use responsibly and in accordance with applicable laws and regulations.

## Disclaimer

This tool is designed for legitimate security research and testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors are not responsible for any misuse of this software.
