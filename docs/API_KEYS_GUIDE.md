# Sentinel — API Keys Guide

## Required Keys

### ipinfo.io (IP Geolocation)
- **Used for:** IP address lookups, geolocation, ASN info in Network Monitor
- **Free tier:** 50,000 requests/month
- **Get key:**
  1. Go to https://ipinfo.io/signup
  2. Create account (email only, no credit card)
  3. Copy token from dashboard
  4. Paste into `.env` as `IPINFO_TOKEN`

## Recommended Keys

### VirusTotal (Malware/URL Scanning)
- **Used for:** URL scanning, file hash lookups in Threat Intelligence
- **Free tier:** 500 lookups/day, 4 lookups/minute
- **Get key:**
  1. Go to https://www.virustotal.com/gui/join-us
  2. Create account
  3. Go to Profile → API Key
  4. Paste into `.env` as `VIRUSTOTAL_API_KEY`

### AbuseIPDB (IP Reputation)
- **Used for:** Checking if IPs are known for malicious activity
- **Free tier:** 1,000 checks/day
- **Get key:**
  1. Go to https://www.abuseipdb.com/register
  2. Create account
  3. Go to API → Create Key
  4. Paste into `.env` as `ABUSEIPDB_API_KEY`

## Optional Keys

### Shodan
- **Used for:** Advanced port scanning, service detection
- **Free tier:** Limited queries
- **Get key:** https://account.shodan.io/register

### MaxMind GeoLite2
- **Used for:** Higher accuracy IP geolocation (offline database)
- **Free tier:** Unlimited (local database)
- **Get key:** https://www.maxmind.com/en/geolite2/signup

## Running Without Keys

Sentinel works without any API keys, but with reduced functionality:
- IP lookups will show "No API key configured" instead of geolocation data
- URL scanning will only work through ARGUS (local sandbox)
- IP reputation checks will be unavailable

Add keys anytime — no restart required, changes are picked up automatically.
