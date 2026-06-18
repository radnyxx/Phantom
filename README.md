# Phantom

Personal threat intelligence toolkit. Works **out of the box with no API keys** using DNS blocklists, Spamhaus DROP, RDAP, URLScan public search, and local port probing. Optionally add free-tier API keys for enhanced mode with richer data from VirusTotal, AbuseIPDB, Shodan, and URLScan.io.

Includes a C extension for fast local hash verification against bundled IOCs.

## Modules

| Module | Purpose |
|--------|---------|
| `intel/` | Zero-key sources + optional API integrations |
| `analyzer/` | Risk scoring engine (LOW → CRITICAL) |
| `reporter/` | Markdown reports + rich terminal dashboard |
| `hashcheck.c` | C extension for local IOC hash lookup |

## Setup

```bash
# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Build the C extension
python setup.py build_ext --inplace
```

No signup or API keys required. Clone and run immediately.

### Optional: Enhanced mode

Add a `.env` file for deeper intel (multi-engine AV verdicts, AbuseIPDB scores, full Shodan host data):

```bash
cp .env.example .env
# Edit .env with your free-tier API keys
```

| Service | Signup |
|---------|--------|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | Free tier |
| [AbuseIPDB](https://www.abuseipdb.com/register) | Free tier |
| [Shodan](https://account.shodan.io/register) | Free tier |
| [URLScan.io](https://urlscan.io/user/signup) | Free tier |

### Optional: Refresh threat feeds

```bash
python scripts/update_feeds.py   # updates Spamhaus DROP cache (max once/day)
```

## Usage

```bash
# Zero-key scan — works immediately
python phantom.py 8.8.8.8

# Scan a domain
python phantom.py example.com

# Check a file hash (local IOC + optional VT if key configured)
python phantom.py 44d88612fea8a8f36de82e1278abb02f

# Local hash check only (C extension)
python phantom.py --hash-only 44d88612fea8a8f36de82e1278abb02f

# Skip active port probing
python phantom.py 1.2.3.4 --no-portscan

# Custom report path, no dashboard
python phantom.py 1.2.3.4 -o /tmp/scan.md --no-dashboard
```

## Intel modes

| Mode | When | Sources |
|------|------|---------|
| **Free (default)** | No `.env` keys | DNS blocklists, Spamhaus DROP, RDAP, URLScan public, port scan, local IOC |
| **Enhanced** | Any API key in `.env` | Above APIs + free sources fill gaps for missing keys |

## Risk Scoring

| Finding | Points |
|---------|--------|
| Known malicious | +40 |
| Suspicious ports (per port) | +15 |
| Recent WHOIS change | +20 |

| Level | Score |
|-------|-------|
| LOW | 0–25 |
| MEDIUM | 26–50 |
| HIGH | 51–75 |
| CRITICAL | 76+ |

## Caveats

- **DNS blocklists** may return incomplete results on public DNS resolvers (Cloudflare, Google). Phantom notes this gracefully.
- **Port scanning** is active reconnaissance on the target IP. Use `--no-portscan` to disable.
- **URLScan public search** is IP-rate-limited (~30/min) — fine for personal use.
- **Enhanced mode** adds VT engine counts, AbuseIPDB confidence scores, and full Shodan metadata not available in zero-key mode.

## Project Structure

```
phantom/
├── phantom.py              # CLI entry point
├── intel/
│   ├── queries.py          # API + routing logic
│   ├── free_sources.py     # Zero-key intel (DNSBL, DROP, RDAP, URLScan)
│   └── portscan.py         # Local suspicious-port probe
├── analyzer/
│   └── scorer.py           # Risk scoring engine
├── reporter/
│   ├── markdown.py         # Markdown report generator
│   └── dashboard.py        # Rich terminal UI
├── scripts/
│   └── update_feeds.py     # Optional feed refresh
├── hashcheck.c             # C extension source
├── data/
│   ├── iocs.txt            # Bundled IOC hash list
│   └── feeds/              # Cached blocklist data
├── requirements.txt
└── .env.example            # Optional API keys
```

## License

MIT
