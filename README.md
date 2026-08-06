# Irene Swiss

```
 ____  _   _  ____  _____ 
|  _ \| \ | |/ __ \|  ___|
| |_) |  \| | |  | | |_  
|  _ <| . ` | |  | |  _| 
| |_) | |\  | |__| | |   
|____/|_| \_\____/|_| 
```

**Irene Swiss** v1.2.0 — lightweight recon toolkit. Subdomain brute-force, nmap parser, HTTP headers, fingerprinting, quick port scan, DNS lookup, TLS info, banner grabber. Single-file Python, zero heavy dependencies.

## Usage

```bash
chmod +x irswiss.py
./irswiss.py --help
```

## Modules

| Module | Description |
|---|---|
| `subdomain` | Subdomain brute-force with wordlist + concurrency |
| `nmap` | Parse nmap output for open ports |
| `headers` | HTTP response headers |
| `fingerprint` | Server, X-Powered-By, cookies, meta tags, title |
| `portscan` | Quick top-100 TCP port scan |
| `dns` | A/AAAA records, optional TXT via dig |
| `tls` | TLS version, cipher, cert subject/issuer/dates |
| `banner` | HTTP/TCP service banner grab |

## Common Flags

```bash
--json          Output JSON instead of text
--output, -o    Write results to file
--timeout       Request timeout in seconds (default: 10)
--workers       Concurrent workers (0 = auto)
--delay         Delay between batches for rate limiting
--no-verify     Disable TLS verification
--quiet, -q     JSON-only, no banner
```

## Examples

```bash
# Subdomain brute-force
./irswiss.py subdomain --domain example.com --wordlist /path/to/wordlist.txt --output subs.txt

# Quick port scan
./irswiss.py portscan --target 10.10.10.10

# HTTP headers
./irswiss.py headers --target example.com --https --json -o headers.json

# Tech fingerprint
./irswiss.py fingerprint --target 10.10.10.10

# DNS lookup
./irswiss.py dns --target example.com --txt

# TLS certificate info
./irswiss.py tls --target example.com

# Banner grab
./irswiss.py banner --target example.com:80
```

## Requirements

- Python 3.7+
- `seclists` for subdomain wordlists (default: `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`)
- `dig` (optional, for `dns --txt`)

## Legal

MIT License. See [LICENSE](LICENSE) for full text.

Disclaimer

This tool is for authorized security testing only. The author is not responsible for misuse or damages. This is not legal advice.
