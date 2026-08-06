# Irene Swiss

```
 ____  _   _  ____  _____ 
|  _ \| \ | |/ __ \|  ___|
| |_) |  \| | |  | | |_   
|  _ <| . ` | |  | |  _|  
| |_) | |\  | |__| | |    
|____/|_| \_\____/|_|  
```

**Irene Swiss** — lightweight recon toolkit. Subdomain brute-force, nmap parser, HTTP headers, fingerprinting, and quick port scan. Single-file Python, zero heavy dependencies.

## Usage

```bash
chmod +x irswiss.py
./irswiss.py --help
./irswiss.py portscan --target 10.10.10.10
./irswiss.py headers --target example.com --https
./irswiss.py fingerprint --target 10.10.10.10
./irswiss.py subdomain --domain example.com [--wordlist path] [--output subs.txt]
./irswiss.py nmap --file nmap-output.txt
```

## Modules

| Module | Description |
|---|---|
| `portscan` | Quick top-100 TCP port scan |
| `headers` | HTTP response headers |
| `fingerprint` | Server, X-Powered-By, cookies, meta tags, title |
| `subdomain` | Subdomain brute-force with wordlist |
| `nmap` | Parse nmap output for open ports |

## Requirements

- Python 3.7+
- `seclists` for subdomain wordlists (default: `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`)

## Legal

MIT License. See [LICENSE](LICENSE) for full text.

Disclaimer

This tool is for authorized security testing only. The author is not responsible for misuse or damages. This is not legal advice.
