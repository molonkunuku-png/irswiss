# recon-swiss-army (rswiss)

Lightweight recon toolkit for HTB / TryHackMe / authorized testing.

Single-file, zero heavy dependencies, works on any modern Python.

## Modules

```
rswiss subdomain   --domain example.com [--wordlist path] [--output subs.txt]
rswiss nmap        --file nmap-output.txt
rswiss headers     --target 10.10.10.10 [--https]
rswiss fingerprint --target 10.10.10.10 [--https]
rswiss portscan    --target 10.10.10.10
```

### subdomain
Brute-forces subdomains using a wordlist. Defaults to seclists top-5000.

### nmap
Parses nmap grepable/normal output and lists only open ports + services.

### headers
Grabs HTTP response headers from a target.

### fingerprint
Lightweight tech fingerprinting from headers, cookies, meta tags, and page title.

### portscan
Quick top-100 TCP port scan (no nmap needed).

## Usage

```bash
chmod +x rswiss.py
./rswiss.py portscan --target 10.10.10.10
./rswiss.py headers --target example.com --https
```

## Todo

- [ ] Add DNS zone-transfer check
- [ ] Add directory busting module
- [ ] Add banner grabber
- [ ] JSON output mode

## Legal

Use only on systems you own or have explicit written authorization to test.
