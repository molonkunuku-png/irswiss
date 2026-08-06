# recon-swiss-army (rswiss)

```
 _____ _       _____ _____    ____  _   _    _    _   _  ____  _____
/ ____| |     / ____|  __ \  / __ \| \ | |  / \  | \ | |/ __ \|  ___|
| |    | |    | (___ | |__) || |  | |  \| | / _ \ |  \| | |  | | |_
| |    | |     \___ \|  _  / | |  | | . ` |/ ___ \| . ` | |  | |  _|
| |____| |____ ____) | | \ \ | |__| | |\  /_/   \_\ |\  | |__| | |
 \_____|______|_____/|_|  \_\ \____/|_| \_/_/     \_\_| \_\____/|_|
```

Lightweight recon toolkit for HTB / TryHackMe / authorized testing.

Single-file, zero heavy dependencies, works on any modern Python.

## Screenshot

```
 ____  _____ _____     _____ ____  
|  _ \|  __ \_   _|   |_   _|  _ \ 
| |_) | |  | || |       | | | |_) |
|  _ <| |  | || |       | | |  _ < 
| |_) | |__| || |_      | | | |_) |
|____/|_____/_____|    |_| |____/ 

 v0.1 — lightweight recon toolkit

 [14:22:03] [*] Brute-forcing subdomains for: example.com
 [14:22:03] [*] Wordlist: /usr/share/seclists/...
 [14:22:05] [+] www.example.com -> 93.184.216.34
 [14:22:05] [+] mail.example.com -> 93.184.216.34
 [14:22:06] [+] Done. 2 subdomains found.
```

## Modules

```bash
rswiss subdomain   --domain example.com [--wordlist path] [--output subs.txt]
rswiss nmap        --file nmap-output.txt
rswiss headers     --target 10.10.10.10 [--https]
rswiss fingerprint --target 10.10.10.10 [--https]
rswiss portscan    --target 10.10.10.10
```

### subdomain
Brute-forces subdomains using a wordlist. Defaults to seclists top-5000.

### nmap
Parses nmap output and lists only open ports + services.

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
