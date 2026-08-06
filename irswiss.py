#!/usr/bin/env python3
"""
irswiss (Irene swiss)
Lightweight recon toolkit for HTB / TryHackMe / authorized testing.
Single-file, zero heavy deps.
"""

import argparse
import os
import re
import sys
import socket
import ssl
from datetime import datetime

# ---------------------------------------------------------------------------
# Colors + logo
# ---------------------------------------------------------------------------

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GRAY = "\033[90m"

DOMAIN_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')

LOGO = rf""" {GREEN} ____  _   _  ____  _____ 
{BLUE}|  _ \| \ | |/ __ \|  ___|
{MAGENTA}| |_) |  \| | |  | | |_   
{CYAN}|  _ <| . ` | |  | |  _|  
{YELLOW}| |_) | |\  | |__| | |    
{RED}|____/|_| \_\____/|_| {RESET}"""

def logo():
    print(LOGO)
    print(f"  {GRAY}Irene Swiss — lightweight recon toolkit{RESET}\n")

def ts():
    return datetime.now().strftime("%H:%M:%S")

def color(color_code, msg):
    return f"{color_code}{msg}{RESET}"

def info(msg):
    print(f" {GRAY}[{ts()}]{RESET} {BLUE}[*]{RESET} {msg}")

def ok(msg):
    print(f" {GRAY}[{ts()}]{RESET} {GREEN}[+]{RESET} {msg}")

def warn(msg):
    print(f" {GRAY}[{ts()}]{RESET} {YELLOW}[!]{RESET} {msg}")

def fail(msg):
    print(f" {GRAY}[{ts()}]{RESET} {RED}[-]{RESET} {msg}", file=sys.stderr)

def make_ctx(verify=True):
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

# ---------------------------------------------------------------------------
# Module 1: Subdomain brute-force
# ---------------------------------------------------------------------------

def module_subdomain(args):
    domain = args.domain.replace("https://", "").replace("http://", "").split("/")[0]
    if not DOMAIN_RE.match(domain):
        fail(f"Invalid domain format: {domain}")
        sys.exit(1)
    wordlist = args.wordlist or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

    if not os.path.exists(wordlist):
        fail(f"Wordlist not found: {wordlist}")
        sys.exit(1)

    info(f"Brute-forcing subdomains for: {color(CYAN, domain)}")
    info(f"Wordlist: {color(GRAY, wordlist)}")

    found = []
    with open(wordlist) as f:
        subs = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    total = len(subs)
    for i, sub in enumerate(subs):
        if i % 200 == 0:
            info(f"Progress: {color(WHITE, str(i))}/{total}")
        host = f"{sub}.{domain}"
        ip = resolve(host)
        if ip:
            found.append((host, ip))
            ok(f"{color(GREEN, host)} -> {ip}")

    ok(f"Done. {color(WHITE, str(len(found)))} subdomains found.")
    if args.output:
        with open(args.output, "w") as f:
            for h, i in found:
                f.write(f"{h}\n")
        ok(f"Saved to {color(GRAY, args.output)}")

# ---------------------------------------------------------------------------
# Module 2: Port scan parser  (nmap -oN / greppable)
# ---------------------------------------------------------------------------

def module_parse_nmap(args):
    path = args.file
    if not os.path.exists(path):
        fail(f"File not found: {path}")
        sys.exit(1)

    info(f"Parsing: {color(GRAY, path)}")
    with open(path) as f:
        data = f.read()

    results = {}
    for line in data.splitlines():
        line = line.strip()
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0]
                state = parts[1]
                service = parts[2]
                if state == "open":
                    results.setdefault(port_proto, []).append(service)

    if not results:
        warn("No open ports found.")
        return

    ok("Open ports:")
    for pp, services in sorted(results.items()):
        print(f"  {color(CYAN, pp)}: {', '.join(services)}")

# ---------------------------------------------------------------------------
# Module 3: HTTP header grabber
# ---------------------------------------------------------------------------

def module_headers(args):
    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"
    if args.https:
        target = target.replace("http://", "https://")

    info(f"Fetching headers: {color(CYAN, target)}")
    try:
        import urllib.request
        ctx = make_ctx(args.no_verify)
        req = urllib.request.Request(target, method="HEAD")
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            headers = dict(r.headers)
            for k, v in headers.items():
                print(f"  {color(YELLOW, k)}: {v}")
            ok(f"Status: {color(WHITE, str(r.status))}")
    except urllib.error.HTTPError as e:
        ok(f"Status: {color(WHITE, str(e.code))}")
        for k, v in e.headers.items():
            print(f"  {color(YELLOW, k)}: {v}")
    except Exception as e:
        fail(str(e))

# ---------------------------------------------------------------------------
# Module 4: Tech fingerprint
# ---------------------------------------------------------------------------

def module_fingerprint(args):
    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"
    if args.https:
        target = target.replace("http://", "https://")

    info(f"Fingerprinting: {color(CYAN, target)}")
    try:
        import urllib.request
        ctx = make_ctx(args.no_verify)
        req = urllib.request.Request(target, method="GET")
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            body = r.read().decode("utf-8", errors="ignore")[:4000]
            headers = dict(r.headers)

            server = headers.get("Server", "unknown")
            ok(f"Server: {color(WHITE, server)}")

            xpb = headers.get("X-Powered-By", "")
            if xpb:
                ok(f"X-Powered-By: {color(GREEN, xpb)}")

            cookies = r.headers.get_all("Set-Cookie", [])
            if cookies:
                tech = []
                for c in cookies:
                    cl = c.lower()
                    if "phpsessid" in cl:
                        tech.append("PHP")
                    if "jsessionid" in cl:
                        tech.append("Java")
                    if "asp.net" in cl or "aspx" in cl:
                        tech.append("ASP.NET")
                    if "laravel" in cl:
                        tech.append("Laravel")
                if tech:
                    ok(f"Possible tech: {', '.join(set(tech))}")

            metas = []
            for tag in ["generator", "framework", "Powered-By"]:
                if f'name="{tag}"' in body or f"name='{tag}'" in body:
                    metas.append(tag)
            if metas:
                ok(f"Meta hints: {', '.join(metas)}")

            title_start = body.find("<title>")
            title_end = body.find("</title>")
            if title_start != -1 and title_end != -1:
                title = body[title_start + 7:title_end].strip()
                ok(f"Title: {color(WHITE, title)}")

    except urllib.error.HTTPError as e:
        ok(f"Status: {color(WHITE, str(e.code))}")
    except Exception as e:
        fail(str(e))

# ---------------------------------------------------------------------------
# Module 5: Quick port scan (top 100)
# ---------------------------------------------------------------------------

def module_portscan(args):
    target = args.target
    top_ports = [
        21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
        1723,3306,3389,5432,5900,5901,6000,8000,8080,8443,8888
    ]
    ip = resolve(target)
    if not ip:
        fail(f"Cannot resolve: {target}")
        sys.exit(1)

    ok(f"Scanning top ports on {color(CYAN, target)} ({ip})")
    open_ports = []
    for port in top_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            open_ports.append((port, service))
            ok(f"  {color(GREEN, str(port))}/tcp  {service}")
        sock.close()

    ok(f"Done. {color(WHITE, str(len(open_ports)))} open ports.")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="irswiss",
        description="irswiss — lightweight recon toolkit by Irene",
    )
    sub = parser.add_subparsers(dest="module", required=True)

    p_sub = sub.add_parser("subdomain", help="Subdomain brute-force")
    p_sub.add_argument("--domain", required=True)
    p_sub.add_argument("--wordlist", default=None)
    p_sub.add_argument("--output", default=None)

    p_nmap = sub.add_parser("nmap", help="Parse nmap output for open ports")
    p_nmap.add_argument("--file", required=True)

    p_hdr = sub.add_parser("headers", help="Grab HTTP response headers")
    p_hdr.add_argument("--target", required=True)
    p_hdr.add_argument("--https", action="store_true")
    p_hdr.add_argument("--no-verify", action="store_true", help="Disable TLS verification")

    p_fp = sub.add_parser("fingerprint", help="Lightweight tech fingerprint")
    p_fp.add_argument("--target", required=True)
    p_fp.add_argument("--https", action="store_true")
    p_fp.add_argument("--no-verify", action="store_true", help="Disable TLS verification")

    p_ps = sub.add_parser("portscan", help="Quick top-100 port scan")
    p_ps.add_argument("--target", required=True)

    args = parser.parse_args()
    logo()
    mods = {
        "subdomain": module_subdomain,
        "nmap": module_parse_nmap,
        "headers": module_headers,
        "fingerprint": module_fingerprint,
        "portscan": module_portscan,
    }
    mods[args.module](args)

if __name__ == "__main__":
    main()
