#!/usr/bin/env python3
"""
irswiss (Irene swiss)
Lightweight recon toolkit for HTB / TryHackMe / authorized testing.
Single-file, zero heavy deps.
"""

import argparse
import json
import os
import random
import re
import sys
import socket
import ssl
import time
import concurrent.futures
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
]

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
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

def random_ua():
    return random.choice(USER_AGENTS)

def build_request(target, method="GET"):
    if not target.startswith("http"):
        target = f"http://{target}"
    req = Request(target, method=method)
    req.add_header("User-Agent", random_ua())
    req.add_header("Accept", "*/*")
    return req

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

    with open(wordlist) as f:
        subs = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    total = len(subs)
    found = []
    lock = __import__("threading").Lock()

    def check(sub):
        host = f"{sub}.{domain}"
        ip = resolve(host)
        if ip:
            with lock:
                found.append((host, ip))
            return (host, ip)
        return None

    workers = args.workers if args.workers > 0 else min(32, os.cpu_count() * 4 or 8)
    info(f"Workers: {workers}")
    if args.delay > 0:
        info(f"Delay: {args.delay}s between batches")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check, sub): sub for sub in subs}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if args.delay > 0 and done % 200 == 0:
                time.sleep(args.delay)
            if args.json:
                continue
            if done % 500 == 0 or done == total:
                info(f"Progress: {color(WHITE, str(done))}/{total}")

    results = sorted(found)
    for h, i in results:
        if not args.json:
            ok(f"{color(GREEN, h)} -> {i}")

    if not args.json:
        ok(f"Done. {color(WHITE, str(len(results)))} subdomains found.")
    else:
        payload = {"domain": domain, "count": len(results), "subdomains": [{"host": h, "ip": i} for h, i in results]}
        out = args.output or f"{domain}_subdomains.json"
        with open(out, "w") as f:
            json.dump(payload, f, indent=2)
        ok(f"JSON saved to {color(GRAY, out)}")

    if args.output and not args.json:
        with open(args.output, "w") as f:
            for h, i in results:
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

    if args.json:
        payload = []
        for pp, services in sorted(results.items()):
            payload.append({"port": pp, "services": services})
        out = args.output or "nmap_parsed.json"
        with open(out, "w") as f:
            json.dump(payload, f, indent=2)
        ok(f"JSON saved to {color(GRAY, out)}")
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
        req = build_request(target, method="HEAD")
        ctx = make_ctx(verify=not args.no_verify)
        with urlopen(req, timeout=args.timeout, context=ctx) as r:
            headers = dict(r.headers)
            if args.json:
                payload = {"status": r.status, "headers": headers}
                out = args.output or "headers.json"
                with open(out, "w") as f:
                    json.dump(payload, f, indent=2)
                ok(f"JSON saved to {color(GRAY, out)}")
                return
            for k, v in headers.items():
                print(f"  {color(YELLOW, k)}: {v}")
            ok(f"Status: {color(WHITE, str(r.status))}")
    except HTTPError as e:
        headers = dict(e.headers) if e.headers else {}
        if args.json:
            payload = {"status": e.code, "headers": headers}
            out = args.output or "headers.json"
            with open(out, "w") as f:
                json.dump(payload, f, indent=2)
            ok(f"JSON saved to {color(GRAY, out)}")
            return
        ok(f"Status: {color(WHITE, str(e.code))}")
        for k, v in headers.items():
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
        req = build_request(target)
        ctx = make_ctx(verify=not args.no_verify)
        with urlopen(req, timeout=args.timeout, context=ctx) as r:
            body = r.read().decode("utf-8", errors="ignore")[:4000]
            headers = dict(r.headers)

            server = headers.get("Server", "unknown")
            xpb = headers.get("X-Powered-By", "")
            cookies = r.headers.get_all("Set-Cookie", []) or []
            metas = []
            for tag in ["generator", "framework", "Powered-By"]:
                if f'name="{tag}"' in body or f"name='{tag}'" in body:
                    metas.append(tag)
            title_start = body.find("<title>")
            title_end = body.find("</title>")
            title = ""
            if title_start != -1 and title_end != -1:
                title = body[title_start + 7:title_end].strip()

            payload = {
                "server": server,
                "x_powered_by": xpb,
                "tech": [],
                "meta": metas,
                "title": title,
            }
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
                payload["tech"] = list(set(tech))

            if args.json:
                out = args.output or "fingerprint.json"
                with open(out, "w") as f:
                    json.dump(payload, f, indent=2)
                ok(f"JSON saved to {color(GRAY, out)}")
                return

            ok(f"Server: {color(WHITE, server)}")
            if xpb:
                ok(f"X-Powered-By: {color(GREEN, xpb)}")
            if payload["tech"]:
                ok(f"Possible tech: {', '.join(payload['tech'])}")
            if metas:
                ok(f"Meta hints: {', '.join(metas)}")
            if title:
                ok(f"Title: {color(WHITE, title)}")

    except HTTPError as e:
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
    lock = __import__("threading").Lock()

    def scan(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return port, service
        return None

    workers = args.workers if args.workers > 0 else min(64, os.cpu_count() * 8 or 16)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan, p) for p in top_ports]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                port, service = res
                with lock:
                    open_ports.append((port, service))
                if not args.json:
                    ok(f"  {color(GREEN, str(port))}/tcp  {service}")

    results = sorted(open_ports)
    if args.json:
        payload = {"target": target, "ip": ip, "open_ports": [{"port": p, "service": s} for p, s in results]}
        out = args.output or "portscan.json"
        with open(out, "w") as f:
            json.dump(payload, f, indent=2)
        ok(f"JSON saved to {color(GRAY, out)}")
    else:
        ok(f"Done. {color(WHITE, str(len(results)))} open ports.")

# ---------------------------------------------------------------------------
# Module 6: DNS lookup
# ---------------------------------------------------------------------------

def module_dns(args):
    target = args.target.replace("https://", "").replace("http://", "").split("/")[0]
    if not DOMAIN_RE.match(target):
        fail(f"Invalid domain format: {target}")
        sys.exit(1)

    info(f"Looking up: {color(CYAN, target)}")
    try:
        ip = resolve(target)
        if ip:
            ok(f"A: {color(GREEN, ip)}")
        else:
            warn("No A record found")

        try:
            info_data = socket.getaddrinfo(target, None)
            for item in info_data:
                fam = item[0]
                addr = item[4][0]
                if fam == socket.AF_INET6:
                    ok(f"AAAA: {color(GREEN, addr)}")
        except socket.gaierror:
            pass

        if args.txt and os.popen("which dig").read().strip():
            try:
                txt_out = os.popen(f"dig +short TXT {target} 2>/dev/null").read().strip()
                if txt_out:
                    ok(f"TXT: {color(GREEN, txt_out)}")
            except Exception:
                pass

    except Exception as e:
        fail(str(e))

# ---------------------------------------------------------------------------
# Module 7: TLS/cert info
# ---------------------------------------------------------------------------

def module_tls(args):
    target = args.target.replace("https://", "").replace("http://", "").split("/")[0]
    hostname = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 443

    info(f"Checking TLS: {color(CYAN, hostname)}:{port}")
    ctx = make_ctx(verify=not args.no_verify)
    try:
        with socket.create_connection((hostname, port), timeout=args.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                if args.json:
                    payload = {
                        "host": hostname,
                        "port": port,
                        "version": version,
                        "cipher": cipher,
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": not_before,
                        "not_after": not_after,
                        "serial": cert.get("serialNumber", ""),
                    }
                    out = args.output or "tls.json"
                    with open(out, "w") as f:
                        json.dump(payload, f, indent=2)
                    ok(f"JSON saved to {color(GRAY, out)}")
                    return

                ok(f"Protocol: {color(WHITE, version)}")
                ok(f"Cipher: {color(GREEN, cipher[0])} {cipher[1]}")
                ok(f"Subject CN: {color(WHITE, subject.get('commonName', 'N/A'))}")
                ok(f"Issuer CN: {color(WHITE, issuer.get('commonName', 'N/A'))}")
                ok(f"Valid: {color(YELLOW, not_before)} -> {color(YELLOW, not_after)}")
    except Exception as e:
        fail(str(e))

# ---------------------------------------------------------------------------
# Module 8: Banner grabber
# ---------------------------------------------------------------------------

def module_banner(args):
    target = args.target
    if not target.startswith("http"):
        target = f"{target}"

    proto = "https" if args.https else "tcp"
    info(f"Grabbing banner: {color(CYAN, target)} ({proto})")

    if proto == "https":
        hostname = target.replace("https://", "").split("/")[0]
        port = int(hostname.split(":")[1]) if ":" in hostname else 443
        try:
            req = build_request(f"https://{hostname}:{port}/", method="GET")
            ctx = make_ctx(verify=not args.no_verify)
            with urlopen(req, timeout=args.timeout, context=ctx) as r:
                if args.json:
                    payload = {"status": r.status, "headers": dict(r.headers)}
                    out = args.output or "banner.json"
                    with open(out, "w") as f:
                        json.dump(payload, f, indent=2)
                    ok(f"JSON saved to {color(GRAY, out)}")
                else:
                    banner = "\n".join([f"{k}: {v}" for k, v in list(r.headers.items())[:15]])
                    print(f"\n{color(GREEN, banner)}\n")
                    ok(f"Status: {color(WHITE, str(r.status))}")
        except Exception as e:
            fail(str(e))
        return

    if ":" in target:
        host, port = target.split(":")
        port = int(port)
    else:
        host = target
        port = 80

    try:
        with socket.create_connection((host, port), timeout=args.timeout) as sock:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(4096).decode("utf-8", errors="ignore")
            if args.json:
                payload = {"host": host, "port": port, "banner": data}
                out = args.output or "banner.json"
                with open(out, "w") as f:
                    json.dump(payload, f, indent=2)
                ok(f"JSON saved to {color(GRAY, out)}")
            else:
                print(f"\n{color(GREEN, data.strip())}\n")
                ok("Banner received")
    except Exception as e:
        fail(str(e))

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="irswiss",
        description="irswiss — lightweight recon toolkit by 6mins",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout (default: 10)")
    parser.add_argument("--workers", type=int, default=0, help="Concurrent workers (0 = auto)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between batches in seconds")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode, JSON only")
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

    p_dns = sub.add_parser("dns", help="DNS lookup + basic records")
    p_dns.add_argument("--target", required=True)
    p_dns.add_argument("--txt", action="store_true", help="Attempt TXT lookup via dig")

    p_tls = sub.add_parser("tls", help="TLS/certificate info")
    p_tls.add_argument("--target", required=True)

    p_banner = sub.add_parser("banner", help="Grab service banner (HTTP/TCP)")
    p_banner.add_argument("--target", required=True)
    p_banner.add_argument("--https", action="store_true")
    p_banner.add_argument("--no-verify", action="store_true", help="Disable TLS verification")

    args = parser.parse_args()
    if args.quiet:
        args.json = True

    if not args.quiet:
        logo()

    mods = {
        "subdomain": module_subdomain,
        "nmap": module_parse_nmap,
        "headers": module_headers,
        "fingerprint": module_fingerprint,
        "portscan": module_portscan,
        "dns": module_dns,
        "tls": module_tls,
        "banner": module_banner,
    }
    mods[args.module](args)

if __name__ == "__main__":
    main()
