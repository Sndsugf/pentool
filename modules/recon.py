#!/usr/bin/env python3
import argparse
import ipaddress
import json
import socket
import sqlite3
from typing import Any

from modules.reconnaissance.dns_lookup import ns_lookup
from modules.reconnaissance.get_ip import get_ip_info
from modules.reconnaissance.ip_lookup import ip_lookup
from modules.reconnaissance.os_fingerprint import os_fingerprint_lookup
from modules.reconnaissance.subdomain_lookup import subdomain_lookup
from modules.reconnaissance.whois_lookup import whois_lookup


def init_db(db_path: str = "pentool.db") -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # cursor.execute("PRAGMA foreign_keys = ON")
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS recon (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            domain TEXT,
            ip TEXT,
            country TEXT,
            city TEXT,
            isp TEXT,
            source TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
        )
        '''
    )
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS subdomain_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            root_domain TEXT,
            subdomain TEXT,
            ip TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
        )
        '''
    )
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS os_fingerprint_results (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            domain TEXT,
            ip TEXT,
            os_name TEXT,
            accuracy TEXT,
            line TEXT,
            osclass_json TEXT,
            source TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
        )
        '''
    )
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_recon_scan_id
        ON recon(scan_id)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_subdomain_scan_id
        ON subdomain_results(scan_id)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_os_fingerprint_scan_id
        ON os_fingerprint_results(scan_id)
    ''')
    # cursor.execute(
    #     '''
    #     CREATE UNIQUE INDEX IF NOT EXISTS idx_subdomain_results_root_subdomain
    #     ON subdomain_results (root_domain, subdomain)
    #     '''
    # )
    conn.commit()
    return conn


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_target_ip(target: str) -> str | None:
    if _is_ip(target):
        return target

    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def run_dns(target: str) -> dict[str, Any]:
    if _is_ip(target):
        try:
            host, aliases, addresses = socket.gethostbyaddr(target)
            return {"target": target, "hostname": host, "aliases": aliases, "addresses": addresses}
        except (socket.herror, socket.gaierror) as exc:
            return {"target": target, "error": str(exc)}

    answers = ns_lookup(target)
    return {"target": target, "records": answers or []}


def run_whois(target: str) -> dict[str, Any]:
    if _is_ip(target):
        return {
            "target": target,
            "note": "WHOIS domain lookup skipped because target is an IP address",
        }

    result = whois_lookup(target)
    if isinstance(result, dict):
        return result
    return dict(result)


def run_geoip(target: str) -> dict[str, Any] | None:
    if _is_ip(target):
        ip_data = ip_lookup(target)
        if not ip_data:
            return None
        return {
            "domain": None,
            "ip": ip_data.get("IP"),
            "country": ip_data.get("Country"),
            "city": ip_data.get("City"),
            "isp": ip_data.get("Organization"),
            "source": "ipinfo",
        }

    return get_ip_info(target, verbose=False)


def run_banner_grab(target: str, port: int = 80, timeout: float = 3.0) -> dict[str, Any]:
    target_ip = _resolve_target_ip(target)
    if not target_ip:
        return {"target": target, "port": port, "error": "Unable to resolve target IP"}

    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            # A small HTTP probe works for web services while staying harmless on non-HTTP ports.
            sock.sendall(f"HEAD / HTTP/1.0\\r\\nHost: {target}\\r\\n\\r\\n".encode())
            raw = sock.recv(1024)
            text = raw.decode("utf-8", errors="replace").strip()
            first_line = text.splitlines()[0] if text else ""
            return {
                "target": target,
                "ip": target_ip,
                "port": port,
                "banner": first_line,
                "raw": text,
            }
    except OSError as exc:
        return {"target": target, "ip": target_ip, "port": port, "error": str(exc)}


def run_os_fingerprint(target: str) -> dict[str, Any]:
    return os_fingerprint_lookup(target)


def run_subdomains(target: str) -> list[dict[str, Any]]:
    if _is_ip(target):
        return []
    return subdomain_lookup(target) or []


def save_recon_result(conn: sqlite3.Connection, info: dict[str, Any] | None,
                      scan_id: int | None = None):
    if not info:
        return

    cursor = conn.cursor()
    cursor.execute(
        '''
        INSERT INTO recon (scan_id, domain, ip, country, city, isp, source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            scan_id,
            info.get("domain"),
            info.get("ip"),
            info.get("country"),
            info.get("city"),
            info.get("isp"),
            info.get("source"),
        ),
    )


def save_dns_results(conn: sqlite3.Connection, target: str, dns_data: dict[str, Any],
                     scan_id: int | None = None):
    records = dns_data.get("records")
    if isinstance(records, list):
        for value in records:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO recon (scan_id, domain, ip, country, city, isp, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (scan_id, target, value, None, None, None, "dnslookup"),
            )


def save_subdomain_results(conn: sqlite3.Connection, root_domain: str,
                           results: list[dict[str, Any]],
                           scan_id: int | None = None):
    if not results:
        return

    cursor = conn.cursor()
    seen = set()
    for item in results:
        subdomain = item.get("subdomain")
        if not subdomain:
            continue

        dedupe_key = (root_domain, subdomain)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        cursor.execute(
            '''
            INSERT OR IGNORE INTO subdomain_results (scan_id, root_domain, subdomain, ip)
            VALUES (?, ?, ?, ?)
            ''',
            (scan_id, root_domain, subdomain, item.get("ip")),
        )


def save_os_fingerprint_results(conn: sqlite3.Connection, target: str,
                                data: dict[str, Any],
                                scan_id: int | None = None):
    if not data:
        return

    target_domain = None if _is_ip(target) else target
    target_ip = data.get("ip")
    source = data.get("source", "nmap_os_fingerprint")
    matches = data.get("os_matches", [])

    if not matches:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO os_fingerprint_results (scan_id, domain, ip, os_name, accuracy, line, osclass_json, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (scan_id, target_domain, target_ip, None, None, None, None, source),
        )
        return

    cursor = conn.cursor()
    for match in matches:
        cursor.execute(
            '''
            INSERT INTO os_fingerprint_results (scan_id, domain, ip, os_name, accuracy, line, osclass_json, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                scan_id,
                target_domain,
                target_ip,
                match.get("name"),
                match.get("accuracy"),
                match.get("line"),
                json.dumps(match.get("osclass", [])),
                source,
            ),
        )


def save_to_db(target: str, results: dict[str, Any], db_path: str = "pentool.db",
               scan_id: int | None = None):
    conn = init_db(db_path)
    try:
        dns_data = results.get("DNS")
        if isinstance(dns_data, dict):
            save_dns_results(conn, target, dns_data, scan_id=scan_id)

        geo_data = results.get("GeoIP")
        if isinstance(geo_data, dict):
            save_recon_result(conn, geo_data, scan_id=scan_id)

        sub_data = results.get("Subdomains")
        if isinstance(sub_data, list):
            save_subdomain_results(conn, target, sub_data, scan_id=scan_id)

        os_data = results.get("OS Finger")
        if isinstance(os_data, dict):
            save_os_fingerprint_results(conn, target, os_data, scan_id=scan_id)

        conn.commit()
    finally:
        conn.close()


def run_recon(
    target: str,
    dns: bool = False,
    whois: bool = False,
    geo: bool = False,
    banner: bool = False,
    os_fingerprint: bool = False,
    subdomains: bool = False,
    run_all: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    tasks = {
        "DNS": (dns or run_all, run_dns),
        "WHOIS": (whois or run_all, run_whois),
        "GeoIP": (geo or run_all, run_geoip),
        "Banner": (banner or run_all, run_banner_grab),
        "OS Finger": (os_fingerprint or run_all, run_os_fingerprint),
        "Subdomains": (subdomains or run_all, run_subdomains),
    }

    if not any(flag for flag, _ in tasks.values()):
        raise ValueError("No reconnaissance step selected")

    results: dict[str, Any] = {}
    for name, (enabled, func) in tasks.items():
        if not enabled:
            continue
        if verbose:
            print(f"[+] Running {name}")
        results[name] = func(target)
    return results


def main():
    parser = argparse.ArgumentParser(description="Reconnaissance Tool")
    parser.add_argument("--target", "-t", required=True, help="Target IP or domain")
    parser.add_argument("--dns", action="store_true", help="Run DNS lookup")
    parser.add_argument("--whois", action="store_true", help="Run WHOIS lookup")
    parser.add_argument("--geo", action="store_true", help="Run GeoIP lookup")
    parser.add_argument("--banner", action="store_true", help="Run banner grabbing")
    parser.add_argument("--os", dest="os_fingerprint", action="store_true", help="Run passive OS fingerprint")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--all", dest="run_all", action="store_true", help="Run all recon steps")
    parser.add_argument("--save", dest="save", action="store_true", default=True, help="Save results to DB")
    parser.add_argument("--no-save", dest="save", action="store_false", help="Do not save results")
    parser.add_argument("--scan-id", type=int, default=None,
                        help="Optional scan ID to link reconnaissance rows")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed progress")
    parser.add_argument("--db-path", default="pentool.db", help="SQLite database path")
    args = parser.parse_args()

    results = run_recon(
        target=args.target,
        dns=args.dns,
        whois=args.whois,
        geo=args.geo,
        banner=args.banner,
        os_fingerprint=args.os_fingerprint,
        subdomains=args.subdomains,
        run_all=args.run_all,
        verbose=args.verbose,
    )

    for key, value in results.items():
        print(f"\n{key}:\n{value}")

    if args.save:
        save_to_db(args.target, results, db_path=args.db_path, scan_id=args.scan_id)
        print("\n[+] Results saved to database")


if __name__ == "__main__":
    main()
