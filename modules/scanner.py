#!/usr/bin/env python3

import nmap
import json
import csv
import sys
import argparse
import subprocess
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
import ipaddress

# Gestionnaire de base de donnees
class Database:
    def __init__(self, db_path: str = "pentool.db"):
        self.db_path = db_path
        self.conn = None
        self._init_db()

    def _init_db(self):
        """Cree les tables scans et ports si elles n'existent pas.
           La table payloads est supposee exister deja."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            cursor = self.conn.cursor()
            # Table des scans
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    target_ip TEXT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    duration REAL,
                    status TEXT DEFAULT 'running',
                    total_ports_scanned INTEGER DEFAULT 0,
                    open_ports_count INTEGER DEFAULT 0
                )
            """)
            # Table des ports 
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port_number INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    state TEXT DEFAULT 'open',
                    service_name TEXT,
                    service_version TEXT,
                    banner TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)
            self.conn.commit()
        except Exception as e:
            print(f"[!] Erreur base de donnees: {e}")
            self.conn = None

    def create_scan(self, target: str, target_ip: str = None) -> int:
        if not self.conn:
            return -1
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO scans (target, target_ip, status, start_time)
            VALUES (?, ?, ?, ?)
        """, (target, target_ip, 'running', datetime.now().isoformat()))
        self.conn.commit()
        return cursor.lastrowid

    def update_scan(self, scan_id: int, end_time: str, duration: float,
                    total_ports: int, open_ports: int, status: str = 'completed'):
        if not self.conn or scan_id == -1:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE scans
            SET end_time = ?, duration = ?, status = ?,
                total_ports_scanned = ?, open_ports_count = ?
            WHERE id = ?
        """, (end_time, duration, status, total_ports, open_ports, scan_id))
        self.conn.commit()

    def save_port(self, scan_id: int, port_data: Dict):
        if not self.conn or scan_id == -1:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO ports
            (scan_id, port_number, protocol, state, service_name, service_version, banner)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            port_data.get('port'),
            port_data.get('protocol', 'tcp'),
            port_data.get('state', 'open'),
            port_data.get('service'),
            port_data.get('version'),
            port_data.get('banner')
        ))
        self.conn.commit()

    def get_payloads_for_scan(self, scan_id: int) -> List[Dict]:
        """Retourne les payloads correspondant aux ports ouverts du scan"""
        if not self.conn:
            return []
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT DISTINCT
                p.port_number,
                p.service_name,
                pl.name AS payload_name,
                pl.payload,
                pl.method
            FROM ports p
            JOIN payloads pl ON pl.port = p.port_number
            WHERE p.scan_id = ? AND p.state = 'open'
        """, (scan_id,))
        rows = cursor.fetchall()
        return [{
            'port': row[0],
            'service': row[1],
            'payload_name': row[2],
            'payload': row[3],
            'method': row[4]
        } for row in rows]

    def close(self):
        if self.conn:
            self.conn.close()

# Scanner de ports (avec insertion et liaison payloads)
class PortScanner:
    def __init__(self, target: str, verbose: bool = False, db: Database = None, no_db: bool = False):
        self.target = target
        self.verbose = verbose
        self.nm = nmap.PortScanner()
        self.db = db if (db and not no_db) else None
        self.scan_id = -1
        self.target_ip = None
        self.scan_results = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'scan_duration': 0,
            'hosts': {},
            'summary': {
                'total_hosts': 0,
                'up_hosts': 0,
                'total_open_ports': 0,
                'services_found': []
            }
        }

    def _log(self, message: str, level: str = "INFO"):
        if self.verbose:
            prefix = {"INFO":"[*]","SUCCESS":"[+]","WARNING":"[!]","ERROR":"[-]"}.get(level,"[*]")
            print(f"{prefix} {message}")

    def _resolve_target(self) -> str:
        try:
            import socket
            ip = socket.gethostbyname(self.target)
            self.target_ip = ip
            self._log(f"Resolu: {self.target} -> {ip}", "SUCCESS")
            return ip
        except:
            self._log(f"Impossible de resoudre {self.target}", "ERROR")
            return None

    def is_host_alive(self) -> bool:
        try:
            result = subprocess.run(['ping','-c','1','-W','1', self.target],
                                    capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False

    def scan_ports(self, ports: str = "1-1000", arguments: str = "-sV --version-light -T4", udp: bool = False) -> List[Dict]:
        ip = self._resolve_target()
        if not ip:
            return []

        if self.db:
            self.scan_id = self.db.create_scan(self.target, ip)
            self._log(f"Scan ID: {self.scan_id}")

        self._log(f"Demarrage du scan sur {self.target} ({ip})")
        self._log(f"Ports: {ports}")
        if udp:
            self._log("Scan UDP active")

        start_time = datetime.now()
        try:
            self.nm.scan(ip, ports, arguments)
            if udp:
                self.nm.scan(ip, ports, arguments + " -sU")
        except Exception as e:
            self._log(f"Erreur Nmap: {e}", "ERROR")
            if self.db and self.scan_id != -1:
                self.db.update_scan(self.scan_id, datetime.now().isoformat(), 0, 0, 0, 'failed')
            return []

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.scan_results['scan_duration'] = duration

        open_ports = []
        total_ports_scanned = self._count_ports(ports)

        for host in self.nm.all_hosts():
            host_info = {
                'host': host,
                'status': self.nm[host].state(),
                'ports': [],
                'os_guess': None,
                'hostname': None
            }
            if 'hostname' in self.nm[host] and self.nm[host]['hostname']:
                host_info['hostname'] = self.nm[host]['hostname'][0].get('name','')
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                host_info['os_guess'] = self.nm[host]['osmatch'][0].get('name','')

            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto]:
                    info = self.nm[host][proto][port]
                    if info['state'] == 'open':
                        service = info.get('name','unknown')
                        version = info.get('version','')
                        product = info.get('product','')
                        extrainfo = info.get('extrainfo','')
                        banner_parts = [p for p in [product, version, extrainfo] if p]
                        banner = ' '.join(banner_parts) if banner_parts else None

                        port_data = {
                            'port': int(port),
                            'protocol': proto,
                            'state': 'open',
                            'service': service,
                            'version': version or None,
                            'banner': banner
                        }
                        host_info['ports'].append(port_data)
                        open_ports.append({'host': host, **port_data})

                        if self.db and self.scan_id != -1:
                            self.db.save_port(self.scan_id, port_data)

                        self._log(f"Port {port}/{proto}: {service} {version}", "SUCCESS")

            self.scan_results['hosts'][host] = host_info

        self._update_summary()
        open_count = len(open_ports)
        if self.db and self.scan_id != -1:
            self.db.update_scan(self.scan_id, end_time.isoformat(), duration,
                                total_ports_scanned, open_count, 'completed')

        # --- Liaison avec la table payloads ---
        if self.db and self.scan_id != -1:
            payloads = self.db.get_payloads_for_scan(self.scan_id)
            if payloads:
                print("\n[!] Payloads disponibles pour les ports ouverts de ce scan :")
                for pl in payloads:
                    print(f"    Port {pl['port']} ({pl['service']}) -> {pl['payload_name']} ({pl['method']})")
                    print(f"        Payload: {pl['payload']}")
            else:
                print("\n[-] Aucun payload trouve pour les ports ouverts (verifiez la table payloads).")

        return open_ports

    def _count_ports(self, ports_spec: str) -> int:
        if '-' in ports_spec:
            a,b = map(int, ports_spec.split('-'))
            return b - a + 1
        elif ',' in ports_spec:
            return len(ports_spec.split(','))
        else:
            return 1

    def fast_scan(self):
        top = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
        return self.scan_ports(ports=top, arguments="-sV --version-light -T4")

    def full_scan(self):
        return self.scan_ports(ports="1-65535", arguments="-sV -T4")

    def stealth_scan(self):
        return self.scan_ports(arguments="-sS -sV -T4")

    def aggressive_scan(self):
        return self.scan_ports(arguments="-A -T4")

    def _update_summary(self):
        total_ports = 0
        services = set()
        up = 0
        for host, data in self.scan_results['hosts'].items():
            if data['status'] == 'up':
                up += 1
                for p in data['ports']:
                    total_ports += 1
                    if p['service']:
                        services.add(p['service'])
        self.scan_results['summary']['total_hosts'] = len(self.scan_results['hosts'])
        self.scan_results['summary']['up_hosts'] = up
        self.scan_results['summary']['total_open_ports'] = total_ports
        self.scan_results['summary']['services_found'] = list(services)

    def save_json(self, output_file=None):
        if not output_file:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = self.target.replace('/','_').replace(':','_')
            output_file = f"scan_{safe}_{ts}.json"
        with open(output_file,'w') as f:
            json.dump(self.scan_results, f, indent=2)
        self._log(f"JSON sauvegarde: {output_file}", "SUCCESS")
        return output_file

    def save_csv(self, output_file=None):
        if not output_file:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = self.target.replace('/','_').replace(':','_')
            output_file = f"scan_{safe}_{ts}.csv"
        with open(output_file,'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['host','port','protocol','state','service','version','banner'])
            for host, data in self.scan_results['hosts'].items():
                for p in data['ports']:
                    writer.writerow([host, p['port'], p['protocol'], p['state'],
                                     p['service'], p['version'] or '', p['banner'] or ''])
        self._log(f"CSV sauvegarde: {output_file}", "SUCCESS")
        return output_file

    def print_summary(self):
        print("\n" + "-"*70)
        print(f"RESUME DU SCAN - {self.target}")
        print("-"*70)
        print(f"Date: {self.scan_results['scan_date']}")
        print(f"Duree: {self.scan_results['scan_duration']:.2f} secondes")
        print(f"Hotess: {self.scan_results['summary']['up_hosts']}/{self.scan_results['summary']['total_hosts']}")
        print(f"Ports ouverts: {self.scan_results['summary']['total_open_ports']}")
        if self.scan_results['summary']['services_found']:
            print(f"Services detectes: {', '.join(self.scan_results['summary']['services_found'][:10])}")
        print("\nDetails par hote:")
        print("-"*70)
        for host, data in self.scan_results['hosts'].items():
            status_icon = "UP" if data['status']=='up' else "DOWN"
            print(f"\n{status_icon} {host} [{data['status']}]")
            if data.get('hostname'):
                print(f"   Hostname: {data['hostname']}")
            if data.get('os_guess'):
                print(f"   OS: {data['os_guess']}")
            if data['ports']:
                print(f"   Ports ouverts ({len(data['ports'])}):")
                for p in data['ports']:
                    ver = f" ({p['version']})" if p['version'] else ""
                    print(f"      - {p['port']}/{p['protocol']}: {p['service']}{ver}")
            else:
                print("   Aucun port ouvert")
        print("\n" + "-"*70)

    def get_db_ready_results(self):
        out = []
        for host, data in self.scan_results['hosts'].items():
            for p in data['ports']:
                out.append({
                    'target_ip': host,
                    'target_hostname': data.get('hostname'),
                    'port': p['port'],
                    'protocol': p['protocol'],
                    'service': p['service'],
                    'version': p['version'],
                    'banner': p['banner'],
                    'os_guess': data.get('os_guess'),
                    'scan_date': self.scan_results['scan_date']
                })
        return out
# Scan reseau
def scan_network_range(network: str, ports: str = "1-1000", verbose: bool = False, db=None, no_db=False):
    all_results = []
    try:
        net = ipaddress.ip_network(network, strict=False)
        total = net.num_addresses
        print(f"[*] Scan du reseau {network} ({total} adresses)")
        for i, ip in enumerate(net.hosts()):
            ip_str = str(ip)
            print(f"[*] Scan de {ip_str} ({i+1}/{total-2})")
            scanner = PortScanner(ip_str, verbose=verbose, db=db, no_db=no_db)
            if scanner.is_host_alive():
                results = scanner.scan_ports(ports=ports)
                all_results.extend(results)
                scanner.print_summary()
            else:
                print(f"[-] {ip_str} hors ligne")
        return all_results
    except Exception as e:
        print(f"[!] Erreur scan reseau: {e}")
        return []

# CLI principale
def main():
    parser = argparse.ArgumentParser(description="Scanner de ports avec insertion SQLite et liaison payloads")
    parser.add_argument("target", help="Cible (IP, domaine, plage CIDR)")
    parser.add_argument("--fast","-f", action="store_true", help="Scan rapide top20")
    parser.add_argument("--full", action="store_true", help="Scan complet 1-65535")
    parser.add_argument("--aggressive","-A", action="store_true", help="Mode agressif")
    parser.add_argument("--stealth", action="store_true", help="Mode furtif (root)")
    parser.add_argument("--udp", action="store_true", help="Ajouter scan UDP")
    parser.add_argument("--ports","-p", default="1-1000", help="Ports a scanner")
    parser.add_argument("--output","-o", help="Fichier JSON de sortie")
    parser.add_argument("--csv", action="store_true", help="Exporter CSV")
    parser.add_argument("--quiet","-q", action="store_true", help="Moins de messages")
    parser.add_argument("--verbose","-v", action="store_true", help="Messages detailles")
    parser.add_argument("--network", action="store_true", help="Scanner reseau CIDR")
    parser.add_argument("--db", default="pentool.db", help="Fichier SQLite (defaut: pentool.db)")
    parser.add_argument("--no-db", action="store_true", help="Desactiver l'ecriture en base")
    args = parser.parse_args()

    verbose = not args.quiet or args.verbose
    db = None if args.no_db else Database(args.db)

    if args.network or '/' in args.target:
        results = scan_network_range(args.target, args.ports, verbose, db, args.no_db)
        if results:
            print(f"\n[+] Scan reseau termine. {len(results)} ports ouverts.")
        if db:
            db.close()
        return 0

    scanner = PortScanner(args.target, verbose=verbose, db=db, no_db=args.no_db)

    if args.fast:
        open_ports = scanner.fast_scan()
    elif args.full:
        open_ports = scanner.full_scan()
    elif args.aggressive:
        open_ports = scanner.aggressive_scan()
    elif args.stealth:
        open_ports = scanner.stealth_scan()
    else:
        open_ports = scanner.scan_ports(ports=args.ports, udp=args.udp)

    scanner.print_summary()
    if open_ports:
        scanner.save_json(args.output)
        if args.csv:
            scanner.save_csv()

    if verbose and open_ports:
        print("\nDonnees pretes pour insertion DB:")
        print("-"*50)
        db_data = scanner.get_db_ready_results()
        print(json.dumps(db_data, indent=2)[:1000] + "...")

    if db:
        db.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())