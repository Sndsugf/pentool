#!/usr/bin/env python3
"""
Usage autonome :
  python cve.py --scan-id 3
  python cve.py --scan-id 3 --verbose
  python cve.py --list-scans
  python cve.py --scan-id 3 --force --export results.json

"""

import sqlite3
import requests
import time
import re
import sys
import json
import argparse
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Chargement de la configuration (.env)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

NVD_API_KEY  = os.getenv("NVD_API_KEY", "")
DB_PATH      = os.getenv("DB_PATH", "pentool.db")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Délai entre requêtes NVD
# Sans clé API : 5 req/30s  → 6.5s de délai
# Avec clé API : 50 req/30s → 0.7s de délai
REQUEST_DELAY    = 0.7 if NVD_API_KEY else 6.5
CVSS_MIN_SCORE   = 0.0   # 0.0 = enregistrer toutes les CVEs
MAX_CVE_PER_PORT = 10    # Nombre max de CVEs à stocker par port


# Gestion de la base de données SQLite

class CveDatabase:
    """
    Gère les interactions SQLite pour cve.py.
    Lit depuis  : scans, ports, payloads, cves
    Écrit dans  : port_cve (créée ici si absente)
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_table()

    def _connect(self):
        """Ouvre la connexion SQLite. Lève une erreur si le fichier est absent."""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(
                f"[!] Base de données introuvable : {self.db_path}\n"
                f"    Lancez d'abord scanner.py pour créer la base."
            )
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # accès par nom de colonne

    def _create_table(self):
        """Crée la table port_cve si elle n'existe pas encore."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS port_cve (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id        INTEGER NOT NULL,
                scan_id        INTEGER NOT NULL,
                cve_id         TEXT    NOT NULL,
                cvss_score     REAL    DEFAULT 0.0,
                cvss_version   TEXT,
                severity       TEXT,
                description    TEXT,
                published_date TEXT,
                last_modified  TEXT,
                exploit_available INTEGER DEFAULT 0,  -- 0 = non, 1 = oui
                exploit_source    TEXT,               -- 'local_db'
                exploit_name      TEXT,               -- nom du payload local
                exploit_payload   TEXT,               -- contenu du payload
                exploit_method    TEXT,               -- méthode (http_get, tcp_raw…)
                created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                UNIQUE(port_id, cve_id)               -- pas de doublon
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_port_cve_scan
            ON port_cve(scan_id)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_port_cve_score
            ON port_cve(cvss_score DESC)
        """)
        self.conn.commit()

    # ---- Lecture ----

    def get_scan_ids(self) -> List[Dict]:
        """Liste tous les scans disponibles en base."""
        cursor = self.conn.execute("""
            SELECT id, target, target_ip, start_time, status, open_ports_count
            FROM scans
            ORDER BY id DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

    def get_ports_for_scan(self, scan_id: int) -> List[Dict]:
        """
        Retourne tous les ports ouverts d'un scan.
        C'est l'entrée principale de cve.py.
        """
        cursor = self.conn.execute("""
            SELECT id, port_number, protocol, service_name, service_version, banner
            FROM ports
            WHERE scan_id = ? AND state = 'open'
            ORDER BY port_number
        """, (scan_id,))
        return [dict(row) for row in cursor.fetchall()]

    def cve_already_scanned(self, port_id: int) -> bool:
        """Vérifie si ce port a déjà été analysé (anti-doublon)."""
        cursor = self.conn.execute(
            "SELECT COUNT(*) FROM port_cve WHERE port_id = ?", (port_id,)
        )
        return cursor.fetchone()[0] > 0

    def get_local_exploit(self, cve_id: str) -> Optional[Dict]:
        """
        Cherche dans la table `payloads` si un exploit local existe
        pour ce CVE. Retourne le premier payload trouvé ou None.
        
        C'est ici qu'on remplace ExploitChecker : pas de requête HTTP,
        juste une jointure SQL sur notre base locale (seed.sql).
        """
        cursor = self.conn.execute("""
            SELECT p.name, p.payload, p.method, p.port, p.service
            FROM payloads p
            WHERE p.cve_id = ?
            LIMIT 1
        """, (cve_id,))
        row = cursor.fetchone()
        if row:
            return {
                "exploit_available": True,
                "exploit_source":    "local_db",
                "exploit_name":      row["name"],
                "exploit_payload":   row["payload"],
                "exploit_method":    row["method"],
            }
        return {
            "exploit_available": False,
            "exploit_source":    None,
            "exploit_name":      None,
            "exploit_payload":   None,
            "exploit_method":    None,
        }

    def get_all_local_exploits(self, cve_id: str) -> List[Dict]:
        """
        Retourne TOUS les payloads locaux pour un CVE donné.
        Utile pour affichage verbose.
        """
        cursor = self.conn.execute("""
            SELECT name, payload, method, port, service
            FROM payloads
            WHERE cve_id = ?
        """, (cve_id,))
        return [dict(row) for row in cursor.fetchall()]

    # ---- Écriture ----

    def save_cve(self, port_id: int, scan_id: int, cve: Dict) -> bool:
        """
        Insère une CVE dans port_cve avec les infos d'exploit local.
        Retourne True si insertion réussie, False si doublon ou erreur.
        """
        try:
            self.conn.execute("""
                INSERT OR IGNORE INTO port_cve
                (port_id, scan_id, cve_id, cvss_score, cvss_version, severity,
                 description, published_date, last_modified,
                 exploit_available, exploit_source, exploit_name,
                 exploit_payload, exploit_method)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                port_id,
                scan_id,
                cve["cve_id"],
                cve.get("cvss_score", 0.0),
                cve.get("cvss_version"),
                cve.get("severity", "UNKNOWN"),
                cve.get("description", ""),
                cve.get("published_date"),
                cve.get("last_modified"),
                1 if cve.get("exploit_available") else 0,
                cve.get("exploit_source"),
                cve.get("exploit_name"),
                cve.get("exploit_payload"),
                cve.get("exploit_method"),
            ))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"    [!] Erreur insertion CVE {cve.get('cve_id')}: {e}")
            return False

    def get_cves_for_scan(self, scan_id: int) -> List[Dict]:
        """
        Récupère toutes les CVEs enregistrées pour un scan.
        Utilisé par report.py.
        """
        cursor = self.conn.execute("""
            SELECT
                pc.cve_id,
                pc.cvss_score,
                pc.severity,
                pc.description,
                pc.exploit_available,
                pc.exploit_source,
                pc.exploit_name,
                pc.exploit_payload,
                pc.exploit_method,
                pc.published_date,
                p.port_number,
                p.protocol,
                p.service_name,
                p.service_version
            FROM port_cve pc
            JOIN ports p ON p.id = pc.port_id
            WHERE pc.scan_id = ?
            ORDER BY pc.cvss_score DESC
        """, (scan_id,))
        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        if self.conn:
            self.conn.close()



# Parsing des versions de service (nmap → mots-clés NVD)

def parse_service_info(service_name: Optional[str],
                       service_version: Optional[str]) -> Tuple[str, str]:
    """
    Extrait un nom propre et une version courte depuis les champs nmap.

    Exemples :
      "http"  + "Apache httpd 2.4.49 ((Unix))"  → ("apache", "2.4.49")
      "ssh"   + "OpenSSH 7.4 (protocol 2.0)"    → ("openssh", "7.4")
      "ms-sql-s" + "Microsoft SQL Server 2019"  → ("mssql", "2019")
    """
    name        = (service_name or "").lower().strip()
    raw_version = (service_version or "").strip()

    alias_map = {
        "http":         "apache",
        "https":        "apache",
        "www":          "apache",
        "ms-sql-s":     "mssql",
        "microsoft-ds": "smb",
        "netbios-ssn":  "smb",
        "domain":       "bind",
    }
    name = alias_map.get(name, name)

    product = name
    version = ""

    if raw_version:
        product_match = re.match(r'^([A-Za-z][\w\-\.]+(?:\s+[\w\-\.]+)?)', raw_version)
        if product_match:
            product = product_match.group(1).split()[0].lower()
            product = re.sub(r'[^a-z0-9\-]', '', product)

        version_match = re.search(r'(\d+\.\d+(?:\.\d+)*)', raw_version)
        if version_match:
            version = version_match.group(1)

    if len(name) > 4 and name not in alias_map.values():
        product = name

    return product.strip(), version.strip()


def build_nvd_keyword(product: str, version: str) -> str:
    """Construit la chaîne de recherche envoyée à l'API NVD."""
    if version:
        return f"{product} {version}"
    return product



# Client API NVD

class NvdClient:
    """
    Interroge l'API NVD 2.0 pour trouver les CVEs associées
    à un couple (service, version).
    """

    def __init__(self, api_key: str = NVD_API_KEY, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "PentestTool-CVEScanner/1.0",
        })
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        self._last_request_time = 0.0

    def _throttle(self):
        """Respecte le rate-limit NVD."""
        elapsed = time.time() - self._last_request_time
        if elapsed < REQUEST_DELAY:
            time.sleep(REQUEST_DELAY - elapsed)
        self._last_request_time = time.time()

    def _log(self, msg: str):
        if self.verbose:
            print(f"    [NVD] {msg}")

    def search_cves(self, keyword: str,
                    results_per_page: int = MAX_CVE_PER_PORT) -> List[Dict]:
        """
        Recherche des CVEs par mot-clé sur l'API NVD.
        Retourne une liste de dicts normalisés, triés par score CVSS décroissant.
        """
        self._throttle()
        params = {
            "keywordSearch":  keyword,
            "resultsPerPage": min(results_per_page, 20),
        }
        self._log(f"Requête NVD : '{keyword}'")

        try:
            resp = self.session.get(NVD_BASE_URL, params=params, timeout=15)
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                print("    [!] Rate limit NVD atteint — pause 35s...")
                time.sleep(35)
                return self.search_cves(keyword, results_per_page)
            self._log(f"Erreur HTTP : {e}")
            return []
        except requests.exceptions.RequestException as e:
            self._log(f"Erreur réseau : {e}")
            return []

        data            = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        self._log(f"{len(vulnerabilities)} CVE(s) reçue(s)")

        parsed = []
        for item in vulnerabilities:
            cve_data   = item.get("cve", {})
            parsed_cve = self._parse_cve(cve_data)
            if parsed_cve and parsed_cve["cvss_score"] >= CVSS_MIN_SCORE:
                parsed.append(parsed_cve)

        parsed.sort(key=lambda x: x["cvss_score"], reverse=True)
        return parsed[:results_per_page]

    def _parse_cve(self, cve_data: Dict) -> Optional[Dict]:
        """
        Extrait les champs utiles depuis la réponse brute NVD.
        Priorité CVSS : v3.1 > v3.0 > v2.0.
        """
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        # Description en anglais
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Score CVSS
        cvss_score   = 0.0
        cvss_version = None
        severity     = "UNKNOWN"
        metrics      = cve_data.get("metrics", {})

        if "cvssMetricV31" in metrics:
            m            = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score   = m.get("baseScore", 0.0)
            severity     = m.get("baseSeverity", "UNKNOWN")
            cvss_version = "3.1"
        elif "cvssMetricV30" in metrics:
            m            = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score   = m.get("baseScore", 0.0)
            severity     = m.get("baseSeverity", "UNKNOWN")
            cvss_version = "3.0"
        elif "cvssMetricV2" in metrics:
            m            = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score   = m.get("baseScore", 0.0)
            severity     = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
            cvss_version = "2.0"

        published = cve_data.get("published",    "")[:10]
        modified  = cve_data.get("lastModified", "")[:10]

        return {
            "cve_id":          cve_id,
            "cvss_score":      float(cvss_score),
            "cvss_version":    cvss_version,
            "severity":        severity.upper(),
            "description":     description,
            "published_date":  published,
            "last_modified":   modified,
            # Champs exploit — remplis plus tard via get_local_exploit()
            "exploit_available": False,
            "exploit_source":    None,
            "exploit_name":      None,
            "exploit_payload":   None,
            "exploit_method":    None,
        }



# Moteur principal CVEScanner

class CVEScanner:
    """
    Orchestre la recherche de CVEs pour un scan donné.

    Workflow :
      1. Lire les ports ouverts (scan_id) depuis la DB
      2. Pour chaque port : parser service+version → keyword NVD
      3. Interroger l'API NVD → liste de CVEs
      4. Pour chaque CVE : chercher un exploit dans la table locale `payloads`
      5. Stocker les résultats dans port_cve
    """

    def __init__(self,
                 db_path:      str  = DB_PATH,
                 api_key:      str  = NVD_API_KEY,
                 verbose:      bool = False,
                 force_rescan: bool = False):
        self.verbose      = verbose
        self.force_rescan = force_rescan
        self.db           = CveDatabase(db_path)
        self.nvd          = NvdClient(api_key=api_key, verbose=verbose)

        self.stats = {
            "ports_analyzed":  0,
            "ports_skipped":   0,
            "cves_found":      0,
            "cves_stored":     0,
            "exploits_matched": 0,   # exploits trouvés en DB locale
        }

    def _log(self, msg: str, level: str = "INFO"):
        prefix = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]", "ERROR": "[-]"}.get(level, "[*]")
        print(f"{prefix} {msg}")

    def run(self, scan_id: int) -> List[Dict]:
        """
        Lance l'analyse CVE complète pour un scan_id.
        Retourne la liste de toutes les CVEs trouvées et stockées.
        """
        self._log(f"Démarrage analyse CVE pour scan_id={scan_id}")
        start = datetime.now()

        # 1. Récupération des ports ouverts
        ports = self.db.get_ports_for_scan(scan_id)
        if not ports:
            self._log("Aucun port ouvert trouvé pour ce scan.", "WARNING")
            return []

        self._log(f"{len(ports)} port(s) ouvert(s) à analyser")
        print("-" * 60)

        all_cves = []

        for port in ports:
            port_id      = port["id"]
            port_number  = port["port_number"]
            service_name = port["service_name"]
            service_ver  = port["service_version"]

            ver_display = f" ({service_ver})" if service_ver else ""
            print(f"\n[>] Port {port_number}/{port['protocol']} — "
                  f"{service_name or '?'}{ver_display}")

            # Skip si déjà analysé (sauf --force)
            if not self.force_rescan and self.db.cve_already_scanned(port_id):
                self._log("  Déjà analysé — ignoré (utilisez --force pour forcer)", "WARNING")
                self.stats["ports_skipped"] += 1
                continue

            # 2. Parsing du service
            product, version = parse_service_info(service_name, service_ver)
            if not product:
                self._log("  Nom de service non exploitable, ignoré.", "WARNING")
                self.stats["ports_skipped"] += 1
                continue

            keyword = build_nvd_keyword(product, version)
            print(f"    Recherche NVD : '{keyword}'")
            self.stats["ports_analyzed"] += 1

            # 3. Appel NVD
            cves = self.nvd.search_cves(keyword)
            self.stats["cves_found"] += len(cves)

            if not cves:
                print("    Aucune CVE trouvée.")
                continue

            print(f"    {len(cves)} CVE(s) trouvée(s) :")

            # 4. Matching exploit local + stockage
            for cve in cves:
                cve_id   = cve["cve_id"]
                score    = cve["cvss_score"]
                severity = cve["severity"]

                # Cherche un exploit dans notre table `payloads` locale
                exploit_info = self.db.get_local_exploit(cve_id)
                cve.update(exploit_info)

                if cve["exploit_available"]:
                    self.stats["exploits_matched"] += 1

                # Affichage avec icône
                icon        = self._severity_icon(severity, cve["exploit_available"])
                exploit_tag = f" [LOCAL EXPLOIT: {cve['exploit_name']}]" if cve["exploit_available"] else ""
                print(f"      {icon} {cve_id} — CVSS {score:.1f} ({severity}){exploit_tag}")

                if self.verbose and cve["description"]:
                    print(f"         {cve['description'][:100]}...")
                if self.verbose and cve["exploit_available"]:
                    print(f"         Payload  : {cve['exploit_payload']}")
                    print(f"         Méthode  : {cve['exploit_method']}")

                # 5. Sauvegarde en base
                if self.db.save_cve(port_id, scan_id, cve):
                    self.stats["cves_stored"] += 1
                    all_cves.append(cve)

        # Récapitulatif final
        duration = (datetime.now() - start).total_seconds()
        print("\n" + "=" * 60)
        print(f"  ANALYSE CVE TERMINÉE — {duration:.1f}s")
        print(f"  Ports analysés      : {self.stats['ports_analyzed']}")
        print(f"  Ports ignorés       : {self.stats['ports_skipped']}")
        print(f"  CVEs trouvées       : {self.stats['cves_found']}")
        print(f"  CVEs stockées       : {self.stats['cves_stored']}")
        print(f"  Exploits locaux     : {self.stats['exploits_matched']}")
        print("=" * 60)

        return all_cves

    @staticmethod
    def _severity_icon(severity: str, exploit: bool) -> str:
        icons = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🔵",
            "NONE":     "⚪",
            "UNKNOWN":  "⚫",
        }
        if exploit:
            return "💥"
        return icons.get(severity.upper(), "⚫")

    def get_summary(self, scan_id: int) -> List[Dict]:
        """Récupère un résumé des CVEs stockées. Utilisé par report.py."""
        return self.db.get_cves_for_scan(scan_id)

    def export_json(self, scan_id: int, output_path: str = None) -> str:
        """Exporte les CVEs d'un scan au format JSON."""
        cves = self.db.get_cves_for_scan(scan_id)
        if not output_path:
            ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"cve_scan_{scan_id}_{ts}.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"scan_id": scan_id, "cves": cves, "total": len(cves)}, f, indent=2)
        self._log(f"Export JSON : {output_path}", "SUCCESS")
        return output_path

    def close(self):
        self.db.close()



# Points d'entrée pour main.py et report.py

def run_cve_scan(scan_id:      int,
                 db_path:      str  = DB_PATH,
                 api_key:      str  = NVD_API_KEY,
                 verbose:      bool = False,
                 force:        bool = False) -> List[Dict]:
    """Point d'entrée simplifié pour main.py."""
    scanner = CVEScanner(
        db_path=db_path,
        api_key=api_key,
        verbose=verbose,
        force_rescan=force,
    )
    try:
        return scanner.run(scan_id)
    finally:
        scanner.close()


def get_cves_for_report(scan_id: int, db_path: str = DB_PATH) -> List[Dict]:
    """Point d'entrée pour report.py."""
    db = CveDatabase(db_path)
    try:
        return db.get_cves_for_scan(scan_id)
    finally:
        db.close()



# Interface CLI autonome

def main():
    parser = argparse.ArgumentParser(
        description="CVE Scanner — Recherche NVD + matching exploit local",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python cve.py --list-scans
  python cve.py --scan-id 1
  python cve.py --scan-id 1 --verbose
  python cve.py --scan-id 1 --force
  python cve.py --scan-id 1 --force --export cve_results.json
        """
    )
    parser.add_argument("--scan-id",    type=int,            help="ID du scan à analyser")
    parser.add_argument("--list-scans", action="store_true", help="Lister les scans disponibles")
    parser.add_argument("--verbose","-v",action="store_true",help="Affichage détaillé")
    parser.add_argument("--force",      action="store_true", help="Re-scanner même les ports déjà analysés")
    parser.add_argument("--export",     metavar="FILE",      help="Exporter les résultats en JSON")
    parser.add_argument("--db",         default=DB_PATH,     help=f"Chemin SQLite (défaut: {DB_PATH})")
    parser.add_argument("--api-key",    default=NVD_API_KEY, help="Clé API NVD (ou via .env NVD_API_KEY)")
    args = parser.parse_args()

    # --- Listing des scans ---
    if args.list_scans:
        try:
            db    = CveDatabase(args.db)
            scans = db.get_scan_ids()
            db.close()
        except FileNotFoundError as e:
            print(e)
            return 1

        if not scans:
            print("Aucun scan en base.")
            return 0

        print(f"\n{'ID':>4}  {'Cible':<25} {'IP':<16} {'Date':<20} {'Statut':<12} {'Ports'}")
        print("-" * 85)
        for s in scans:
            print(f"{s['id']:>4}  {(s['target'] or ''):<25} {(s['target_ip'] or ''):<16} "
                  f"{(s['start_time'] or '')[:19]:<20} {(s['status'] or ''):<12} {s['open_ports_count']}")
        return 0

    # --- Scan CVE ---
    if not args.scan_id:
        parser.print_help()
        return 1

    print(f"\n{'='*60}")
    print(f"  CVE Scanner — scan_id={args.scan_id}")
    print(f"  API NVD  : {'configurée ✓' if (args.api_key or NVD_API_KEY) else 'ABSENTE (rate-limit strict)'}")
    print(f"  Exploits : matching local DB (table payloads)")
    print(f"{'='*60}\n")

    try:
        scanner = CVEScanner(
            db_path=args.db,
            api_key=args.api_key,
            verbose=args.verbose,
            force_rescan=args.force,
        )
    except FileNotFoundError as e:
        print(e)
        return 1

    try:
        cves = scanner.run(args.scan_id)
        if args.export:
            scanner.export_json(args.scan_id, args.export)
    finally:
        scanner.close()

    return 0 if cves is not None else 1


if __name__ == "__main__":
    sys.exit(main())
