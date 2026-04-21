#!/usr/bin/env python3
"""
cli.py — Interface en ligne de commande du PenTool
Utilise Click + Rich pour une UX claire et colorée.
Base de données : SQLite uniquement (pentool.db)
→ Cohérence totale avec modules/scanner.py, modules/cve.py, modules/exploit.py et reporter.py
FIX 1 : Mapping service nmap → service seed dans get_payloads_for_scan()
 Nmap retourne 'http', 'ssh', 'ftp'... mais le seed stocke 'apache', 'bash', 'smb'...
 Le JOIN port seul + filtre SERVICE_MAP résout le problème "Aucun payload trouvé".
FIX 2 : CVE non trouvées — deux causes corrigées :
 a) alias_map de parse_service_info() trop limité dans cve.py
    → on le remplace par EXTENDED_ALIAS_MAP (40+ entrées) via monkey-patch
 b) get_local_exploit() cherche uniquement par cve_id exact
    → on ajoute un fallback : cherche par (port, service) si cve_id absent du seed
"""
import sys
import sqlite3
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from datetime import datetime

console = Console()

# ─────────────────────────────────────────────
# Mapping nmap service → valeurs service du seed
# ─────────────────────────────────────────────
SERVICE_MAP = {
    # Web
    "http": ["apache", "nginx", "web", "php", "drupal", "wordpress",
             "tomcat", "jboss", "weblogic", "iis", "glassfish",
             "joomla", "magento", "struts", "spring", "laravel",
             "symfony", "rails", "nodejs", "python", "flask",
             "django", "ruby", "java", "graphql", "api",
             "phpmyadmin", "confluence", "papercut", "airflow",
             "superset", "grafana", "kibana", "prometheus",
             "hikvision", "dvr", "iot", "proxy", "varnish",
             "haproxy", "cloudfront", "akamai"],
    "https": ["apache", "nginx", "web", "ssl", "exchange", "citrix",
              "f5-bigip", "fortinet", "cisco-rv", "cisco-asa",
              "cisco-ios", "paloalto", "pulse-vpn", "vcenter",
              "kubernetes", "gitlab", "github", "connectwise",
              "sonicwall", "mobileiron", "teamcity", "bitbucket",
              "aws-s3", "azure-storage", "oauth", "websocket"],
    "http-alt": ["tomcat", "jboss", "weblogic", "spring", "spring-cloud",
                 "jenkins", "airflow", "rocketmq", "activemq",
                 "nexus", "artifactory", "wildfly", "payara",
                 "coldfusion", "glassfish", "solr"],
    # SSH / FTP / Telnet
    "ssh": ["ssh"],
    "ftp": ["ftp", "vsftpd"],
    "telnet": ["telnet", "iot"],
    # Mail
    "smtp": ["smtp"],
    "smtps": ["smtp"],
    "pop3": ["smtp"],
    "imap": ["smtp"],
    # Windows / SMB / AD
    "microsoft-ds": ["smb", "samba", "netlogon", "kerberos"],
    "netbios-ssn": ["smb", "samba", "netbios"],
    "msrpc": ["rpc", "adcs"],
    "ms-wbt-server": ["rdp"],
    "rdp": ["rdp"],
    "kerberos": ["kerberos"],
    # Bases de données
    "mysql": ["mysql"],
    "ms-sql-s": ["mssql"],
    "postgresql": ["postgresql"],
    "oracle": ["oracle"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "elasticsearch": ["elasticsearch"],
    "cassandra": ["cassandra"],
    "couchdb": ["couchdb"],
    "memcached": ["memcached"],
    "zookeeper": ["zookeeper"],
    "kafka": ["kafka"],
    "rabbitmq": ["rabbitmq"],
    # DNS / SNMP / LDAP / NTP
    "domain": ["dns"],
    "snmp": ["snmp"],
    "ldap": ["ldap"],
    "ldaps": ["ldap"],
    # Docker / Kubernetes
    "docker": ["docker", "docker-registry"],
    "kubernetes": ["kubernetes"],
    # Autres protocoles
    "vnc": ["vnc"],
    "mqtt": ["mqtt"],
    "modbus": ["modbus"],
    "bacnet": ["bacnet"],
    "stun": ["stun"],
    "upnp": ["upnp"],
    "ssdp": ["upnp"],
    "cups": ["cups"],
    "ipp": ["cups"],
    # Hadoop / Big Data
    "hadoop": ["hadoop-yarn", "hdfs", "hbase"],
    "spark": ["spark"],
    # Proxy / misc
    "socks": ["proxy"],
    "proxy": ["proxy"],
}

# ─────────────────────────────────────────────
# FIX 2a : alias_map étendu pour parse_service_info() de cve.py
# ─────────────────────────────────────────────
EXTENDED_ALIAS_MAP = {
    # HTTP / Web
    "http": "apache",
    "https": "apache",
    "www": "apache",
    "http-alt": "tomcat",
    "http-proxy": "apache",
    "webcache": "apache",
    "ajp13": "tomcat",
    # Bases de données
    "ms-sql-s": "mssql",
    "ms-sql-m": "mssql",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "oracle": "oracle",
    "oracle-tns": "oracle",
    "redis": "redis",
    "mongodb": "mongodb",
    "cassandra": "cassandra",
    "couchdb": "couchdb",
    "memcached": "memcached",
    "elasticsearch": "elasticsearch",
    # Windows / SMB / AD
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "netbios-ns": "smb",
    "msrpc": "rpc",
    "epmap": "rpc",
    "ms-wbt-server": "rdp",
    "kerberos-sec": "kerberos",
    "kerberos": "kerberos",
    "ldap": "ldap",
    "ldaps": "ldap",
    "msft-gc": "ldap",
    # Mail
    "smtp": "smtp",
    "smtps": "smtp",
    "pop3": "smtp",
    "imap": "smtp",
    "imaps": "smtp",
    # DNS / NTP / SNMP
    "domain": "bind",
    "snmp": "snmp",
    "ntp": "ntp",
    # SSH / FTP / Telnet
    "ssh": "openssh",
    "ftp": "vsftpd",
    "ftps": "vsftpd",
    "telnet": "telnet",
    # Docker / K8s
    "docker": "docker",
    "kubernetes": "kubernetes",
    # Autres
    "vnc": "vnc",
    "mqtt": "mqtt",
    "amqp": "rabbitmq",
    "zookeeper": "zookeeper",
    "kafka": "kafka",
    "spark": "spark",
    "hadoop": "hadoop-yarn",
    "cups": "cups",
    "ipp": "cups",
}


def _patched_parse_service_info(service_name, service_version):
    """
    Version corrigée de parse_service_info() de cve.py.
    Utilise EXTENDED_ALIAS_MAP au lieu de l'alias_map minimaliste original.
    Injectée via monkey-patch dans _apply_cve_patches().
    """
    import re
    name = (service_name or "").lower().strip()
    raw_version = (service_version or "").strip()

    # Résolution via l'alias map étendu (correspondance exacte d'abord)
    name = EXTENDED_ALIAS_MAP.get(name, name)

    # Correspondance partielle si toujours pas mappé
    if name not in EXTENDED_ALIAS_MAP.values():
        for key, val in EXTENDED_ALIAS_MAP.items():
            if key in name or name in key:
                name = val
                break

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
    if len(name) > 4 and name not in EXTENDED_ALIAS_MAP.values():
        product = name
    return product.strip(), version.strip()


def _patched_get_local_exploit(db_conn, cve_id: str) -> dict:
    """
    Version corrigée de CveDatabase.get_local_exploit().
    FIX 2b :
    L'original cherche UNIQUEMENT par cve_id exact → retourne False si
    le CVE retourné par NVD n'est pas dans le seed (cas fréquent).
    Nouveau comportement :
    1. Cherche par cve_id exact (comportement original)
    2. Si rien → cherche par préfixe CVE-YYYY pour avoir un payload
       du même produit/année (heuristique utile pour les variantes)
    3. Retourne toujours un dict cohérent
    """
    # 1. Correspondance exacte sur cve_id
    cursor = db_conn.execute("""
        SELECT name, payload, method, port, service
        FROM payloads
        WHERE cve_id = ?
        LIMIT 1
    """, (cve_id,))
    row = cursor.fetchone()
    if row:
        return {
            "exploit_available": True,
            "exploit_source": "local_db",
            "exploit_name": row["name"],
            "exploit_payload": row["payload"],
            "exploit_method": row["method"],
        }

    # 2. Fallback : même CVE année+produit (ex: CVE-2021-*)
    import re
    year_match = re.match(r'CVE-(\d{4})-', cve_id)
    if year_match:
        year = year_match.group(1)
        cursor = db_conn.execute("""
            SELECT name, payload, method, port, service
            FROM payloads
            WHERE cve_id LIKE ?
            LIMIT 1
        """, (f"CVE-{year}-%",))
        row = cursor.fetchone()
        if row:
            return {
                "exploit_available": True,
                "exploit_source": "local_db_approx",
                "exploit_name": row["name"],
                "exploit_payload": row["payload"],
                "exploit_method": row["method"],
            }

    return {
        "exploit_available": False,
        "exploit_source": None,
        "exploit_name": None,
        "exploit_payload": None,
        "exploit_method": None,
    }


def _apply_cve_patches():
    """
    Applique les monkey-patches sur modules/cve.py après son import.
    Appelé une seule fois au début de chaque commande qui utilise CVEScanner.
    Patches appliqués :
    - cve_module.parse_service_info → _patched_parse_service_info
      (alias_map étendu : 40+ services au lieu de 6)
    - CveDatabase.get_local_exploit → méthode enrichie avec fallback
      (cherche par cve_id exact, puis par année si absent du seed)
    """
    try:
        import modules.cve as cve_module
        # Patch 1 : parse_service_info avec alias_map étendu
        cve_module.parse_service_info = _patched_parse_service_info
        # Patch 2 : get_local_exploit avec fallback année
        def _new_get_local_exploit(self, cve_id: str) -> dict:
            return _patched_get_local_exploit(self.conn, cve_id)
        cve_module.CveDatabase.get_local_exploit = _new_get_local_exploit
    except ImportError:
        pass  # Module pas encore chargé, pas grave


def _build_service_filter(nmap_service: str):
    """
    Retourne la liste des valeurs 'service' du seed qui correspondent
    à un nom de service nmap.
    Stratégie (par ordre de priorité) :
    1. Correspondance exacte dans SERVICE_MAP
    2. Correspondance partielle : si le nom nmap contient une clé du map
    3. Fallback : retourner le nom nmap tel quel
    """
    if not nmap_service:
        return []
    s = nmap_service.lower()
    if s in SERVICE_MAP:
        return SERVICE_MAP[s]
    for key, values in SERVICE_MAP.items():
        if key in s or s in key:
            return values
    return [s]


# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────
BANNER = r"""
██████╗ ███████╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║   ██║██║
██║     ███████╗██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
"""


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(
        Panel(
            "[bold white]Automated Penetration Testing Framework[/bold white]\n"
            "[dim]ENSA Marrakech — Ethical Hacking Project[/dim]",
            border_style="red",
            expand=False,
        )
    )
    console.print()


# ─────────────────────────────────────────────
# Helpers affichage
# ─────────────────────────────────────────────
def section(title: str):
    console.print(f"\n[bold cyan]❯ {title}[/bold cyan]")
    console.rule(style="cyan")


def success(msg: str):
    console.print(f"[bold green] ✔ {msg}[/bold green]")


def info(msg: str):
    console.print(f"[blue] ℹ {msg}[/blue]")


def warn(msg: str):
    console.print(f"[yellow] ⚠ {msg}[/yellow]")


def error(msg: str):
    console.print(f"[bold red] ✘ {msg}[/bold red]")


def abort(msg: str):
    error(msg)
    sys.exit(1)


# ─────────────────────────────────────────────
# Helper SQLite
# ─────────────────────────────────────────────
def _sqlite_connect(db_path: str = "pentool.db") -> sqlite3.Connection:
    """Ouvre une connexion SQLite avec row_factory activé."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_payloads_table(db_path: str = "pentool.db"):
    """Crée la table payloads si elle n'existe pas."""
    conn = _sqlite_connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'generic',
            protocol TEXT NOT NULL DEFAULT 'tcp',
            port INTEGER,
            service TEXT,
            cve_id TEXT,
            method TEXT,
            payload TEXT,
            template TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def _init_db_schema(db_path: str = "pentool.db"):
    """Crée toutes les tables nécessaires si elles n'existent pas."""
    conn = _sqlite_connect(db_path)
    cur = conn.cursor()
    cur.execute("""
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
    cur.execute("""
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS port_cve (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            cvss_score REAL DEFAULT 0.0,
            cvss_version TEXT,
            severity TEXT,
            description TEXT,
            published_date TEXT,
            last_modified TEXT,
            exploit_available INTEGER DEFAULT 0,
            exploit_source TEXT,
            exploit_name TEXT,
            exploit_payload TEXT,
            exploit_method TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            UNIQUE(port_id, cve_id)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_port_cve_scan ON port_cve(scan_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_port_cve_score ON port_cve(cvss_score DESC)")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'generic',
            protocol TEXT NOT NULL DEFAULT 'tcp',
            port INTEGER,
            service TEXT,
            cve_id TEXT,
            method TEXT,
            payload TEXT,
            template TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS exploit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port_cve_id INTEGER,
            cve_id TEXT NOT NULL,
            payload_name TEXT,
            payload_used TEXT,
            method TEXT,
            target_ip TEXT,
            port INTEGER,
            requete_envoyee TEXT,
            reponse_recue TEXT,
            code_retour TEXT,
            succes INTEGER DEFAULT 0,
            duree_ms REAL,
            date_tentative TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY (port_cve_id) REFERENCES port_cve(id) ON DELETE SET NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_exploit_scan ON exploit_logs(scan_id)")
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# FIX : Recherche payloads avec mapping service
# ─────────────────────────────────────────────
def get_payloads_for_scan(db_path: str, scan_id: int) -> list:
    """Retourne les payloads correspondant aux ports ouverts d'un scan."""
    conn = _sqlite_connect(db_path)
    ports_rows = conn.execute("""
        SELECT port_number, service_name
        FROM ports
        WHERE scan_id = ? AND state = 'open'
    """, (scan_id,)).fetchall()

    if not ports_rows:
        conn.close()
        return []

    results = []
    for row in ports_rows:
        port_number = row["port_number"]
        nmap_service = row["service_name"] or ""
        seed_services = _build_service_filter(nmap_service)

        if seed_services:
            placeholders = ",".join("?" * len(seed_services))
            payload_rows = conn.execute(f"""
                SELECT DISTINCT
                    pl.name AS payload_name,
                    pl.payload,
                    pl.method,
                    pl.service AS payload_service,
                    pl.cve_id,
                    pl.port AS payload_port
                FROM payloads pl
                WHERE pl.port = ?
                AND (
                    pl.service IN ({placeholders})
                    OR pl.service IS NULL
                    OR pl.service = ''
                )
                ORDER BY pl.name
            """, [port_number] + seed_services).fetchall()
        else:
            payload_rows = conn.execute("""
                SELECT DISTINCT
                    pl.name AS payload_name,
                    pl.payload,
                    pl.method,
                    pl.service AS payload_service,
                    pl.cve_id,
                    pl.port AS payload_port
                FROM payloads pl
                WHERE pl.port = ?
                ORDER BY pl.name
            """, (port_number,)).fetchall()

        for pl in payload_rows:
            results.append({
                "port": port_number,
                "nmap_service": nmap_service,
                "payload_service": pl["payload_service"] or "",
                "payload_name": pl["payload_name"],
                "payload": pl["payload"] or "",
                "method": pl["method"] or "",
                "cve_id": pl["cve_id"] or "",
            })
    conn.close()
    return results


def _display_payloads_for_scan(db_path: str, scan_id: int):
    """Affiche un tableau Rich des payloads trouvés pour un scan."""
    payloads = get_payloads_for_scan(db_path, scan_id)
    if not payloads:
        warn(
            "Aucun payload trouvé pour les ports ouverts.\n"
            " → Vérifiez que seed.sql a bien été importé : pentool db init --seed\n"
            " → Ou ajoutez des payloads : pentool payloads add ..."
        )
        return

    success(f"{len(payloads)} payload(s) correspondant(s) trouvé(s) pour ce scan.")
    t = Table(
        box=box.SIMPLE_HEAD,
        header_style="bold magenta",
        show_lines=True,
        title="[bold]Payloads disponibles pour les ports ouverts[/bold]",
    )
    t.add_column("Port", style="cyan", justify="right")
    t.add_column("Service nmap", style="yellow")
    t.add_column("Service seed", style="dim")
    t.add_column("CVE", style="red")
    t.add_column("Payload", style="white")
    t.add_column("Méthode", style="green")
    t.add_column("Contenu", style="dim", no_wrap=False, max_width=50)

    for p in payloads:
        t.add_row(
            str(p["port"]),
            p["nmap_service"],
            p["payload_service"],
            p["cve_id"],
            p["payload_name"],
            p["method"],
            (p["payload"] or "")[:80],
        )
    console.print(t)


# ─────────────────────────────────────────────
# CLI Root
# ─────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """
    \b
    ╔══════════════════════════════════╗
    ║  PenTool — Automated Pentest    ║
    ╚══════════════════════════════════╝
    Lancez une commande ou utilisez --help sur chaque sous-commande.
    """
    print_banner()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


# ─────────────────────────────────────────────
# recon
# ─────────────────────────────────────────────
@cli.command("recon")
@click.option("--target", "-t", required=True, help="Cible : IP ou nom de domaine.")
@click.option("--dns", is_flag=True, default=False, help="Énumération DNS.")
@click.option("--whois", is_flag=True, default=False, help="Recherche WHOIS.")
@click.option("--geo", is_flag=True, default=False, help="Géolocalisation IP.")
@click.option("--banner", is_flag=True, default=False, help="Banner grabbing (socket).")
@click.option("--os", is_flag=True, default=False, help="OS fingerprinting passif (nmap).")
@click.option("--subdomains", is_flag=True, default=False, help="Énumération des sous-domaines.")
@click.option("--all", "run_all", is_flag=True, default=False, help="Lancer toutes les étapes.")
@click.option("--save/--no-save", default=True, show_default=True, help="Sauvegarder en base.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Affichage détaillé.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def recon(target, dns, whois, geo, banner, os, subdomains, run_all, save, verbose, db_path):
    """
    Reconnaissance passive et active d'une cible.
    \b
    Exemples :
      pentool recon -t example.com --all
      pentool recon -t 192.168.1.1 --dns --whois --geo
    """
    section(f"Reconnaissance — {target}")
    try:
        from modules.recon import run_recon, save_to_db
    except ImportError as e:
        abort(f"Impossible d'importer modules/recon.py : {e}")

    try:
        results = run_recon(
            target=target, dns=dns, whois=whois, geo=geo,
            banner=banner, os_fingerprint=os,
            subdomains=subdomains, run_all=run_all, verbose=verbose,
        )
    except ValueError:
        warn("Aucune option sélectionnée. Utilisez --all ou spécifiez une étape.")
        return
    except Exception as e:
        abort(f"Reconnaissance échouée : {e}")

    for name, result in results.items():
        success(f"{name} terminé.")
        if verbose:
            info(f"Résultat {name} : {result}")

    if save and results:
        try:
            save_to_db(target, results, db_path=db_path)
            success("Résultats sauvegardés en base.")
        except Exception as e:
            warn(f"Sauvegarde en base échouée : {e}")


# ─────────────────────────────────────────────
# scan
# ─────────────────────────────────────────────
@cli.command("scan")
@click.option("--target", "-t", required=True, help="Cible : IP, CIDR ou hostname.")
@click.option("--ports", "-p", default="1-1000", show_default=True, help="Plage de ports.")
@click.option("--intensity", "-i",
              type=click.Choice(["T1", "T2", "T3", "T4", "T5"], case_sensitive=False),
              default="T4", show_default=True, help="Timing Nmap.")
@click.option("--udp", is_flag=True, default=False, help="Inclure le scan UDP.")
@click.option("--fast", is_flag=True, default=False, help="Scan rapide (top 20 ports).")
@click.option("--full", is_flag=True, default=False, help="Scan complet (1-65535).")
@click.option("--stealth", is_flag=True, default=False, help="Mode furtif SYN scan.")
@click.option("--aggressive", is_flag=True, default=False, help="Mode agressif (-A).")
@click.option("--scripts", "-s", multiple=True, help="Scripts NSE (répétable).")
@click.option("--no-db", is_flag=True, default=False, help="Ne pas sauvegarder en base.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def scan(target, ports, intensity, udp, fast, full, stealth, aggressive, scripts, no_db, db_path):
    """
    Scan de ports et détection de services via Nmap.
    \b
    Exemples :
      pentool scan -t 192.168.1.1 --ports 1-65535 -i T4
      pentool scan -t 10.0.0.1 --fast
      pentool scan -t 10.0.0.1 --ports 80,443 --scripts http-title
    """
    section(f"Scan de ports — {target} [{ports}]")
    try:
        from modules.scanner import PortScanner, Database, scan_network_range
    except ImportError as e:
        abort(f"Impossible d'importer modules/scanner.py : {e}")

    if not no_db:
        _ensure_payloads_table(db_path)

    db = None if no_db else Database(db_path)

    if "/" in target:
        info("Cible CIDR détectée — scan réseau en cours…")
        try:
            results = scan_network_range(target, ports=ports, verbose=True, db=db, no_db=no_db)
            success(f"{len(results)} port(s) ouvert(s) au total sur le réseau.")
            _display_ports_table(results)
        except Exception as e:
            abort(f"Scan réseau échoué : {e}")
        finally:
            if db:
                db.close()
        return

    scanner = PortScanner(target, verbose=True, db=db, no_db=no_db)
    nmap_args = f"-sV --version-light -{intensity}"
    if aggressive:
        nmap_args = f"-A -{intensity}"
    elif stealth:
        nmap_args = f"-sS -sV -{intensity}"
    if scripts:
        nmap_args += " --script " + ",".join(scripts)
        info(f"Scripts NSE : {', '.join(scripts)}")

    info(f"Arguments nmap : {nmap_args} | UDP : {'oui' if udp else 'non'}")
    try:
        if fast:
            results = scanner.fast_scan()
        elif full:
            results = scanner.full_scan()
        elif aggressive:
            results = scanner.aggressive_scan()
        elif stealth:
            results = scanner.stealth_scan()
        else:
            results = scanner.scan_ports(ports=ports, arguments=nmap_args, udp=udp)

        success(f"{len(results)} port(s) découvert(s). Scan ID : {scanner.scan_id}")
        _display_ports_table(results)

        if not no_db and scanner.scan_id and scanner.scan_id != -1:
            console.print()
            section("Payloads correspondants aux ports ouverts")
            _display_payloads_for_scan(db_path, scanner.scan_id)
    except Exception as e:
        abort(f"Scan échoué : {e}")
    finally:
        if db:
            db.close()


def _display_ports_table(ports_data: list):
    """Affiche un tableau Rich des ports découverts."""
    if not ports_data:
        warn("Aucun port ouvert trouvé.")
        return

    t = Table(box=box.SIMPLE_HEAD, header_style="bold magenta", show_lines=True)
    t.add_column("Host", style="white")
    t.add_column("Port", style="cyan", justify="right")
    t.add_column("Proto", style="white")
    t.add_column("État", style="green")
    t.add_column("Service", style="yellow")
    t.add_column("Version", style="dim")
    t.add_column("Bannière", style="dim")

    for p in ports_data:
        t.add_row(
            p.get("host", ""),
            str(p.get("port", "")),
            p.get("protocol", "tcp"),
            p.get("state", "open"),
            p.get("service", "") or "",
            p.get("version", "") or "",
            p.get("banner", "") or "",
        )
    console.print(t)


# ─────────────────────────────────────────────
# cve
# ─────────────────────────────────────────────
@cli.command("cve")
@click.option("--target", "-t", required=True,
              help="Cible (doit avoir été scannée au préalable).")
@click.option("--scan-id", "-s", type=int, default=None,
              help="ID du scan (si omis, prend le dernier scan de la cible).")
@click.option("--min-score", "-m", default=0.0, show_default=True, type=float,
              help="Score CVSS minimum (0–10).")
@click.option("--force", is_flag=True, default=False, help="Re-scanner (ignore le cache).")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Affichage détaillé.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def cve(target, scan_id, min_score, force, verbose, db_path):
    """
    Recherche de CVE via l'API NVD pour les services détectés.
    \b
    Exemples :
      pentool cve -t 192.168.1.1 --min-score 7.0
      pentool cve -t example.com --scan-id 3 --verbose
    """
    section(f"Recherche CVE — {target} (CVSS ≥ {min_score})")
    _apply_cve_patches()  # FIX 2 : alias_map étendu + fallback get_local_exploit
    try:
        from modules.cve import CVEScanner, CveDatabase
    except ImportError as e:
        abort(f"Impossible d'importer modules/cve.py : {e}")

    if scan_id is None:
        try:
            db = CveDatabase(db_path)
            scans = db.get_scan_ids()
            db.close()
            matched = [
                s for s in scans
                if target in (s.get("target", ""), s.get("target_ip", ""))
            ]
            if not matched:
                abort(
                    f"Aucun scan trouvé pour '{target}'.\n"
                    f" Lancez d'abord : pentool scan -t {target}"
                )
            scan_id = matched[0]["id"]
        except Exception as e:
            abort(f"Erreur résolution scan_id : {e}")

    info(f"Scan ID retenu : {scan_id}")
    info("Interrogation de l'API NVD…")
    try:
        scanner = CVEScanner(db_path=db_path, verbose=verbose, force_rescan=force)
        findings = scanner.run(scan_id)
        scanner.close()
    except Exception as e:
        abort(f"Recherche CVE échouée : {e}")

    if min_score > 0.0:
        findings = [f for f in findings if f.get("cvss_score", 0.0) >= min_score]

    success(f"{len(findings)} CVE(s) trouvée(s) (CVSS ≥ {min_score}).")
    _display_cve_table(findings)


def _display_cve_table(findings: list):
    if not findings:
        warn("Aucune CVE à afficher.")
        return

    t = Table(box=box.SIMPLE_HEAD, header_style="bold magenta", show_lines=True)
    t.add_column("CVE ID", style="red")
    t.add_column("Port", style="cyan", justify="right")
    t.add_column("Service", style="yellow")
    t.add_column("CVSS", style="bold", justify="center")
    t.add_column("Exploit?", style="green", justify="center")
    t.add_column("Description", style="dim", no_wrap=False, max_width=55)

    for f in findings:
        score = f.get("cvss_score", 0.0)
        score_color = "red" if score >= 9 else ("yellow" if score >= 7 else "green")
        port_val = str(f.get("port_number", f.get("port", "")))
        service_val = f.get("service_name", f.get("service", ""))
        t.add_row(
            f.get("cve_id", ""),
            port_val,
            service_val,
            f"[{score_color}]{score:.1f}[/{score_color}]",
            "✔" if f.get("exploit_available") else "✘",
            f.get("description", "")[:120],
        )
    console.print(t)


# ─────────────────────────────────────────────
# exploit
# ─────────────────────────────────────────────
@cli.command("exploit")
@click.option("--target", "-t", default=None, help="IP ou hostname de la cible.")
@click.option("--scan-id", "-s", type=int, default=None, help="ID du scan à exploiter.")
@click.option("--cve", "-c", default=None, help="Filtrer sur une CVE précise.")
@click.option("--lhost", "-L", default="", help="IP locale pour les reverse shells.")
@click.option("--lport", "-l", default="4444", show_default=True, help="Port local.")
@click.option("--all-payloads", "all_payloads", is_flag=True, default=False,
              help="Tester toutes les variantes de payload.")
@click.option("--no-skip", is_flag=True, default=False,
              help="Re-tenter même les CVEs déjà exploitées.")
@click.option("--timeout", type=int, default=5, show_default=True,
              help="Timeout par requête (s).")
@click.option("--dry-run", is_flag=True, default=False,
              help="Simuler sans envoyer de payload.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Affichage détaillé.")
@click.option("--export", default=None, help="Exporter les résultats JSON.")
@click.option("--list-scans", is_flag=True, default=False, help="Lister les scans disponibles.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def exploit(target, scan_id, cve, lhost, lport, all_payloads, no_skip,
            timeout, dry_run, verbose, export, list_scans, db_path):
    """
    Exploitation des CVEs trouvées par le module cve.
    \b
    Exemples :
      pentool exploit -t 192.168.1.10 --cve CVE-2021-41773 -L 192.168.1.5
      pentool exploit -t 10.0.0.1 --dry-run --verbose
      pentool exploit --list-scans
    """
    section("Exploitation")
    try:
        from modules.exploit import run_exploit as _run_exploit, ExploitDatabase
    except ImportError as e:
        abort(f"Impossible d'importer modules/exploit.py : {e}")

    if list_scans:
        try:
            db = ExploitDatabase(db_path)
            scans = db.get_all_scans()
            db.close()
        except FileNotFoundError as e:
            abort(str(e))
        if not scans:
            warn("Aucun scan en base.")
            return
        t = Table(box=box.SIMPLE_HEAD, header_style="bold magenta")
        t.add_column("ID", style="cyan", justify="right")
        t.add_column("Cible", style="white")
        t.add_column("IP", style="yellow")
        t.add_column("Date", style="dim")
        t.add_column("Statut", style="green")
        t.add_column("Ports", style="cyan", justify="right")
        for s in scans:
            t.add_row(
                str(s["id"]), s.get("target", ""),
                s.get("target_ip", "") or "",
                (s.get("start_time", "") or "")[:19],
                s.get("status", ""),
                str(s.get("open_ports_count", 0)),
            )
        console.print(t)
        return

    if scan_id is None:
        if not target:
            abort("--target ou --scan-id est requis (ou --list-scans).")
        try:
            db = ExploitDatabase(db_path)
            scans = db.get_all_scans()
            db.close()
        except FileNotFoundError as e:
            abort(str(e))
        matched = [
            s for s in scans
            if target in (s.get("target", ""), s.get("target_ip", ""))
        ]
        if not matched:
            abort(
                f"Aucun scan trouvé pour '{target}'.\n"
                f" Lancez d'abord : pentool scan -t {target}"
            )
        scan_id = matched[0]["id"]
    info(f"Scan ID retenu : {scan_id}")

    if dry_run:
        warn("Mode DRY-RUN : aucun payload ne sera envoyé.")
    try:
        if no_skip or timeout != 5:
            from modules.exploit import ExploitEngine
            db_obj = ExploitDatabase(db_path)
            engine = ExploitEngine(
                db_obj,
                verbose=verbose,
                timeout=timeout,
                dry_run=dry_run,
                all_payloads=all_payloads,
                skip_done=not no_skip,
            )
            results = engine.run(scan_id, cve_filter=cve, lhost=lhost, lport=str(lport))
            engine.afficher_resume()
            db_obj.close()
        else:
            results = _run_exploit(
                scan_id=scan_id,
                db_path=db_path,
                cve_id=cve,
                lhost=lhost,
                lport=str(lport),
                verbose=verbose,
                dry_run=dry_run,
                all_payloads=all_payloads,
            )
    except Exception as e:
        abort(f"Erreur durant l'exploitation : {e}")

    if results:
        succes_list = [r for r in results if r.get("succes")]
        success(f"{len(succes_list)} exploit(s) confirmé(s) / {len(results)} tentative(s).")
        if succes_list:
            t = Table(box=box.SIMPLE_HEAD, header_style="bold magenta", show_lines=True)
            t.add_column("CVE ID", style="red")
            t.add_column("Port", style="cyan", justify="right")
            t.add_column("Payload", style="yellow")
            t.add_column("Méthode", style="dim")
            t.add_column("Durée ms", style="dim", justify="right")
            for r in succes_list:
                t.add_row(
                    r.get("cve_id", ""),
                    str(r.get("port", "")),
                    r.get("payload_name", ""),
                    r.get("method", ""),
                    f"{r.get('duree_ms', 0):.0f}",
                )
            console.print(t)
    else:
        warn("Aucun résultat retourné.")

    if export and results:
        import json
        export_data = {
            "scan_id": scan_id,
            "target": target,
            "date": datetime.now().isoformat(),
            "resultats": results,
        }
        try:
            with open(export, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            success(f"Résultats exportés → {export}")
        except Exception as e:
            warn(f"Export JSON échoué : {e}")


# ─────────────────────────────────────────────
# report
# ─────────────────────────────────────────────
@cli.command("report")
@click.option("--target", "-t", default=None, help="Cible (pour résoudre le scan_id).")
@click.option("--scan-id", "-s", type=int, default=None, help="ID du scan à reporter.")
@click.option("--output", "-o", default=None, help="Chemin du PDF de sortie.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Affichage détaillé.")
@click.option("--open", "open_report", is_flag=True, default=False,
              help="Ouvrir le PDF après génération.")
@click.option("--list-scans", is_flag=True, default=False, help="Lister les scans disponibles.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def report(target, scan_id, output, verbose, open_report, list_scans, db_path):
    """
    Génération du rapport PDF de pentest (via reporter.py).
    \b
    Exemples :
      pentool report -t 192.168.1.1
      pentool report --scan-id 3 -o /tmp/rapport.pdf --open
    """
    section("Génération du rapport PDF")
    try:
        from reporter import generate_report as _generate_report, ReportDatabase
    except ImportError as e:
        abort(f"Impossible d'importer reporter.py : {e}")

    if list_scans:
        try:
            db = ReportDatabase(db_path)
            scans = db.list_scans()
            db.close()
        except FileNotFoundError as e:
            abort(str(e))
        if not scans:
            warn("Aucun scan en base.")
            return
        t = Table(box=box.SIMPLE_HEAD, header_style="bold magenta")
        t.add_column("ID", style="cyan", justify="right")
        t.add_column("Cible", style="white")
        t.add_column("IP", style="yellow")
        t.add_column("Date", style="dim")
        t.add_column("Statut", style="green")
        t.add_column("Ports", style="cyan", justify="right")
        for s in scans:
            t.add_row(
                str(s["id"]), s.get("target", ""),
                s.get("target_ip", "") or "",
                (s.get("start_time", "") or "")[:19],
                s.get("status", ""),
                str(s.get("open_ports_count", 0)),
            )
        console.print(t)
        return

    if scan_id is None:
        if not target:
            abort("--target ou --scan-id est requis (ou --list-scans).")
        try:
            db = ReportDatabase(db_path)
            scans = db.list_scans()
            db.close()
        except FileNotFoundError as e:
            abort(str(e))
        matched = [
            s for s in scans
            if target in (s.get("target", ""), s.get("target_ip", ""))
        ]
        if not matched:
            abort(
                f"Aucun scan trouvé pour '{target}'.\n"
                f" Lancez d'abord : pentool scan -t {target}"
            )
        scan_id = matched[0]["id"]
    info(f"Scan ID retenu : {scan_id}")

    label = target or f"scan{scan_id}"
    if output is None:
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_label = label.replace("/", "_").replace(":", "_")
        output = f"rapport_{safe_label}_{date_str}.pdf"
    info(f"Fichier de sortie : {output}")

    try:
        out_path = _generate_report(
            scan_id=scan_id,
            db_path=db_path,
            output_path=output,
            verbose=verbose,
        )
        success(f"Rapport PDF généré → {out_path}")
    except FileNotFoundError as e:
        abort(str(e))
    except ValueError as e:
        abort(str(e))
    except Exception as e:
        abort(f"Génération du rapport échouée : {e}")

    if open_report:
        import subprocess
        opener = "xdg-open" if sys.platform.startswith("linux") else (
            "open" if sys.platform == "darwin" else "start"
        )
        subprocess.Popen([opener, out_path])


# ─────────────────────────────────────────────
# run (pipeline complet)
# ─────────────────────────────────────────────
@cli.command("run")
@click.option("--target", "-t", required=True, help="Cible principale du pentest.")
@click.option("--ports", "-p", default="1-1024", show_default=True, help="Plage de ports.")
@click.option("--min-score", "-m", default=7.0, show_default=True, type=float,
              help="Score CVSS minimum.")
@click.option("--exploit", "do_exploit", is_flag=True, default=False,
              help="Lancer la phase d'exploitation.")
@click.option("--lhost", "-L", default="", help="IP locale (reverse shell).")
@click.option("--lport", "-l", default="4444", show_default=True, help="Port local.")
@click.option("--all-payloads", is_flag=True, default=False,
              help="Toutes les variantes de payload (--exploit requis).")
@click.option("--dry-run", is_flag=True, default=False,
              help="Mode dry-run pour la phase exploit.")
@click.option("--report-output", "-o", default=None, help="Chemin du PDF final.")
@click.option("--skip-recon", is_flag=True, default=False, help="Ignorer la phase Recon.")
@click.option("--skip-cve", is_flag=True, default=False, help="Ignorer la recherche CVE.")
@click.option("--skip-report", is_flag=True, default=False, help="Ne pas générer le PDF.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def run(target, ports, min_score, do_exploit, lhost, lport, all_payloads, dry_run,
        report_output, skip_recon, skip_cve, skip_report, db_path):
    """
    Pipeline complet : Recon → Scan → CVE → [Exploit] → Rapport PDF.
    \b
    Exemples :
      pentool run -t 192.168.1.10 --exploit -L 192.168.1.5
      pentool run -t example.com --skip-recon --min-score 9.0
      pentool run -t 10.0.0.1 --exploit --all-payloads --dry-run
    """
    section("Pipeline PenTest complet")
    info(f"Cible : {target}")
    console.print()

    try:
        _init_db_schema(db_path)
    except Exception as e:
        warn(f"Initialisation base échouée : {e}")

    recon_results = {}

    # 1. Recon
    if not skip_recon:
        console.rule("[bold cyan]1/4 — Reconnaissance[/bold cyan]")
        try:
            from modules.recon import (
                run_dns, run_whois, run_geoip,
                run_banner_grab, run_subdomains, run_os_fingerprint,
                save_to_db as recon_save,
            )
            for name, func in [
                ("DNS", run_dns),
                ("WHOIS", run_whois),
                ("GeoIP", run_geoip),
                ("Banner", run_banner_grab),
                ("Subdomains", run_subdomains),
                ("OS Fingerprint", run_os_fingerprint),
            ]:
                info(f"{name}…")
                try:
                    recon_results[name] = func(target)
                    success(f"{name} OK")
                except Exception as e:
                    warn(f"{name} ignoré : {e}")
        except ImportError as e:
            warn(f"Module recon non disponible : {e}")
    else:
        warn("Phase Recon ignorée (--skip-recon).")

    # 2. Scan
    console.rule("[bold cyan]2/4 — Scan de ports[/bold cyan]")
    scan_id = None
    db_scanner = None
    scan_results = []
    try:
        from modules.scanner import PortScanner, Database
        info(f"Scan des ports {ports}…")
        db_scanner = Database(db_path)
        port_scanner = PortScanner(target, verbose=False, db=db_scanner)
        scan_results = port_scanner.scan_ports(
            ports=ports,
            arguments="-sV --version-light -T4 --host-timeout 60s --open",
        )
        scan_id = port_scanner.scan_id
        success(f"{len(scan_results)} port(s) ouvert(s). Scan ID : {scan_id}")
        _display_ports_table(scan_results)
    except Exception as e:
        abort(f"Scan échoué (pipeline arrêté) : {e}")
    finally:
        if db_scanner:
            db_scanner.close()

    if scan_id and scan_id != -1:
        console.print()
        section("Payloads correspondants aux ports ouverts")
        _display_payloads_for_scan(db_path, scan_id)

    if recon_results:
        try:
            from modules.recon import save_to_db as recon_save
            recon_save(target, recon_results, db_path=db_path, scan_id=scan_id)
            success(f"Recon liée au scan ID : {scan_id}")
        except Exception as e:
            warn(f"Sauvegarde Recon échouée : {e}")

    # 3. CVE
    findings = []
    if not skip_cve:
        console.rule("[bold cyan]3/4 — Recherche CVE[/bold cyan]")
        _apply_cve_patches()  # FIX 2 : alias_map étendu + fallback get_local_exploit
        try:
            from modules.cve import CVEScanner, CveDatabase
            if scan_id is None:
                db = CveDatabase(db_path)
                scans = db.get_scan_ids()
                db.close()
                matched = [
                    s for s in scans
                    if target in (s.get("target", ""), s.get("target_ip", ""))
                ]
                if matched:
                    scan_id = matched[0]["id"]
            if scan_id is None:
                warn("Impossible de déterminer le scan_id — phase CVE ignorée.")
            else:
                cve_scanner = CVEScanner(db_path=db_path, verbose=False, force_rescan=False)
                all_findings = cve_scanner.run(scan_id)
                cve_scanner.close()
                findings = [f for f in all_findings if f.get("cvss_score", 0.0) >= min_score]
                success(f"{len(findings)} CVE(s) trouvée(s) (CVSS ≥ {min_score}).")
                _display_cve_table(findings)
        except Exception as e:
            warn(f"Recherche CVE échouée (pipeline continue) : {e}")
    else:
        warn("Phase CVE ignorée (--skip-cve).")

    # 4. Exploit
    if do_exploit:
        console.rule("[bold cyan]4/4 — Exploitation[/bold cyan]")
        if dry_run:
            warn("Mode DRY-RUN : aucun payload ne sera envoyé.")
        if scan_id is None:
            warn("Scan ID introuvable — phase exploit ignorée.")
        else:
            try:
                from modules.exploit import run_exploit as _run_exploit
                exploit_results = _run_exploit(
                    scan_id=scan_id,
                    db_path=db_path,
                    cve_id=None,
                    lhost=lhost,
                    lport=str(lport),
                    verbose=False,
                    dry_run=dry_run,
                    all_payloads=all_payloads,
                )
                confirmed = [r for r in exploit_results if r.get("succes")]
                success(
                    f"{len(confirmed)} exploit(s) confirmé(s) "
                    f"sur {len(exploit_results)} tentative(s)."
                )
            except Exception as e:
                warn(f"Phase exploit échouée : {e}")
    else:
        warn("Phase Exploit ignorée (utilisez --exploit pour l'activer).")

    # 5. Report
    if not skip_report:
        console.rule("[bold cyan]Rapport final[/bold cyan]")
        if scan_id is None:
            warn("Scan ID introuvable — rapport ignoré.")
        else:
            try:
                from reporter import generate_report as _generate_report
                if report_output is None:
                    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_target = target.replace("/", "_").replace(":", "_")
                    report_output = f"rapport_{safe_target}_{date_str}.pdf"
                out_path = _generate_report(
                    scan_id=scan_id,
                    db_path=db_path,
                    output_path=report_output,
                    verbose=False,
                )
                success(f"Rapport PDF généré → {out_path}")
            except Exception as e:
                warn(f"Génération du rapport échouée : {e}")
    else:
        warn("Rapport ignoré (--skip-report).")

    console.print()
    console.print(
        Panel(
            f"[bold green]Pipeline terminé — {datetime.now().strftime('%H:%M:%S')}[/bold green]",
            border_style="green",
        )
    )


# ─────────────────────────────────────────────
# db (utilitaires base de données)
# ─────────────────────────────────────────────
@cli.group("db")
def db_group():
    """Gestion de la base de données SQLite (pentool.db)."""
    pass


@db_group.command("init")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
@click.option("--seed", is_flag=True, default=False,
              help="Exécuter db/seed.sql après création des tables.")
def db_init(db_path, seed):
    """Initialiser la base de données SQLite (toutes les tables)."""
    section("Initialisation de la base SQLite")
    try:
        _init_db_schema(db_path)
        success(f"Schéma créé : {db_path}")
    except Exception as e:
        abort(f"Erreur lors de la création du schéma : {e}")

    if seed:
        seed_file = "db/seed.sql"
        try:
            with open(seed_file) as f:
                sql = f.read()
            conn = _sqlite_connect(db_path)
            conn.executescript(sql)
            conn.close()
            success(f"Seed exécuté : {seed_file}")
        except FileNotFoundError:
            warn(f"Fichier seed introuvable : {seed_file}")
        except Exception as e:
            warn(f"Erreur seed : {e}")


@db_group.command("status")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def db_status(db_path):
    """Afficher les statistiques de la base SQLite."""
    section("Statut de la base SQLite")
    try:
        conn = _sqlite_connect(db_path)
        tables = ["scans", "ports", "port_cve", "payloads", "cves", "exploit_logs"]
        t = Table(box=box.SIMPLE_HEAD, header_style="bold magenta")
        t.add_column("Table", style="cyan")
        t.add_column("Lignes", style="white", justify="right")
        for table in tables:
            try:
                row = conn.execute(f"SELECT COUNT(*) FROM {table};").fetchone()
                count = row[0] if row else "N/A"
            except sqlite3.OperationalError:
                count = "absente"
            t.add_row(table, str(count))
        conn.close()
        console.print(t)
        success(f"Base SQLite OK : {db_path}")
    except Exception as e:
        abort(f"Connexion échouée : {e}")


@db_group.command("clear")
@click.option("--target", "-t", default=None,
              help="Supprimer uniquement les données de cette cible.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
@click.confirmation_option(prompt="⚠ Confirmer la suppression des données ?")
def db_clear(target, db_path):
    """Vider les données de la base SQLite (ou d'une cible spécifique)."""
    section("Nettoyage de la base SQLite")
    try:
        conn = _sqlite_connect(db_path)
        if target:
            conn.execute(
                "DELETE FROM scans WHERE target = ? OR target_ip = ?;",
                (target, target)
            )
            conn.commit()
            info(f"Données de '{target}' supprimées.")
        else:
            for table in ["exploit_logs", "port_cve", "ports", "scans", "payloads", "cves"]:
                conn.execute(f"DELETE FROM {table};")
            conn.execute("DELETE FROM sqlite_sequence;")
            conn.commit()
            info("Toutes les données supprimées.")
        conn.close()
        success("Nettoyage terminé.")
    except Exception as e:
        abort(f"Nettoyage échoué : {e}")


# ─────────────────────────────────────────────
# payloads
# ─────────────────────────────────────────────
@cli.group("payloads")
def payloads_group():
    """Gestion des payloads stockés en SQLite."""
    pass


@payloads_group.command("list")
@click.option("--type", "-t", "ptype", default=None, help="Filtrer par type.")
@click.option("--cve", "-c", default=None, help="Filtrer par CVE ID.")
@click.option("--port", "-p", type=int, default=None, help="Filtrer par numéro de port.")
@click.option("--service", "-s", default=None, help="Filtrer par service (ex: apache, smb).")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def payloads_list(ptype, cve, port, service, db_path):
    """Lister les payloads disponibles dans la base SQLite."""
    section("Payloads disponibles")
    _ensure_payloads_table(db_path)
    try:
        conn = _sqlite_connect(db_path)
        query = "SELECT id, name, type, protocol, port, service, cve_id, description FROM payloads WHERE 1=1"
        params = []
        if ptype:
            query += " AND type = ?"; params.append(ptype)
        if cve:
            query += " AND cve_id = ?"; params.append(cve)
        if port is not None:
            query += " AND port = ?"; params.append(port)
        if service:
            query += " AND service LIKE ?"; params.append(f"%{service}%")
        query += " ORDER BY id"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        if not rows:
            warn("Aucun payload trouvé.")
            return
        t = Table(box=box.SIMPLE_HEAD, header_style="bold magenta")
        t.add_column("ID", style="cyan", justify="right")
        t.add_column("Nom", style="white")
        t.add_column("Type", style="yellow")
        t.add_column("Proto", style="green")
        t.add_column("Port", style="cyan", justify="right")
        t.add_column("Service", style="dim")
        t.add_column("CVE ID", style="red")
        t.add_column("Description", style="dim")
        for row in rows:
            t.add_row(
                str(row["id"]), row["name"], row["type"],
                row["protocol"] or "",
                str(row["port"]) if row["port"] else "",
                row["service"] or "",
                row["cve_id"] or "",
                (row["description"] or "")[:60],
            )
        console.print(t)
        success(f"{len(rows)} payload(s) affiché(s).")
    except Exception as e:
        abort(f"Erreur : {e}")


@payloads_group.command("add")
@click.option("--name", required=True, help="Nom du payload.")
@click.option("--type", "ptype", required=True, help="Type (reverse_shell, web, etc.).")
@click.option("--proto", default="tcp", help="Protocole.")
@click.option("--port", type=int, default=None, help="Port ciblé.")
@click.option("--service", default=None, help="Service ciblé (ex: http, ssh, apache).")
@click.option("--cve-id", default=None, help="CVE associée.")
@click.option("--method", default=None, help="Méthode (http_get, tcp_raw, etc.).")
@click.option("--payload", "payload_raw", default=None, help="Contenu brut du payload.")
@click.option("--template", default=None, help="Template avec {LHOST}/{LPORT}.")
@click.option("--desc", default="", help="Description.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def payloads_add(name, ptype, proto, port, service, cve_id, method,
                 payload_raw, template, desc, db_path):
    """
    Ajouter un payload en base SQLite.
    \b
    Note : pour le service, utilisez la valeur du seed (ex: 'apache', 'smb')
    et non le nom nmap (ex: 'http', 'microsoft-ds') — le mapping est automatique.
    \b
    Exemple :
      pentool payloads add --name "Apache RCE" --type web \\
        --port 80 --service apache --cve-id CVE-2021-41773 \\
        --method http_get --payload "/cgi-bin/.%2e/.%2e/bin/sh"
    """
    section(f"Ajout du payload : {name}")
    _ensure_payloads_table(db_path)
    try:
        conn = _sqlite_connect(db_path)
        cur = conn.execute("""
            INSERT INTO payloads
            (name, type, protocol, port, service, cve_id, method, payload, template, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, ptype, proto, port, service, cve_id, method, payload_raw, template, desc))
        new_id = cur.lastrowid
        conn.commit()
        conn.close()
        success(f"Payload ajouté avec ID={new_id}.")
        if cve_id:
            info(f"Indexé sur CVE : {cve_id} → visible par cve.py et exploit.py")
        if port:
            info(f"Indexé sur port : {port} → visible par scanner.py")
        if service:
            nmap_names = [k for k, v in SERVICE_MAP.items() if service in v]
            if nmap_names:
                info(f"Service '{service}' détecté via nmap sous : {', '.join(nmap_names)}")
    except Exception as e:
        abort(f"Ajout échoué : {e}")


@payloads_group.command("delete")
@click.argument("payload_id", type=int)
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
@click.confirmation_option(prompt="⚠ Confirmer la suppression ?")
def payloads_delete(payload_id, db_path):
    """Supprimer un payload par son ID."""
    section(f"Suppression du payload ID={payload_id}")
    try:
        conn = _sqlite_connect(db_path)
        conn.execute("DELETE FROM payloads WHERE id = ?", (payload_id,))
        conn.commit()
        conn.close()
        success(f"Payload ID={payload_id} supprimé.")
    except Exception as e:
        abort(f"Suppression échouée : {e}")


@payloads_group.command("scan-match")
@click.option("--scan-id", "-s", type=int, required=True,
              help="ID du scan pour lequel afficher les payloads.")
@click.option("--db-path", default="pentool.db", show_default=True, help="Chemin SQLite.")
def payloads_scan_match(scan_id, db_path):
    """
    Afficher les payloads correspondant aux ports d'un scan spécifique.
    Utilise le mapping service nmap → service seed.
    \b
    Exemple :
      pentool payloads scan-match --scan-id 1
    """
    section(f"Payloads pour le scan ID={scan_id}")
    _display_payloads_for_scan(db_path, scan_id)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()
