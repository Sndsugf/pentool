#!/usr/bin/env python3
"""
reporter.py — Générateur de rapport PDF pour PenTool
=====================================================
Synthétise l'ensemble des données collectées en base (pentool.db) :
  - Informations du scan (cible, IP, durée, statut)
  - Ports ouverts et services détectés
  - CVEs trouvées avec scores CVSS et sévérité
  - Tentatives d'exploitation et résultats
  - Preuves : flags, réponses, fichiers capturés

Usage :
  python reporter.py --scan-id 1
  python reporter.py --scan-id 1 --output rapport_pentest.pdf
  python reporter.py --list-scans
  python reporter.py --scan-id 1 --verbose
"""

import sqlite3
import argparse
import sys
import os
from datetime import datetime
from typing import List, Dict, Optional

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
except ImportError:
    print("[!] Installez reportlab : pip install reportlab")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DB_PATH = os.getenv("DB_PATH", "pentool.db")

# ══════════════════════════════════════════════════════════════════
# PALETTE DE COULEURS
# ══════════════════════════════════════════════════════════════════

C_BG_HEADER   = colors.HexColor("#0d1117")   # Noir quasi-total (header)
C_ACCENT      = colors.HexColor("#58a6ff")   # Bleu GitHub-like
C_CRITICAL    = colors.HexColor("#da3633")   # Rouge critique
C_HIGH        = colors.HexColor("#e85c0d")   # Orange élevé
C_MEDIUM      = colors.HexColor("#d29922")   # Jaune moyen
C_LOW         = colors.HexColor("#3fb950")   # Vert bas
C_INFO        = colors.HexColor("#58a6ff")   # Bleu info
C_SUCCESS     = colors.HexColor("#3fb950")   # Vert succès
C_FAIL        = colors.HexColor("#da3633")   # Rouge échec
C_TABLE_HEAD  = colors.HexColor("#161b22")   # Fond en-tête tableau
C_TABLE_ALT   = colors.HexColor("#0d1117")   # Ligne alternée
C_TABLE_EVEN  = colors.HexColor("#13191f")
C_WHITE       = colors.white
C_LIGHT_GRAY  = colors.HexColor("#c9d1d9")
C_DARK_GRAY   = colors.HexColor("#8b949e")
C_BORDER      = colors.HexColor("#30363d")
C_SECTION_BG  = colors.HexColor("#161b22")

SEVERITY_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "NONE":     C_DARK_GRAY,
    "UNKNOWN":  C_DARK_GRAY,
}

# ══════════════════════════════════════════════════════════════════
# BASE DE DONNÉES — LECTURE SEULE
# ══════════════════════════════════════════════════════════════════

class ReportDatabase:
    """Lit toutes les données nécessaires depuis pentool.db."""

    def __init__(self, db_path: str = DB_PATH):
        if not os.path.exists(db_path):
            raise FileNotFoundError(
                f"[!] Base de données introuvable : {db_path}\n"
                f"    Lancez scanner.py, cve.py et exploit.py avant reporter.py."
            )
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    def list_scans(self) -> List[Dict]:
        cursor = self.conn.execute("""
            SELECT id, target, target_ip, start_time, end_time,
                   duration, status, total_ports_scanned, open_ports_count
            FROM scans ORDER BY id DESC
        """)
        return [dict(r) for r in cursor.fetchall()]

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        cursor = self.conn.execute("""
            SELECT id, target, target_ip, start_time, end_time,
                   duration, status, total_ports_scanned, open_ports_count
            FROM scans WHERE id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_ports(self, scan_id: int) -> List[Dict]:
        cursor = self.conn.execute("""
            SELECT port_number, protocol, state, service_name,
                   service_version, banner
            FROM ports
            WHERE scan_id = ? AND state = 'open'
            ORDER BY port_number
        """, (scan_id,))
        return [dict(r) for r in cursor.fetchall()]

    def get_recon(self, scan_id: int) -> List[Dict]:
        scan = self.get_scan(scan_id)
        if not scan:
            return []

        target = scan.get("target")
        target_ip = scan.get("target_ip")

        try:
            cursor = self.conn.execute("""
                SELECT id, domain, ip, country, city, isp, source
                FROM recon
                WHERE scan_id = ?
                ORDER BY id ASC
            """, (scan_id,))
            rows = [dict(r) for r in cursor.fetchall()]

            if not rows:
                # Fallback for older rows that were saved without scan_id.
                cursor = self.conn.execute("""
                    SELECT id, domain, ip, country, city, isp, source
                    FROM recon
                    WHERE domain = ?
                       OR ip = ?
                       OR domain = ?
                       OR ip = ?
                    ORDER BY id ASC
                """, (target, target, target_ip, target_ip))
                rows = [dict(r) for r in cursor.fetchall()]

            seen = set()
            unique_rows = []
            for row in rows:
                key = (row.get("domain"), row.get("ip"), row.get("source"))
                if key in seen:
                    continue
                seen.add(key)
                unique_rows.append(row)
            return unique_rows
        except sqlite3.OperationalError:
            try:
                cursor = self.conn.execute("""
                    SELECT id, domain, ip, country, city, isp, source
                    FROM recon
                    WHERE domain = ?
                       OR ip = ?
                       OR domain = ?
                       OR ip = ?
                    ORDER BY id ASC
                """, (target, target, target_ip, target_ip))
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.OperationalError:
                return []

    def get_subdomains(self, scan_id: int) -> List[Dict]:
        scan = self.get_scan(scan_id)
        if not scan:
            return []

        target = scan.get("target")
        try:
            cursor = self.conn.execute("""
                SELECT id, root_domain, subdomain, ip
                FROM subdomain_results
                WHERE scan_id = ?
                ORDER BY subdomain ASC
            """, (scan_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            if rows:
                return rows

            # Fallback for older rows that were saved without scan_id.
            cursor = self.conn.execute("""
                SELECT id, root_domain, subdomain, ip
                FROM subdomain_results
                WHERE root_domain = ?
                ORDER BY subdomain ASC
            """, (target,))
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.OperationalError:
            try:
                cursor = self.conn.execute("""
                    SELECT id, root_domain, subdomain, ip
                    FROM subdomain_results
                    WHERE root_domain = ?
                    ORDER BY subdomain ASC
                """, (target,))
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.OperationalError:
                return []

    def get_os_fingerprints(self, scan_id: int) -> List[Dict]:
        scan = self.get_scan(scan_id)
        if not scan:
            return []

        target = scan.get("target")
        target_ip = scan.get("target_ip")
        try:
            cursor = self.conn.execute("""
                SELECT id, domain, ip, os_name, accuracy, line, osclass_json, source
                FROM os_fingerprint_results
                WHERE scan_id = ?
                ORDER BY id ASC
            """, (scan_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            if rows:
                return rows

            # Fallback for older rows that were saved without scan_id.
            cursor = self.conn.execute("""
                SELECT id, domain, ip, os_name, accuracy, line, osclass_json, source
                FROM os_fingerprint_results
                WHERE domain = ?
                   OR ip = ?
                   OR domain = ?
                   OR ip = ?
                ORDER BY id ASC
            """, (target, target, target_ip, target_ip))
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.OperationalError:
            try:
                cursor = self.conn.execute("""
                    SELECT id, domain, ip, os_name, accuracy, line, osclass_json, source
                    FROM os_fingerprint_results
                    WHERE domain = ?
                       OR ip = ?
                       OR domain = ?
                       OR ip = ?
                    ORDER BY id ASC
                """, (target, target, target_ip, target_ip))
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.OperationalError:
                return []

    def get_cves(self, scan_id: int) -> List[Dict]:
        """CVEs depuis port_cve, jointure avec ports pour avoir le numéro de port."""
        try:
            cursor = self.conn.execute("""
                SELECT
                    pc.cve_id,
                    pc.cvss_score,
                    pc.cvss_version,
                    pc.severity,
                    pc.description,
                    pc.published_date,
                    pc.exploit_available,
                    pc.exploit_name,
                    pc.exploit_payload,
                    pc.exploit_method,
                    p.port_number,
                    p.service_name,
                    p.protocol
                FROM port_cve pc
                JOIN ports p ON p.id = pc.port_id
                WHERE pc.scan_id = ?
                ORDER BY pc.cvss_score DESC
            """, (scan_id,))
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.OperationalError:
            return []  # table port_cve absente si cve.py jamais lancé

    def get_exploits(self, scan_id: int) -> List[Dict]:
        """Logs d'exploitation depuis exploit_logs."""
        try:
            cursor = self.conn.execute("""
                SELECT
                    cve_id, payload_name, payload_used, method,
                    target_ip, port, requete_envoyee, reponse_recue,
                    code_retour, succes, duree_ms, date_tentative
                FROM exploit_logs
                WHERE scan_id = ?
                ORDER BY date_tentative ASC
            """, (scan_id,))
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.OperationalError:
            return []  # table exploit_logs absente si exploit.py jamais lancé

    def close(self):
        self.conn.close()


# ══════════════════════════════════════════════════════════════════
# STYLES REPORTLAB
# ══════════════════════════════════════════════════════════════════

def build_styles():
    base = getSampleStyleSheet()

    styles = {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontSize=32, leading=40,
            textColor=C_WHITE,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            spaceAfter=8,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontSize=13, leading=18,
            textColor=C_ACCENT,
            alignment=TA_CENTER,
            fontName="Helvetica",
            spaceAfter=4,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta",
            fontSize=10, leading=14,
            textColor=C_DARK_GRAY,
            alignment=TA_CENTER,
            fontName="Helvetica",
        ),
        "section_title": ParagraphStyle(
            "section_title",
            fontSize=16, leading=20,
            textColor=C_ACCENT,
            fontName="Helvetica-Bold",
            spaceBefore=18, spaceAfter=6,
        ),
        "subsection_title": ParagraphStyle(
            "subsection_title",
            fontSize=12, leading=16,
            textColor=C_WHITE,
            fontName="Helvetica-Bold",
            spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=9, leading=14,
            textColor=C_LIGHT_GRAY,
            fontName="Helvetica",
            spaceAfter=4,
        ),
        "body_small": ParagraphStyle(
            "body_small",
            fontSize=8, leading=12,
            textColor=C_DARK_GRAY,
            fontName="Helvetica",
        ),
        "code": ParagraphStyle(
            "code",
            fontSize=8, leading=12,
            textColor=C_SUCCESS,
            fontName="Courier",
            backColor=colors.HexColor("#0d1117"),
            borderPadding=(4, 6, 4, 6),
            spaceAfter=4,
        ),
        "code_fail": ParagraphStyle(
            "code_fail",
            fontSize=8, leading=12,
            textColor=C_FAIL,
            fontName="Courier",
            backColor=colors.HexColor("#0d1117"),
            borderPadding=(4, 6, 4, 6),
        ),
        "badge_critical": ParagraphStyle(
            "badge_critical",
            fontSize=8, leading=10,
            textColor=C_WHITE,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "toc_entry": ParagraphStyle(
            "toc_entry",
            fontSize=10, leading=16,
            textColor=C_LIGHT_GRAY,
            fontName="Helvetica",
            leftIndent=10,
        ),
    }
    return styles


# ══════════════════════════════════════════════════════════════════
# HELPERS UI
# ══════════════════════════════════════════════════════════════════

def severity_badge_text(severity: str) -> str:
    icons = {
        "CRITICAL": "● CRITICAL",
        "HIGH":     "● HIGH",
        "MEDIUM":   "● MEDIUM",
        "LOW":      "● LOW",
        "NONE":     "● NONE",
        "UNKNOWN":  "● UNKNOWN",
    }
    return icons.get((severity or "UNKNOWN").upper(), "● UNKNOWN")

def severity_color(severity: str) -> colors.Color:
    return SEVERITY_COLORS.get((severity or "UNKNOWN").upper(), C_DARK_GRAY)

def score_bar_text(score: float) -> str:
    """Barre de progression textuelle pour le score CVSS."""
    filled = int((score / 10.0) * 10)
    return "█" * filled + "░" * (10 - filled)

def trunc(text: str, n: int) -> str:
    if not text:
        return ""
    return text[:n] + ("…" if len(text) > n else "")

def fmt_date(dt_str: str) -> str:
    if not dt_str:
        return "—"
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", ""))
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return dt_str[:16] if dt_str else "—"

def dark_table_style(col_widths, header_rows=1) -> TableStyle:
    """Style de base pour tous les tableaux du rapport."""
    commands = [
        # En-tête
        ("BACKGROUND",   (0, 0), (-1, header_rows - 1), C_TABLE_HEAD),
        ("TEXTCOLOR",    (0, 0), (-1, header_rows - 1), C_ACCENT),
        ("FONTNAME",     (0, 0), (-1, header_rows - 1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, header_rows - 1), 8),
        ("ALIGN",        (0, 0), (-1, header_rows - 1), "LEFT"),
        ("BOTTOMPADDING",(0, 0), (-1, header_rows - 1), 6),
        ("TOPPADDING",   (0, 0), (-1, header_rows - 1), 6),
        # Corps
        ("BACKGROUND",   (0, header_rows), (-1, -1), C_TABLE_ALT),
        ("TEXTCOLOR",    (0, header_rows), (-1, -1), C_LIGHT_GRAY),
        ("FONTNAME",     (0, header_rows), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, header_rows), (-1, -1), 8),
        ("ALIGN",        (0, header_rows), (-1, -1), "LEFT"),
        ("TOPPADDING",   (0, header_rows), (-1, -1), 4),
        ("BOTTOMPADDING",(0, header_rows), (-1, -1), 4),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        # Bordures
        ("GRID",         (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, header_rows), (-1, -1), [C_TABLE_EVEN, C_TABLE_ALT]),
    ]
    return TableStyle(commands)


# ══════════════════════════════════════════════════════════════════
# PAGE DE COUVERTURE
# ══════════════════════════════════════════════════════════════════

def build_cover(story, scan: Dict, stats: Dict, styles: Dict):
    W, H = A4

    # Bande noire en haut
    story.append(Spacer(1, 2 * cm))

    # Titre principal
    story.append(Paragraph("RAPPORT DE PENTEST", styles["cover_title"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="80%", thickness=1, color=C_ACCENT, spaceAfter=12))

    # Infos cible
    target_display = scan.get("target") or "Cible inconnue"
    ip_display     = scan.get("target_ip") or "IP non résolue"
    story.append(Paragraph(f"Cible : {target_display}  ({ip_display})", styles["cover_sub"]))
    story.append(Spacer(1, 0.5 * cm))

    # Métadonnées
    story.append(Paragraph(f"Scan ID : #{scan.get('id', '?')}", styles["cover_meta"]))
    story.append(Paragraph(f"Date de début : {fmt_date(scan.get('start_time'))}", styles["cover_meta"]))
    story.append(Paragraph(f"Durée : {scan.get('duration', 0) or 0:.1f} secondes", styles["cover_meta"]))
    story.append(Paragraph(f"Statut : {(scan.get('status') or 'inconnu').upper()}", styles["cover_meta"]))
    story.append(Spacer(1, 1 * cm))

    # Tableau de synthèse
    story.append(HRFlowable(width="60%", thickness=0.5, color=C_BORDER, spaceAfter=12))

    summary_data = [
        ["Indicateur", "Valeur"],
        ["Ports scannés",         str(scan.get("total_ports_scanned") or 0)],
        ["Ports ouverts",         str(scan.get("open_ports_count") or 0)],
        ["CVEs identifiées",      str(stats.get("total_cves", 0))],
        ["CVEs critiques/élevées",str(stats.get("critical_high", 0))],
        ["Exploits disponibles",  str(stats.get("exploits_available", 0))],
        ["Tentatives d'exploit",  str(stats.get("exploit_attempts", 0))],
        ["Exploits réussis",      str(stats.get("exploit_success", 0))],
    ]
    col_w = [8 * cm, 4 * cm]
    t = Table(summary_data, colWidths=col_w)
    ts = dark_table_style(col_w)
    # Coloriser la ligne des succès
    for i, row in enumerate(summary_data[1:], start=1):
        if "réussis" in row[0] and int(row[1]) > 0:
            ts.add("TEXTCOLOR", (1, i), (1, i), C_CRITICAL)
            ts.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")
        elif "ouverts" in row[0]:
            ts.add("TEXTCOLOR", (1, i), (1, i), C_MEDIUM)
    t.setStyle(ts)
    story.append(t)

    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="60%", thickness=0.5, color=C_BORDER, spaceAfter=6))
    story.append(Paragraph(
        f"Rapport généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} par PenTool / reporter.py",
        styles["cover_meta"]
    ))
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════
# TABLE DES MATIÈRES
# ══════════════════════════════════════════════════════════════════

def build_toc(story, stats: Dict, styles: Dict):
    story.append(Paragraph("TABLE DES MATIÈRES", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=10))

    sections = [
        ("1.", "Informations du scan"),
        ("2.", "Reconnaissance"),
        ("3.", "Ports ouverts et services"),
        ("4.", "Vulnérabilités (CVEs)"),
        ("5.", "Tentatives d'exploitation"),
        ("6.", "Preuves et artefacts"),
        ("7.", "Synthèse et recommandations"),
    ]
    for num, title in sections:
        story.append(Paragraph(f"  {num}  {title}", styles["toc_entry"]))
        story.append(Spacer(1, 2))

    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════
# SECTION 2 : RECONNAISSANCE
# ══════════════════════════════════════════════════════════════════

def build_section_recon(story, recon_rows: List[Dict], subdomains: List[Dict],
                        os_fingerprints: List[Dict], styles: Dict):
    story.append(Paragraph("2. Reconnaissance", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

    if not recon_rows and not subdomains and not os_fingerprints:
        story.append(Paragraph(
            "Aucun résultat de reconnaissance enregistré — lancez recon.py ou la commande recon du CLI.",
            styles["body"]
        ))
        story.append(Spacer(1, 0.5 * cm))
        return

    # Résumé rapide
    recon_count = len(recon_rows)
    subdomain_count = len(subdomains)
    os_count = len(os_fingerprints)
    story.append(Paragraph(
        f"Résumé : <b>{recon_count}</b> entrée(s) de reconnaissance, "
        f"<b>{subdomain_count}</b> sous-domaine(s), "
        f"<b>{os_count}</b> empreinte(s) OS.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.35 * cm))

    if recon_rows:
        story.append(Paragraph("Résultats de reconnaissance", styles["subsection_title"]))
        header = ["Source", "Domaine", "IP", "Pays", "Ville", "ISP"]
        col_w = [3.0*cm, 4.0*cm, 3.0*cm, 2.5*cm, 2.5*cm, 3.0*cm]
        rows = [header]
        for r in recon_rows:
            rows.append([
                r.get("source") or "—",
                trunc(r.get("domain") or "—", 28),
                r.get("ip") or "—",
                r.get("country") or "—",
                r.get("city") or "—",
                trunc(r.get("isp") or "—", 22),
            ])
        t = Table(rows, colWidths=col_w, repeatRows=1)
        t.setStyle(dark_table_style(col_w))
        story.append(t)
        story.append(Spacer(1, 0.35 * cm))

    if subdomains:
        story.append(Paragraph("Sous-domaines", styles["subsection_title"]))
        header = ["Sous-domaine", "IP"]
        col_w = [10.5*cm, 6.0*cm]
        rows = [header]
        for s in subdomains:
            rows.append([
                trunc(s.get("subdomain") or "—", 52),
                s.get("ip") or "—",
            ])
        t = Table(rows, colWidths=col_w, repeatRows=1)
        t.setStyle(dark_table_style(col_w))
        story.append(t)
        story.append(Spacer(1, 0.35 * cm))

    if os_fingerprints:
        story.append(Paragraph("Empreintes OS", styles["subsection_title"]))
        header = ["OS", "Accuracy", "Line", "IP", "Source"]
        col_w = [5.0*cm, 2.2*cm, 1.2*cm, 3.0*cm, 4.5*cm]
        rows = [header]
        for fp in os_fingerprints:
            rows.append([
                trunc(fp.get("os_name") or "—", 34),
                fp.get("accuracy") or "—",
                fp.get("line") or "—",
                fp.get("ip") or "—",
                fp.get("source") or "—",
            ])
        t = Table(rows, colWidths=col_w, repeatRows=1)
        t.setStyle(dark_table_style(col_w))
        story.append(t)
        story.append(Spacer(1, 0.35 * cm))


# ══════════════════════════════════════════════════════════════════
# SECTION 1 : INFORMATIONS DU SCAN
# ══════════════════════════════════════════════════════════════════

def build_section_scan_info(story, scan: Dict, styles: Dict):
    story.append(Paragraph("1. Informations du scan", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

    data = [
        ["Champ", "Valeur"],
        ["ID du scan",          str(scan.get("id", "?"))],
        ["Cible",               scan.get("target") or "—"],
        ["IP résolue",          scan.get("target_ip") or "—"],
        ["Date de début",       fmt_date(scan.get("start_time"))],
        ["Date de fin",         fmt_date(scan.get("end_time"))],
        ["Durée",               f"{scan.get('duration') or 0:.2f} s"],
        ["Statut",              (scan.get("status") or "—").upper()],
        ["Ports scannés",       str(scan.get("total_ports_scanned") or 0)],
        ["Ports ouverts",       str(scan.get("open_ports_count") or 0)],
    ]
    col_w = [6 * cm, 11 * cm]
    t = Table(data, colWidths=col_w)
    ts = dark_table_style(col_w)
    if scan.get("status") == "completed":
        ts.add("TEXTCOLOR", (1, 7), (1, 7), C_SUCCESS)
    elif scan.get("status") == "failed":
        ts.add("TEXTCOLOR", (1, 7), (1, 7), C_FAIL)
    t.setStyle(ts)
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))


# ══════════════════════════════════════════════════════════════════
# SECTION 3 : PORTS OUVERTS
# ══════════════════════════════════════════════════════════════════

def build_section_ports(story, ports: List[Dict], styles: Dict):
    story.append(Paragraph("3. Ports ouverts et services", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

    if not ports:
        story.append(Paragraph("Aucun port ouvert détecté.", styles["body"]))
        story.append(Spacer(1, 0.5 * cm))
        return

    story.append(Paragraph(
        f"{len(ports)} port(s) ouvert(s) identifié(s).", styles["body"]
    ))
    story.append(Spacer(1, 0.3 * cm))

    header = ["Port", "Proto", "Service", "Version", "Banner"]
    col_w  = [1.8*cm, 1.4*cm, 3.2*cm, 4.5*cm, 6.1*cm]

    rows = [header]
    for p in ports:
        banner = trunc(p.get("banner") or "", 60)
        rows.append([
            str(p.get("port_number", "?")),
            (p.get("protocol") or "tcp").upper(),
            p.get("service_name") or "—",
            trunc(p.get("service_version") or "—", 40),
            banner or "—",
        ])

    t = Table(rows, colWidths=col_w, repeatRows=1)
    ts = dark_table_style(col_w)
    # Colorer le numéro de port
    for i in range(1, len(rows)):
        ts.add("TEXTCOLOR", (0, i), (0, i), C_ACCENT)
        ts.add("FONTNAME",  (0, i), (0, i), "Helvetica-Bold")
    t.setStyle(ts)
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))


# ══════════════════════════════════════════════════════════════════
# SECTION 4 : CVEs
# ══════════════════════════════════════════════════════════════════

def build_section_cves(story, cves: List[Dict], styles: Dict):
    story.append(Paragraph("4. Vulnérabilités (CVEs)", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

    if not cves:
        story.append(Paragraph(
            "Aucune CVE identifiée — cve.py n'a peut-être pas encore été lancé.",
            styles["body"]
        ))
        story.append(Spacer(1, 0.5 * cm))
        return

    # Compteurs par sévérité
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    exploitable = 0
    for c in cves:
        sev = (c.get("severity") or "UNKNOWN").upper()
        counts[sev if sev in counts else "UNKNOWN"] += 1
        if c.get("exploit_available"):
            exploitable += 1

    story.append(Paragraph(
        f"Total : <b>{len(cves)}</b> CVE(s) — "
        f"Critiques : <b>{counts['CRITICAL']}</b>  "
        f"Élevées : <b>{counts['HIGH']}</b>  "
        f"Moyennes : <b>{counts['MEDIUM']}</b>  "
        f"Basses : <b>{counts['LOW']}</b>  "
        f"Avec exploit local : <b>{exploitable}</b>",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4 * cm))

    # Tableau récapitulatif
    header = ["CVE ID", "Port", "Sévérité", "CVSS", "Exploit", "Description"]
    col_w  = [3.2*cm, 1.4*cm, 2.0*cm, 1.4*cm, 2.0*cm, 7.0*cm]

    rows = [header]
    for c in cves:
        sev    = (c.get("severity") or "UNKNOWN").upper()
        score  = c.get("cvss_score") or 0.0
        has_ex = bool(c.get("exploit_available"))
        ex_txt = c.get("exploit_name") or "—"
        rows.append([
            c.get("cve_id") or "—",
            str(c.get("port_number") or "?"),
            sev,
            f"{score:.1f}",
            trunc(ex_txt, 22) if has_ex else "—",
            trunc(c.get("description") or "—", 80),
        ])

    t = Table(rows, colWidths=col_w, repeatRows=1)
    ts = dark_table_style(col_w)

    # Colorisation par sévérité
    for i, row in enumerate(rows[1:], start=1):
        sev = row[2]
        col = severity_color(sev)
        ts.add("TEXTCOLOR",  (0, i), (0, i), C_ACCENT)          # CVE ID
        ts.add("FONTNAME",   (0, i), (0, i), "Helvetica-Bold")
        ts.add("TEXTCOLOR",  (2, i), (2, i), col)                # Sévérité
        ts.add("FONTNAME",   (2, i), (2, i), "Helvetica-Bold")
        ts.add("TEXTCOLOR",  (3, i), (3, i), col)                # Score
        ts.add("FONTNAME",   (3, i), (3, i), "Helvetica-Bold")
        if rows[i][4] != "—":
            ts.add("TEXTCOLOR", (4, i), (4, i), C_MEDIUM)
            ts.add("FONTNAME",  (4, i), (4, i), "Helvetica-Bold")

    t.setStyle(ts)
    story.append(t)
    story.append(Spacer(1, 0.6 * cm))

    # Détails pour les CVEs critiques/élevées
    critical_cves = [c for c in cves
                     if (c.get("severity") or "").upper() in ("CRITICAL", "HIGH")]
    if critical_cves:
        story.append(Paragraph("Détail des vulnérabilités critiques et élevées",
                                styles["subsection_title"]))
        for c in critical_cves:
            sev   = (c.get("severity") or "UNKNOWN").upper()
            score = c.get("cvss_score") or 0.0
            col   = severity_color(sev)

            block = []
            block.append(Paragraph(
                f"<b>{c.get('cve_id','—')}</b>  —  Port {c.get('port_number','?')}"
                f" / {c.get('service_name','?')}",
                styles["subsection_title"]
            ))
            block.append(Paragraph(
                f"Sévérité : <b>{sev}</b>  |  CVSS : <b>{score:.1f}</b>"
                f"  |  Version CVSS : {c.get('cvss_version') or '—'}"
                f"  |  Publié le : {fmt_date(c.get('published_date'))}",
                styles["body"]
            ))
            if c.get("description"):
                block.append(Paragraph(c["description"], styles["body"]))
            if c.get("exploit_available"):
                block.append(Paragraph(
                    f"<b>Exploit local disponible :</b> {c.get('exploit_name','—')}  "
                    f"(méthode : {c.get('exploit_method','—')})",
                    styles["body"]
                ))
                if c.get("exploit_payload"):
                    block.append(Paragraph(
                        f"Payload : {trunc(c.get('exploit_payload',''), 120)}",
                        styles["code"]
                    ))
            block.append(HRFlowable(width="100%", thickness=0.3,
                                     color=C_BORDER, spaceAfter=4))
            story.append(KeepTogether(block))

    story.append(Spacer(1, 0.3 * cm))


# ══════════════════════════════════════════════════════════════════
# SECTION 5 : TENTATIVES D'EXPLOITATION
# ══════════════════════════════════════════════════════════════════

def build_section_exploits(story, exploits: List[Dict], styles: Dict):
    story.append(Paragraph("5. Tentatives d'exploitation", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

    if not exploits:
        story.append(Paragraph(
            "Aucune tentative d'exploitation enregistrée — exploit.py n'a peut-être pas été lancé.",
            styles["body"]
        ))
        story.append(Spacer(1, 0.5 * cm))
        return

    total    = len(exploits)
    success  = sum(1 for e in exploits if e.get("succes"))
    fail     = total - success

    story.append(Paragraph(
        f"Total : <b>{total}</b> tentative(s)  —  "
        f"<font color='#3fb950'><b>Succès : {success}</b></font>  —  "
        f"<font color='#da3633'><b>Échecs : {fail}</b></font>",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4 * cm))

    header = ["CVE", "Port", "Payload", "Méthode", "Code retour", "Résultat", "Date"]
    col_w  = [3.0*cm, 1.2*cm, 3.0*cm, 2.2*cm, 1.8*cm, 2.0*cm, 3.8*cm]

    rows = [header]
    for e in exploits:
        res_txt  = "SUCCÈS" if e.get("succes") else "ÉCHEC"
        rows.append([
            trunc(e.get("cve_id") or "—", 25),
            str(e.get("port") or "?"),
            trunc(e.get("payload_name") or "—", 28),
            e.get("method") or "—",
            trunc(e.get("code_retour") or "—", 16),
            res_txt,
            fmt_date(e.get("date_tentative")),
        ])

    t = Table(rows, colWidths=col_w, repeatRows=1)
    ts = dark_table_style(col_w)
    for i, row in enumerate(rows[1:], start=1):
        if row[5] == "SUCCÈS":
            ts.add("TEXTCOLOR", (5, i), (5, i), C_SUCCESS)
            ts.add("FONTNAME",  (5, i), (5, i), "Helvetica-Bold")
        else:
            ts.add("TEXTCOLOR", (5, i), (5, i), C_FAIL)
    t.setStyle(ts)
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))


# ══════════════════════════════════════════════════════════════════
# SECTION 6 : PREUVES ET ARTEFACTS
# ══════════════════════════════════════════════════════════════════

def build_section_evidence(story, exploits: List[Dict], styles: Dict):
    story.append(Paragraph("6. Preuves et artefacts", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

    successful = [e for e in exploits if e.get("succes")]
    if not successful:
        story.append(Paragraph(
            "Aucune preuve à documenter (pas d'exploit confirmé).",
            styles["body"]
        ))
        story.append(Spacer(1, 0.5 * cm))
        return

    story.append(Paragraph(
        f"{len(successful)} exploit(s) confirmé(s) — détail des réponses capturées :",
        styles["body"]
    ))
    story.append(Spacer(1, 0.3 * cm))

    for idx, e in enumerate(successful, start=1):
        block = []
        block.append(Paragraph(
            f"Preuve #{idx}  —  {e.get('cve_id','—')}  —  "
            f"Port {e.get('port','?')}  —  {fmt_date(e.get('date_tentative'))}",
            styles["subsection_title"]
        ))
        block.append(Paragraph(
            f"Cible : {e.get('target_ip','—')}:{e.get('port','?')}  |  "
            f"Payload : {e.get('payload_name','—')}  |  "
            f"Méthode : {e.get('method','—')}  |  "
            f"Code retour : {e.get('code_retour','—')}  |  "
            f"Durée : {e.get('duree_ms') or 0:.1f} ms",
            styles["body"]
        ))

        if e.get("requete_envoyee"):
            block.append(Paragraph("<b>Requête envoyée :</b>", styles["body"]))
            block.append(Paragraph(
                trunc(e.get("requete_envoyee", ""), 500),
                styles["code"]
            ))

        if e.get("reponse_recue"):
            block.append(Paragraph("<b>Réponse capturée :</b>", styles["body"]))
            resp = e.get("reponse_recue", "")
            # Détecter les flags potentiels (patterns CTF/pentest classiques)
            flag_patterns = ["flag{", "FLAG{", "HTB{", "THM{", "root:", "uid=0", "passwd"]
            found_flags   = [p for p in flag_patterns if p in resp]
            if found_flags:
                block.append(Paragraph(
                    f"[!] INDICATEURS SENSIBLES DÉTECTÉS : {', '.join(found_flags)}",
                    ParagraphStyle("flag_warn", fontSize=9, leading=13,
                                   textColor=C_CRITICAL, fontName="Helvetica-Bold")
                ))
            block.append(Paragraph(trunc(resp, 800), styles["code"]))

        block.append(HRFlowable(width="100%", thickness=0.3, color=C_BORDER, spaceAfter=4))
        story.append(KeepTogether(block))

    story.append(Spacer(1, 0.3 * cm))


# ══════════════════════════════════════════════════════════════════
# SECTION 7 : SYNTHÈSE ET RECOMMANDATIONS
# ══════════════════════════════════════════════════════════════════

def build_section_recommendations(story, scan: Dict, ports: List[Dict],
                                   cves: List[Dict], exploits: List[Dict],
                                   styles: Dict):
    story.append(Paragraph("7. Synthèse et recommandations", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

    critical_cves = [c for c in cves if (c.get("severity") or "").upper() == "CRITICAL"]
    high_cves     = [c for c in cves if (c.get("severity") or "").upper() == "HIGH"]
    success_ex    = [e for e in exploits if e.get("succes")]
    exploitable   = [c for c in cves if c.get("exploit_available")]

    # Niveau de risque global
    if success_ex or critical_cves:
        risk_level = "CRITIQUE"
        risk_color = C_CRITICAL
        risk_msg   = ("Des exploits ont été confirmés et/ou des vulnérabilités critiques "
                      "ont été identifiées. La surface d'attaque est significativement exposée.")
    elif high_cves or exploitable:
        risk_level = "ÉLEVÉ"
        risk_color = C_HIGH
        risk_msg   = ("Des vulnérabilités élevées avec exploit disponible ont été détectées. "
                      "Une remédiation prioritaire est requise.")
    elif cves:
        risk_level = "MODÉRÉ"
        risk_color = C_MEDIUM
        risk_msg   = ("Des vulnérabilités de sévérité modérée ont été détectées. "
                      "Une revue de sécurité est recommandée.")
    else:
        risk_level = "FAIBLE"
        risk_color = C_LOW
        risk_msg   = "Aucune vulnérabilité significative identifiée lors de ce scan."

    story.append(Paragraph(
        f"Niveau de risque global : <b>{risk_level}</b>",
        ParagraphStyle("risk", fontSize=14, leading=18,
                       textColor=risk_color, fontName="Helvetica-Bold", spaceAfter=6)
    ))
    story.append(Paragraph(risk_msg, styles["body"]))
    story.append(Spacer(1, 0.5 * cm))

    # Résumé chiffré
    summary_data = [
        ["Indicateur",                    "Valeur"],
        ["Ports ouverts",                 str(len(ports))],
        ["CVEs identifiées",              str(len(cves))],
        ["Dont critiques",                str(len(critical_cves))],
        ["Dont élevées",                  str(len(high_cves))],
        ["Avec exploit local",            str(len(exploitable))],
        ["Tentatives d'exploitation",     str(len(exploits))],
        ["Exploits confirmés",            str(len(success_ex))],
    ]
    col_w = [9 * cm, 4 * cm]
    t = Table(summary_data, colWidths=col_w)
    ts = dark_table_style(col_w)
    if len(success_ex) > 0:
        ts.add("TEXTCOLOR", (1, 8), (1, 8), C_CRITICAL)
        ts.add("FONTNAME",  (1, 8), (1, 8), "Helvetica-Bold")
    t.setStyle(ts)
    story.append(t)
    story.append(Spacer(1, 0.6 * cm))

    # Recommandations
    story.append(Paragraph("Recommandations prioritaires", styles["subsection_title"]))

    recs = []

    # Ports exposés
    risky_ports = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC",
                   445: "SMB", 3306: "MySQL", 6379: "Redis", 27017: "MongoDB"}
    exposed = [p for p in ports if p.get("port_number") in risky_ports]
    if exposed:
        names = ", ".join(
            f"{p['port_number']} ({risky_ports[p['port_number']]})" for p in exposed
        )
        recs.append(("CRITIQUE",
                      f"Fermer ou restreindre l'accès aux ports sensibles exposés : {names}."))

    if success_ex:
        recs.append(("CRITIQUE",
                      f"{len(success_ex)} exploit(s) confirmé(s) — appliquer immédiatement "
                      f"les correctifs ou isoler la cible du réseau."))

    if critical_cves:
        ids = ", ".join(c["cve_id"] for c in critical_cves[:5])
        recs.append(("CRITIQUE",
                      f"Patcher en priorité les CVEs critiques : {ids}"
                      f"{'…' if len(critical_cves) > 5 else ''}."))

    if high_cves:
        recs.append(("ÉLEVÉ",
                      f"Traiter les {len(high_cves)} CVE(s) de sévérité élevée dans les 30 jours."))

    if exploitable and not success_ex:
        recs.append(("ÉLEVÉ",
                      f"{len(exploitable)} CVE(s) disposent d'un exploit local — "
                      f"tester en environnement contrôlé et patcher."))

    http_ports = [p for p in ports if p.get("service_name") in ("http", "https", "http-alt")]
    if http_ports:
        recs.append(("MOYEN",
                      "Activer HTTPS partout, configurer les en-têtes de sécurité "
                      "(CSP, HSTS, X-Frame-Options)."))

    recs.append(("INFO",
                  "Mettre en place une veille CVE continue (NVD, CERT) pour les services exposés."))
    recs.append(("INFO",
                  "Effectuer des scans réguliers et après chaque déploiement majeur."))

    if not recs:
        recs.append(("INFO", "Aucune recommandation critique identifiée — maintenir la vigilance."))

    priority_color = {"CRITIQUE": C_CRITICAL, "ÉLEVÉ": C_HIGH,
                      "MOYEN": C_MEDIUM, "INFO": C_INFO}

    rec_data = [["Priorité", "Recommandation"]]
    for prio, msg in recs:
        rec_data.append([prio, msg])

    col_w = [2.2 * cm, 14.8 * cm]
    t = Table(rec_data, colWidths=col_w)
    ts = dark_table_style(col_w)
    for i, (prio, _) in enumerate(recs, start=1):
        col = priority_color.get(prio, C_INFO)
        ts.add("TEXTCOLOR", (0, i), (0, i), col)
        ts.add("FONTNAME",  (0, i), (0, i), "Helvetica-Bold")
    t.setStyle(ts)
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))


# ══════════════════════════════════════════════════════════════════
# NUMÉROTATION DES PAGES
# ══════════════════════════════════════════════════════════════════

def _page_number_canvas(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setFillColor(C_DARK_GRAY)
    canvas_obj.setFont("Helvetica", 8)
    page_num = canvas_obj.getPageNumber()
    canvas_obj.drawRightString(A4[0] - 1.5 * cm, 1 * cm,
                               f"Page {page_num}")
    canvas_obj.drawString(1.5 * cm, 1 * cm, "PenTool — Rapport confidentiel")
    canvas_obj.setStrokeColor(C_BORDER)
    canvas_obj.setLineWidth(0.3)
    canvas_obj.line(1.5 * cm, 1.3 * cm, A4[0] - 1.5 * cm, 1.3 * cm)
    canvas_obj.restoreState()


# ══════════════════════════════════════════════════════════════════
# FONCTION PRINCIPALE : GÉNÉRATION DU PDF
# ══════════════════════════════════════════════════════════════════

def generate_report(scan_id: int, db_path: str = DB_PATH,
                    output_path: str = None, verbose: bool = False) -> str:
    """
    Génère le rapport PDF complet pour un scan_id donné.
    Retourne le chemin du fichier créé.
    """
    # ── Chargement des données ──────────────────────────────────
    if verbose:
        print(f"[*] Connexion à la base : {db_path}")

    db   = ReportDatabase(db_path)
    scan = db.get_scan(scan_id)
    if not scan:
        db.close()
        raise ValueError(f"Aucun scan trouvé avec l'ID {scan_id}.")

    ports   = db.get_ports(scan_id)
    cves    = db.get_cves(scan_id)
    exploits= db.get_exploits(scan_id)
    recon   = db.get_recon(scan_id)
    subdomains = db.get_subdomains(scan_id)
    os_fingerprints = db.get_os_fingerprints(scan_id)
    db.close()

    if verbose:
        print(f"[*] Données chargées : {len(recon)} recon, {len(subdomains)} sous-domaines, "
              f"{len(os_fingerprints)} OS, {len(ports)} ports, {len(cves)} CVEs, "
              f"{len(exploits)} logs d'exploit")

    # ── Statistiques globales ────────────────────────────────────
    stats = {
        "total_cves":       len(cves),
        "critical_high":    sum(1 for c in cves
                                if (c.get("severity") or "").upper() in ("CRITICAL", "HIGH")),
        "exploits_available": sum(1 for c in cves if c.get("exploit_available")),
        "exploit_attempts": len(exploits),
        "exploit_success":  sum(1 for e in exploits if e.get("succes")),
    }

    # ── Chemin de sortie ─────────────────────────────────────────
    if not output_path:
        ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = (scan.get("target") or "scan").replace("/", "_").replace(":", "_")
        output_path = f"rapport_{safe_target}_{ts}.pdf"

    # ── Mise en page ─────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.5 * cm, rightMargin=1.5 * cm,
        topMargin=1.8 * cm,  bottomMargin=2 * cm,
        title=f"Rapport PenTool — {scan.get('target','?')}",
        author="PenTool / reporter.py",
    )

    styles = build_styles()
    story  = []

    # ── Construction des sections ────────────────────────────────
    build_cover(story, scan, stats, styles)
    build_toc(story, stats, styles)
    build_section_scan_info(story, scan, styles)
    story.append(Spacer(1, 0.3 * cm))
    build_section_recon(story, recon, subdomains, os_fingerprints, styles)
    story.append(PageBreak())
    build_section_ports(story, ports, styles)
    story.append(PageBreak())
    build_section_cves(story, cves, styles)
    story.append(PageBreak())
    build_section_exploits(story, exploits, styles)
    story.append(Spacer(1, 0.3 * cm))
    build_section_evidence(story, exploits, styles)
    story.append(PageBreak())
    build_section_recommendations(story, scan, ports, cves, exploits, styles)

    # ── Compilation ──────────────────────────────────────────────
    doc.build(story, onFirstPage=_page_number_canvas, onLaterPages=_page_number_canvas)

    if verbose:
        print(f"[+] Rapport généré : {output_path}")
    return output_path


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Générateur de rapport PDF — synthèse scanner + CVE + exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python reporter.py --list-scans
  python reporter.py --scan-id 1
  python reporter.py --scan-id 1 --output mon_rapport.pdf
  python reporter.py --scan-id 1 --verbose
        """
    )
    parser.add_argument("--scan-id",    type=int, help="ID du scan à reporter")
    parser.add_argument("--list-scans", action="store_true",
                        help="Lister les scans disponibles en base")
    parser.add_argument("--output",  "-o", metavar="FILE",
                        help="Nom du fichier PDF de sortie (défaut: rapport_<cible>_<ts>.pdf)")
    parser.add_argument("--db",      default=DB_PATH,
                        help=f"Chemin vers la base SQLite (défaut: {DB_PATH})")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Affichage détaillé")
    args = parser.parse_args()

    # ── Listing ──────────────────────────────────────────────────
    if args.list_scans:
        try:
            db    = ReportDatabase(args.db)
            scans = db.list_scans()
            db.close()
        except FileNotFoundError as e:
            print(e)
            return 1

        if not scans:
            print("Aucun scan en base.")
            return 0

        print(f"\n{'ID':>4}  {'Cible':<25} {'IP':<16} {'Date':<20} {'Statut':<12} Ports")
        print("─" * 85)
        for s in scans:
            print(f"{s['id']:>4}  {(s['target'] or ''):<25} {(s['target_ip'] or ''):<16} "
                  f"{(s['start_time'] or '')[:19]:<20} {(s['status'] or ''):<12} "
                  f"{s['open_ports_count']}")
        return 0

    # ── Génération du rapport ────────────────────────────────────
    if not args.scan_id:
        parser.print_help()
        return 1

    print(f"\n{'═'*60}")
    print(f"  REPORTER — PenTool")
    print(f"  Scan ID : {args.scan_id}")
    print(f"  Base    : {args.db}")
    print(f"{'═'*60}")

    try:
        out = generate_report(
            scan_id    = args.scan_id,
            db_path    = args.db,
            output_path= args.output,
            verbose    = args.verbose,
        )
        print(f"\n[+] Rapport PDF généré avec succès :")
        print(f"    {os.path.abspath(out)}")
        return 0
    except FileNotFoundError as e:
        print(e)
        return 1
    except ValueError as e:
        print(f"[!] {e}")
        return 1
    except Exception as e:
        print(f"[!] Erreur inattendue : {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
