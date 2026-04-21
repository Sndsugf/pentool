-- schema.sql
-- Structure de la base de données

-- Table des CVEs
CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    severity TEXT,
    exploit_available BOOLEAN DEFAULT 0
);

-- Table des payloads
CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    name TEXT,
    payload TEXT,
    method TEXT,
    port INTEGER,
    service TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(id)
);
