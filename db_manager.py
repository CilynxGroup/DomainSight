import sqlite3
from pathlib import Path
import logging
from rich.console import Console

console = Console()
logger = logging.getLogger("DomainSight")

DB_DIR = Path("db")

def get_db_path(tld: str) -> str:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    return str(DB_DIR / f"{tld}.db")

def init_db(db_path: str):
    """
    Create all core tables if they don’t exist:
    - subdomains
    - nmap_results
    - nuclei_results
    - ai_classification  ← NEW
    - ai_exploit_advice  ← NEW
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # --- existing tables ---
    c.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            purpose TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS nmap_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomain_id INTEGER,
            port INTEGER,
            service TEXT,
            state TEXT,
            protocol TEXT,
            FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS nuclei_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomain_id INTEGER,
            template_id TEXT,
            severity TEXT,
            matched_at TEXT,
            FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
        )
    """)

    # --- NEW classification table ---
    c.execute("""
        CREATE TABLE IF NOT EXISTS ai_classification (
            subdomain_id INTEGER PRIMARY KEY,
            backend TEXT,
            purpose TEXT,
            vulnerabilities TEXT,
            manual_website_exploring_result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
        )
    """)

    # --- NEW exploit‐advice table ---
    c.execute("""
        CREATE TABLE IF NOT EXISTS ai_exploit_advice (
            subdomain_id INTEGER PRIMARY KEY,
            exploit_advice TEXT,
            risk_score REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
        )
    """)

    conn.commit()
    conn.close()

def get_or_create_subdomain_id(subdomain: str, db_path: str) -> int:
    """
    Ensure the subdomain exists in subdomains(name) and return its id.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # Make sure table exists
    c.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            purpose TEXT
        )
    """)
    c.execute("SELECT id FROM subdomains WHERE name = ?", (subdomain,))
    row = c.fetchone()
    if row:
        sub_id = row[0]
    else:
        c.execute("INSERT INTO subdomains (name) VALUES (?)", (subdomain,))
        sub_id = c.lastrowid
    conn.commit()
    conn.close()
    return sub_id

def save_classification_analysis(subdomain: str, analysis_result: dict, db_path: str):
    """
    Write the AI‐classification output into ai_classification,
    and update subdomains.purpose so your dashboard can show the category.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # 1) Ensure the subdomain exists and get its ID
    sub_id = get_or_create_subdomain_id(subdomain, db_path)

    # 2) Upsert into ai_classification
    c.execute("""
        INSERT OR REPLACE INTO ai_classification
          (subdomain_id, backend, purpose, vulnerabilities, manual_website_exploring_result)
        VALUES (?, ?, ?, ?, ?)
    """, (
        sub_id,
        analysis_result.get('backend', ''),
        analysis_result.get('purpose', ''),
        analysis_result.get('vulnerabilities', ''),
        analysis_result.get('manual_website_exploring_result', '')
    ))

    # 3) ALSO update the subdomains.purpose column
    #    This is what your UI reads for the "Category" column.
    purpose = analysis_result.get('purpose', '').strip() or None
    if purpose:
        c.execute("""
            UPDATE subdomains
               SET purpose = ?
             WHERE id = ?
        """, (purpose, sub_id))

    conn.commit()
    conn.close()
    logger.info(f"[green]Saved AI classification & set purpose='{purpose}' for {subdomain}[/green]")


def save_exploit_advice(subdomain: str, advice: str, risk_score: float, db_path: str):
    """
    Write the red-team exploit advice into ai_exploit_advice.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    sub_id = get_or_create_subdomain_id(subdomain, db_path)

    # Upsert exploit‐advice record
    c.execute("""
        INSERT OR REPLACE INTO ai_exploit_advice
          (subdomain_id, exploit_advice, risk_score)
        VALUES (?, ?, ?)
    """, (
        sub_id,
        advice,
        risk_score
    ))

    conn.commit()
    conn.close()
    logger.info(f"[green]Saved exploit advice for {subdomain}[/green]")

def ensure_purpose_field(conn):
    """
    Ensure that the 'purpose' column exists in subdomains table.
    (For older databases created before purpose existed.)
    """
    try:
        c = conn.cursor()
        c.execute("PRAGMA table_info(subdomains)")
        columns = [col[1] for col in c.fetchall()]

        if 'purpose' not in columns:
            c.execute("ALTER TABLE subdomains ADD COLUMN purpose TEXT DEFAULT 'Unknown'")
            conn.commit()
            logger.info("[green]Migrated subdomains table: added 'purpose' column.[/green]")
    except Exception as e:
        logger.warning(f"[yellow]Failed to check/migrate purpose field: {e}[/yellow]")

def get_or_create_subdomain_id(subdomain, db_path):
    """
    Insert subdomain into DB if not exists, return its ID.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT id FROM subdomains WHERE name = ?", (subdomain,))
    row = c.fetchone()
    if row:
        sub_id = row[0]
    else:
        c.execute("INSERT INTO subdomains (name) VALUES (?)", (subdomain,))
        sub_id = c.lastrowid
        conn.commit()
    conn.close()
    return sub_id

def save_nuclei_results(subdomain, findings, db_path):
    """
    Save Nuclei scan results for a subdomain.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    subdomain_id = get_or_create_subdomain_id(subdomain, db_path)

    for finding in findings:
        template_id = finding.get("template-id", "")
        matched_at = finding.get("matched-at", "")
        matcher_name = finding.get("matcher-name", "")
        info = finding.get("info", {})
        severity = info.get("severity", "unknown")

        c.execute("""
            INSERT INTO nuclei_results (subdomain_id, template_id, severity, matcher_name, type, matched_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            subdomain_id,
            template_id,
            severity,
            matcher_name,
            finding.get("type", ""),
            matched_at
        ))

    conn.commit()
    conn.close()

    logger.info(f"[green]Saved {len(findings)} Nuclei findings for {subdomain}[/green]")

def save_nmap_results(subdomain, nmap_data, db_path):
    """
    Save Nmap open ports for a subdomain.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    subdomain_id = get_or_create_subdomain_id(subdomain, db_path)

    for port_info in nmap_data:
        c.execute("""
            INSERT INTO nmap_results (subdomain_id, port, protocol, service, version, state)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            subdomain_id,
            port_info.get('port'),
            port_info.get('protocol', ''),
            port_info.get('service', ''),
            port_info.get('version', ''),
            port_info.get('state', '')
        ))
    conn.commit()
    conn.close()

    logger.info(f"[green]Saved {len(nmap_data)} Nmap ports for {subdomain}[/green]")

