# ai_agent/context_builder.py

import sqlite3

def get_context_for_subdomain(subdomain: str, db_path: str) -> dict:
    """
    Fetch the context (Nmap + Nuclei findings) for a given subdomain
    from your SQLite DB.
    """
    context = {
        "subdomain": subdomain,
        "nmap": [],
        "vulnerabilities": [],
        "tech_stack": []  # placeholder if you add tech‐fingerprinting later
    }

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 1) Lookup subdomain ID
    cursor.execute("SELECT id FROM subdomains WHERE name = ?", (subdomain,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return context
    sub_id = row[0]

    # 2) Nmap results
    cursor.execute(
        "SELECT port, service, state FROM nmap_results WHERE subdomain_id = ?",
        (sub_id,)
    )
    for port, service, state in cursor.fetchall():
        context["nmap"].append(f"{port}/{service}/{state}")

    # 3) Nuclei results
    cursor.execute(
        "SELECT template_id, severity, matched_at FROM nuclei_results WHERE subdomain_id = ?",
        (sub_id,)
    )
    for template_id, severity, matched_at in cursor.fetchall():
        context["vulnerabilities"].append({
            "id": template_id,
            "severity": severity,
            "matched_at": matched_at
        })

    conn.close()
    return context
