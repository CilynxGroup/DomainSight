from flask import Flask, render_template, request, jsonify
import sqlite3
from pathlib import Path
from rich.console import Console
import logging
import json

console = Console()
logger = logging.getLogger("DomainSight")
from flask import redirect, url_for

app = Flask(__name__)

# === Settings ===
DB_DIR = Path("db")
GRAPH_DIR = Path("output")

# === Routes ===

@app.route('/')
def index():
    """
    Homepage - show available scanned TLDs with number of live subdomains.
    """
    tlds_info = []

    for db_file in DB_DIR.glob("*.db"):
        tld = db_file.stem
        db_path = db_file

        live_count = 0
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM subdomains")
            live_count = c.fetchone()[0]
            conn.close()
        except Exception as e:
            logger.warning(f"[yellow]Failed to query {tld} database: {e}[/yellow]")

        tlds_info.append({
            'tld': tld,
            'live_count': live_count
        })

    return render_template('index.html', tlds_info=tlds_info)


@app.route('/tld/<tld>')
def view_tld(tld):
    """
    View assets for a specific TLD.
    """
    return render_template('tld_dashboard.html', tld=tld)


@app.route('/api/tld/<tld>')
def api_tld_data(tld):
    """
    API endpoint: return JSON of assets for a specific TLD,
    including classification and exploit advice.
    """
    db_path = DB_DIR / f"{tld}.db"

    if not db_path.is_file():
        return jsonify({"error": "Database not found"}), 404

    assets = []

    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        query = """
        SELECT 
            s.name,
            GROUP_CONCAT(DISTINCT n.port || '/' || n.service || '/' || n.state) AS ports,
            GROUP_CONCAT(DISTINCT nr.template_id || ' (' || nr.severity || ')') AS vulnerabilities,
            ac.backend,
            ae.risk_score,
            ae.exploit_advice,
            s.purpose
        FROM subdomains s
        LEFT JOIN nmap_results n
          ON s.id = n.subdomain_id
        LEFT JOIN nuclei_results nr
          ON s.id = nr.subdomain_id
        LEFT JOIN ai_classification ac
          ON s.id = ac.subdomain_id
        LEFT JOIN ai_exploit_advice ae
          ON s.id = ae.subdomain_id
        GROUP BY s.id
        """

        for row in c.execute(query):
            assets.append({
                'subdomain':       row[0],
                'ports':           row[1] or '',
                'vulnerabilities': row[2] or '',
                'backend':         row[3] or '',
                'risk_score':      row[4] or '',
                'advice':          row[5] or '',
                'purpose':         row[6] or 'Unknown'
            })

        conn.close()

    except Exception as e:
        logger.warning(f"[yellow]Failed to query TLD {tld}: {e}[/yellow]")
        return jsonify({"error": "Internal error"}), 500

    return jsonify(assets)


@app.route("/tld/<tld>/ai/<subdomain>")
def view_ai_advice(tld, subdomain):
    """
    View AI exploitation advice for a specific subdomain under a given TLD.
    """
    db_path = DB_DIR / f"{tld}.db"
    if not db_path.is_file():
        return render_template("ai_advice.html", tld=tld, subdomain=subdomain, advice=None)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ae.exploit_advice, ae.risk_score, ae.created_at
            FROM ai_exploit_advice ae
            JOIN subdomains s
              ON ae.subdomain_id = s.id
            WHERE s.name = ?
        """, (subdomain,))
        row = cursor.fetchone()
        conn.close()

        if row:
            advice, score, timestamp = row
            return render_template(
                "ai_advice.html",
                tld=tld,
                subdomain=subdomain,
                advice=advice,
                score=score,
                timestamp=timestamp
            )
        else:
            return render_template("ai_advice.html", tld=tld, subdomain=subdomain, advice=None)

    except Exception as e:
        logger.warning(f"[yellow]Failed to load AI advice for {subdomain}: {e}[/yellow]")
        return render_template("ai_advice.html", tld=tld, subdomain=subdomain, advice=None)


# === Main ===
@app.route('/clear_db/<tld>', methods=['POST'])
def clear_db(tld):
    """
    Deletes the SQLite database for a single TLD and redirects back to index.
    """
    db_path = DB_DIR / f"{tld}.db"
    try:
        if db_path.is_file():
            db_path.unlink()
            console.log(f"[red]Deleted database: {db_path}[/red]")
    except Exception as e:
        logger.warning(f"[yellow]Failed to delete {db_path}: {e}[/yellow]")
    return redirect(url_for('index'))

@app.route('/clear_all', methods=['POST'])
def clear_all():
    """
    Deletes all TLD databases and redirects back to index.
    """
    for db_file in DB_DIR.glob("*.db"):
        try:
            db_file.unlink()
            console.log(f"[red]Deleted database: {db_file}[/red]")
        except Exception as e:
            logger.warning(f"[yellow]Failed to delete {db_file}: {e}[/yellow]")
    return redirect(url_for('index'))

if __name__ == '__main__':
    console.log("[blue]Starting DomainSight Webserver...[/blue]")
    app.run(host='0.0.0.0', port=5000, debug=True)
