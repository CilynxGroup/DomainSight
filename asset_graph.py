import sqlite3
import json
from pathlib import Path
from rich.console import Console
import logging

console = Console()
logger = logging.getLogger("DomainSight")

def generate_asset_graph(args):
    """
    Generates a JSON structure summarizing all assets from the database,
    including classification and exploit advice. Saves it into
    <output_dir>/graph_data.json for frontend visualization.
    """
    # Determine DB and output paths
    db_path = Path("db") / f"{args.domain}.db"
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Connect and query
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    query = """
    SELECT
        s.name AS subdomain,
        GROUP_CONCAT(DISTINCT n.port || '/' || n.service || '/' || n.state) AS ports,
        GROUP_CONCAT(DISTINCT nr.template_id || ' (' || nr.severity || ')') AS vulnerabilities,
        ac.backend,
        ea.risk_score,
        ea.exploit_advice
    FROM subdomains s
    LEFT JOIN nmap_results n
      ON s.id = n.subdomain_id
    LEFT JOIN nuclei_results nr
      ON s.id = nr.subdomain_id
    LEFT JOIN ai_classification ac
      ON s.id = ac.subdomain_id
    LEFT JOIN ai_exploit_advice ea
      ON s.id = ea.subdomain_id
    GROUP BY s.id
    """

    nodes = []
    for row in c.execute(query):
        nodes.append({
            'subdomain':       row[0],
            'ports':           row[1] or '',
            'vulnerabilities': row[2] or '',
            'backend':         row[3] or '',
            'risk_score':      row[4] if row[4] is not None else 'N/A',
            'advice':          row[5] or ''
        })

    conn.close()

    # Save to JSON
    graph_file = output_dir / "graph_data.json"
    with open(graph_file, 'w') as f:
        json.dump(nodes, f, indent=2)

    logger.info(f"[green]Asset graph data saved: {graph_file}[/green]")
