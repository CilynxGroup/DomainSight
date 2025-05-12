# live_checker.py

from pathlib import Path
from utils import run_with_progress
from rich.console import Console
import logging
import sqlite3

from db_manager import get_db_path, get_or_create_subdomain_id

console = Console()
logger  = logging.getLogger("DomainSight")

def check_live_subdomains(args, merged_file: Path):
    """
    Uses dnsx to filter all_subdomains.txt → live_subdomains.txt,
    then saves each live subdomain into the database.
    """
    output = Path(args.output) / "live_subdomains.txt"
    console.log(f"[blue]Checking live subdomains with dnsx...[/blue]")

    cmd = f"dnsx -l {merged_file} -a -silent"
    run_with_progress("dnsx", cmd, str(output), timeout=60)
    console.log(f"[green]dnsx completed; live list → {output}[/green]")

    # Persist only live hosts
    db_path = get_db_path(args.domain)
    count = 0
    conn  = sqlite3.connect(db_path)
    for host in open(output):
        host = host.strip()
        if not host:
            continue
        try:
            get_or_create_subdomain_id(host, db_path)
            count += 1
        except Exception as e:
            logger.warning(f"[yellow]Failed to save live subdomain {host}: {e}[/yellow]")
    conn.close()

    console.log(f"[green]{count} live subdomains saved to DB[/green]")
    return output
