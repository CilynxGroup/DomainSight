import subprocess
import json
from pathlib import Path
from db_manager import save_nuclei_results
from rich.console import Console
import logging

console = Console()
logger = logging.getLogger("DomainSight")

def run_nuclei_scan(subdomain, db_path):
    """
    Run Nuclei scan on the given subdomain and save results into database.
    """
    try:
        console.log(f"[blue]Starting Nuclei scan for {subdomain}...[/blue]")

        # Run nuclei scan
        cmd = f"nuclei -u {subdomain} -json -silent"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=300)

        if result.returncode != 0:
            logger.warning(f"[yellow]Nuclei scan failed for {subdomain} (exit code {result.returncode})[/yellow]")
            return

        findings = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                except json.JSONDecodeError:
                    logger.warning(f"[yellow]Failed to parse Nuclei output line: {line}[/yellow]")

        if findings:
            save_nuclei_results(subdomain, findings, db_path)
            logger.info(f"[green]Nuclei scan complete for {subdomain} — {len(findings)} findings saved.[/green]")
        else:
            logger.warning(f"[yellow]No vulnerabilities found for {subdomain}.[/yellow]")

    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]Nuclei scan for {subdomain} timed out.[/yellow]")
    except Exception as e:
        logger.warning(f"[yellow]Nuclei scan failed for {subdomain}: {e}[/yellow]")
