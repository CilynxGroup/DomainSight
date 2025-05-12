import subprocess
import json
from db_manager import save_nuclei_results
from rich.console import Console
import logging

console = Console()
logger = logging.getLogger("DomainSight")

def run_nuclei_scan(subdomain, db_path):
    """
    Run Nuclei scan on the given subdomain and save structured JSON results.
    """
    try:
        console.log(f"[blue]Starting Nuclei scan for {subdomain}...[/blue]")

        # Use -j for JSON output and -silent for line-based structured entries
        cmd = f'nuclei -u {subdomain} -j -rl 20 -silent -H "Mozilla/5.0 (iPad16,3; CPU OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Tropicana_NJ/5.7.1"'

        result = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=300
        )

        findings = []

        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
                findings.append(parsed)
            except json.JSONDecodeError as e:
                logger.warning(f"[yellow]Nuclei JSON parsing failed on line: {line[:100]}... Error: {e}[/yellow]")

        if findings:
            save_nuclei_results(subdomain, findings, db_path)
            logger.info(f"[green]Nuclei scan complete for {subdomain} — {len(findings)} findings saved.[/green]")
        else:
            logger.info(f"[yellow]Nuclei found no vulnerabilities for {subdomain}.[/yellow]")

    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]Nuclei scan timed out for {subdomain}.[/yellow]")
    except Exception as e:
        logger.warning(f"[yellow]Nuclei scan failed for {subdomain}: {e}[/yellow]")
