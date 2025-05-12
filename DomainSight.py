#!/usr/bin/env python3
"""
DomainSight: Subdomain Recon & Automation Tool
"""

import argparse
from pathlib import Path
import logging
from rich.console import Console
from rich.logging import RichHandler
from ai_analysis import set_openai_api_key
from db_manager import init_db

# Set API key first
set_openai_api_key()
BANNER = r"""
  ____                            _         ____   _         _      _   
 |  _ \   ___   _ __ ___    __ _ (_) _ __  / ___| (_)  __ _ | |__  | |_ 
 | | | | / _ \ | '_ ` _ \  / _` || || '_ \ \___ \ | | / _` || '_ \ | __|
 | |_| || (_) || | | | | || (_| || || | | | ___) || || (_| || | | || |_ 
 |____/  \___/ |_| |_| |_|\__,_||_||_| |_||____/ |_| \__, ||_| |_|\__|
                                                      |___/             
        DomainSight: Subdomain Recon & Automation Tool
"""

# === Rich Console and Logger Setup ===
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(show_time=True, show_level=True, show_path=False, markup=True)]
)
logger = logging.getLogger("DomainSight")

# === Import Modules ===
from db_manager import get_db_path
from subdomain_enum import run_subdomain_enum
from live_checker import check_live_subdomains
from nuclei_scanner import run_nuclei_scan
from nmap_scanner import run_nmap_scan
from ai_analysis import parallel_openai_analysis

from asset_graph import generate_asset_graph
from leak_hunter import run_leak_hunter
from utils import read_lines

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="DomainSight - Red Team Asset Discovery & Risk Platform",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-d', '--domain', required=True, help='Target base domain (TLD)')
    parser.add_argument('-o', '--output', default='output', help='Output directory for results')
    parser.add_argument('--enum-tools', default='subfinder,amass,assetfinder,gobuster',
                        help='Comma-separated enumeration tools to use')
    parser.add_argument('--subtakeover', action='store_true', help='Enable subdomain takeover checks via subjack')
    parser.add_argument('--leak-hunter', action='store_true', help='Enable GitHub/GitLab Leak Hunter scan')
    parser.add_argument('--hunt-pii', action='store_true', help='Scan files for sensitive PII leaks')
    parser.add_argument('--github-token', help='GitHub API token')
    parser.add_argument('--gitlab-token', help='GitLab API token')
    parser.add_argument('--passive-scan', choices=['shodan', 'censys'], 
                    help='Enable passive port scan. Must choose shodan or censys platform.')

    parser.add_argument('--passive-limit', type=int, help='Max number of IPs to scan passively')
    parser.add_argument('--passive-delay', type=float, default=1.0, help='Delay between passive API calls')
    parser.add_argument('--shodan-keys', help='Comma-separated Shodan API keys')
    parser.add_argument('--censys-ids', help='Comma-separated Censys API IDs')
    parser.add_argument('--censys-secrets', help='Comma-separated Censys API secrets')
    parser.add_argument('--fingerprint', action='store_true', help='Enable OpenAI backend fingerprinting and risk scoring')
    parser.add_argument('--skip-nmap', action='store_true', help='Skip Nmap scanning')
    parser.add_argument('--skip-nuclei', action='store_true', help='Skip Nuclei vulnerability scanning')
    parser.add_argument('--skip-ai', action='store_true', help='Skip OpenAI fingerprint analysis')
    parser.add_argument('--ai-agent', action='store_true', help='Run AI advisor on scanned subdomains')

    return parser.parse_args()

def main():
    console.print(BANNER, style="green")
    
    args = parse_arguments()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    db_path = get_db_path(args.domain)
    init_db(db_path)

    console.log(f"[bold blue]Starting DomainSight scan for {args.domain}[/bold blue]")

    # === 1. Subdomain Enumeration
    merged_file = run_subdomain_enum(args)

    # === 2. Live Host Checking
    live_file = check_live_subdomains(args, merged_file)
    live_subdomains = read_lines(live_file)

    if not live_subdomains:
        logger.warning("[yellow]No live subdomains found. Exiting.[/yellow]")
        return

    logger.info(f"[green]{len(live_subdomains)} live subdomains detected.[/green]")

    # === 3. Optional: Subdomain Takeover
    if args.subtakeover:
        from takeover_checker import run_subjack
        run_subjack(live_file, output_dir)

    # === 4. Passive Scanning (Shodan, Censys)
    if args.passive_scan:
        from passive_scanner import run_passive_scans
        run_passive_scans(args, live_file)

    # === 5. Leak Hunter
    if args.leak_hunter:
        run_leak_hunter(live_subdomains, args)

    # === 6. Per-Subdomain Deep Scanning
    for subdomain in live_subdomains:
        if not args.skip_nuclei:
            run_nuclei_scan(subdomain, db_path)

        if not args.skip_nmap:
            run_nmap_scan(subdomain, db_path)

    if args.fingerprint and not args.skip_ai:
            parallel_openai_analysis(live_subdomains, db_path)

    if args.ai_agent:
        from ai_agent.agent_core import run_agent_for_all
        logger.info(f"[green]Running AI Red Team Advisor...[/green]")
        run_agent_for_all(get_db_path(args.domain))


    # === 7. Generate Asset Graph (JSON)
    generate_asset_graph(args)

    logger.info(f"[bold green]DomainSight scan complete for {args.domain}[/bold green]")
    logger.info(f"[bold green]Output saved under {output_dir}/ and database at db/{args.domain}.db[/bold green]")

if __name__ == "__main__":
    main()
