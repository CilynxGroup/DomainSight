# subdomain_enum.py

from pathlib import Path
from utils import run_with_progress, read_lines, save_lines
from rich.console import Console
import logging
import sys

console = Console()
logger  = logging.getLogger("DomainSight")

ALLOWED_TOOLS = {"subfinder", "amass", "assetfinder", "gobuster"}
DEFAULT_TIMEOUTS = {
    "subfinder":   120,
    "amass":       180,
    "assetfinder":  60,
    "gobuster":     90
}

def run_subdomain_enum(args):
    """
    Run enumeration tools and merge results into all_subdomains.txt,
    without touching the DB.
    """
    domain     = args.domain
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    tools = [t.strip() for t in args.enum_tools.split(",") if t.strip()]
    cmds = {
        "subfinder":   f"subfinder -d {domain} -silent",
        "amass":       f"amass enum -passive -d {domain}",
        "assetfinder": f"assetfinder --subs-only {domain}",
        "gobuster":    (
            f"gobuster dns -d {domain} "
            "-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt "
            "-t 100 --quiet"
        )
    }

    output_files = []
    for tool in tools:
        if tool not in ALLOWED_TOOLS:
            logger.warning(f"[yellow]Skipping unknown tool: {tool}[/yellow]")
            continue

        tool_output = output_dir / f"{tool}.txt"
        console.log(f"[blue]Starting {tool}...[/blue]")
        ret = run_with_progress(tool, cmds[tool], str(tool_output), DEFAULT_TIMEOUTS.get(tool, 60))
        if ret == 0 and tool_output.is_file():
            output_files.append(tool_output)
            console.log(f"[green]{tool} completed; output → {tool_output}[/green]")
        else:
            logger.warning(f"[yellow]{tool} failed or produced no output[/yellow]")

    if not output_files:
        logger.error("[red]No enumeration results. Exiting.[/red]")
        sys.exit(1)

    merged_file = output_dir / "all_subdomains.txt"
    merge_and_deduplicate(output_files, merged_file)
    console.log(f"[green]{merged_file.name}: {len(read_lines(merged_file))} unique subdomains[/green]")

    return merged_file


def merge_and_deduplicate(files, merged_file):
    """
    Merge multiple outputs, dedupe, sort, and write to merged_file.
    """
    subs = set()
    for fp in files:
        for line in read_lines(fp):
            host = line.split()[0].rstrip(".")
            if host:
                subs.add(host)

    sorted_subs = sorted(subs)
    save_lines(merged_file, sorted_subs)
    logger.info(f"[green]{len(sorted_subs)} merged into {merged_file}[/green]")
