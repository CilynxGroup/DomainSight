# passive_scanner.py

from pathlib import Path
import csv
import socket
import base64
import time
import requests
import shodan
from rich.console import Console
import logging
import sqlite3

from db_manager import get_db_path, get_or_create_subdomain_id

console = Console()
logger = logging.getLogger("DomainSight")


def run_passive_scans(args, live_file):
    """
    Run passive scans (Shodan or Censys), dump to CSV,
    and persist any open ports into nmap_results.
    """
    # 1) Resolve hosts to IPs
    hosts = [line.strip() for line in open(live_file) if line.strip()]
    ipmap = {}
    for host in hosts:
        try:
            ipmap.setdefault(socket.gethostbyname(host), []).append(host)
        except Exception as e:
            logger.warning(f"[yellow]Failed to resolve {host}: {e}[/yellow]")

    ips = list(ipmap.keys())
    if args.passive_limit:
        ips = ips[:args.passive_limit]

    # 2) Perform chosen passive scan
    if args.passive_scan == "shodan":
        if not args.shodan_keys:
            logger.warning("[red]No Shodan API keys provided![/red]")
            return
        csv_path = run_shodan_scan(args, ips, ipmap)
    elif args.passive_scan == "censys":
        if not (args.censys_ids and args.censys_secrets):
            logger.warning("[red]No Censys credentials provided![/red]")
            return
        csv_path = run_censys_scan(args, ips, ipmap)
    else:
        logger.warning(f"[yellow]Unknown passive scan: {args.passive_scan}[/yellow]")
        return

    # 3) Persist CSV results into nmap_results
    persist_passive_csv_to_db(csv_path, args)


def run_shodan_scan(args, ips, ipmap):
    """
    Query Shodan for open ports and write results to CSV.
    """
    console.log("[blue]Running Shodan passive port scan...[/blue]")
    keys = args.shodan_keys.split(',')
    output_path = Path(args.output) / "shodan_ports.csv"

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['host', 'ip', 'ports'])
        for i, ip in enumerate(ips):
            api = shodan.Shodan(keys[i % len(keys)])
            ports = []
            backoff = 1
            for _ in range(5):
                try:
                    info = api.host(ip)
                    ports = info.get('ports', [])
                    break
                except shodan.exception.APIError as e:
                    if '429' in str(e):
                        time.sleep(backoff)
                        backoff *= 2
                        continue
                    break
            for host in ipmap[ip]:
                writer.writerow([host, ip, ';'.join(map(str, ports))])
            time.sleep(args.passive_delay)

    logger.info(f"[green]Shodan results saved: {output_path}[/green]")
    return output_path


def run_censys_scan(args, ips, ipmap):
    """
    Query Censys for open ports and write results to CSV.
    """
    console.log("[blue]Running Censys passive port scan...[/blue]")
    ids     = args.censys_ids.split(',')
    secrets = args.censys_secrets.split(',')
    output_path = Path(args.output) / "censys_ports.csv"

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['host', 'ip', 'ports'])
        for i, ip in enumerate(ips):
            cid, secret = ids[i % len(ids)], secrets[i % len(secrets)]
            auth = base64.b64encode(f"{cid}:{secret}".encode()).decode()
            headers = {
                'Accept': 'application/json',
                'Authorization': f"Basic {auth}"
            }
            ports = []
            backoff = 1
            for _ in range(5):
                try:
                    r = requests.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                                     headers=headers, timeout=30)
                    if r.status_code == 429:
                        time.sleep(backoff)
                        backoff *= 2
                        continue
                    services = r.json().get('result', {}).get('services', [])
                    ports = [s.get('port') for s in services if s.get('port')]
                    break
                except Exception:
                    break
            for host in ipmap[ip]:
                writer.writerow([host, ip, ';'.join(map(str, ports))])
            time.sleep(args.passive_delay)

    logger.info(f"[green]Censys results saved: {output_path}[/green]")
    return output_path


def persist_passive_csv_to_db(csv_path: Path, args):
    """
    Read CSV of host, ip, ports and insert each port as 'open'
    into the nmap_results table.
    """
    db_path = get_db_path(args.domain)
    conn    = sqlite3.connect(db_path)
    c       = conn.cursor()
    inserted = 0

    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            host  = row.get('host')
            ports = row.get('ports', '')
            if not host or not ports:
                continue

            # Ensure the subdomain exists
            sub_id = get_or_create_subdomain_id(host, db_path)

            # Insert each port
            for p in ports.split(';'):
                try:
                    port_num = int(p)
                except:
                    continue
                try:
                    c.execute(
                        "INSERT OR IGNORE INTO nmap_results (subdomain_id, port, service, state) VALUES (?, ?, ?, ?)",
                        (sub_id, port_num, '', 'open')
                    )
                    if c.rowcount > 0:
                        inserted += 1
                except Exception as e:
                    logger.warning(f"[yellow]Failed to save port {p} for {host}: {e}[/yellow]")

    conn.commit()
    conn.close()
    console.log(f"[green]{inserted} passive ports saved into nmap_results[/green]")
