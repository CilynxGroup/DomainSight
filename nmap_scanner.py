import subprocess
import xml.etree.ElementTree as ET
import sqlite3
from pathlib import Path
from db_manager import save_nmap_results
from rich.console import Console
import logging

console = Console()
logger = logging.getLogger("DomainSight")

def run_nmap_scan(subdomain, db_path):
    """
    Run Nmap scan on the given subdomain and save results into database.
    """
    try:
        console.log(f"[blue]Starting Nmap scan for {subdomain}...[/blue]")

        cmd = f"nmap  -sV -T4 --top-ports 1000 -oX - {subdomain}"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=300)

        nmap_output = result.stdout

        nmap_data = parse_nmap_xml_output(nmap_output)

        if nmap_data:
            save_nmap_results(subdomain, nmap_data, db_path)
            logger.info(f"[green]Nmap scan complete for {subdomain} — {len(nmap_data)} ports saved.[/green]")
        else:
            logger.warning(f"[yellow]No open ports found for {subdomain}.[/yellow]")

    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]Nmap scan for {subdomain} timed out.[/yellow]")
    except Exception as e:
        logger.warning(f"[yellow]Nmap scan failed for {subdomain}: {e}[/yellow]")

def parse_nmap_xml_output(xml_output):
    """
    Parse Nmap XML output (in string) and return list of ports info dicts.
    """
    ports_data = []

    try:
        root = ET.fromstring(xml_output)
        for host in root.findall('host'):
            ports_element = host.find('ports')
            if ports_element is not None:
                for port in ports_element.findall('port'):
                    port_id = int(port.attrib.get('portid'))
                    protocol = port.attrib.get('protocol', '')

                    state_element = port.find('state')
                    state = state_element.attrib.get('state', '') if state_element is not None else ''

                    service_element = port.find('service')
                    service = service_element.attrib.get('name', '') if service_element is not None else ''
                    version = service_element.attrib.get('version', '') if service_element is not None else ''

                    ports_data.append({
                        'port': port_id,
                        'protocol': protocol,
                        'service': service,
                        'version': version,
                        'state': state
                    })

    except ET.ParseError as e:
        logger.warning(f"[yellow]Failed to parse Nmap XML output: {e}[/yellow]")
    except Exception as e:
        logger.warning(f"[yellow]Unknown error during Nmap parsing: {e}[/yellow]")

    return ports_data
