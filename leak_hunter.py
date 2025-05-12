import requests
import re
import csv
from pathlib import Path
from rich.console import Console
import logging

console = Console()
logger = logging.getLogger("DomainSight")

PII_PATTERNS = {
    'email': r'[\w\.-]+@[\w\.-]+',
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'(?i)aws_secret_access_key[^\S\r\n]*=[^\S\r\n]*([A-Za-z0-9/+=]{40})',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b'
}

def run_leak_hunter(subdomains, args):
    """
    Scan GitHub and GitLab for code leaks mentioning the live subdomains.
    Save results into CSV file.
    """
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / "leak_hunter.csv"

    console.log("[blue]Starting Leak Hunter scan...[/blue]")

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        header = ['service', 'subdomain', 'repo', 'path', 'url']
        if args.hunt_pii:
            header.append('pii_matches')
        writer.writerow(header)

        if args.github_token:
            scan_github(subdomains, args.github_token, writer, hunt_pii=args.hunt_pii)
        
        if args.gitlab_token:
            scan_gitlab(subdomains, args.gitlab_token, writer, hunt_pii=args.hunt_pii)

    logger.info(f"[green]Leak Hunter results saved to {output_path}[/green]")

def scan_github(subdomains, token, writer, hunt_pii=False):
    """
    Search GitHub for leaks mentioning subdomains.
    """
    headers = {'Authorization': f'token {token}'}

    for sub in subdomains:
        page = 1
        while True:
            query = requests.utils.quote(f"{sub} in:file")
            url = f"https://api.github.com/search/code?q={query}&page={page}&per_page=100"
            r = requests.get(url, headers=headers)

            if r.status_code != 200:
                logger.warning(f"[yellow]GitHub API error for {sub}: {r.status_code}[/yellow]")
                break

            items = r.json().get('items', [])
            if not items:
                break

            for item in items:
                repo = item['repository']['full_name']
                path = item['path']
                link = item['html_url']
                row = ['github', sub, repo, path, link]

                if hunt_pii:
                    pii_matches = extract_pii_from_github(repo, path, token)
                    row.append(';'.join(pii_matches))

                writer.writerow(row)

            if 'next' not in r.links:
                break

            page += 1

def scan_gitlab(subdomains, token, writer, hunt_pii=False):
    """
    Search GitLab for leaks mentioning subdomains.
    """
    headers = {'PRIVATE-TOKEN': token}

    for sub in subdomains:
        page = 1
        while True:
            url = f"https://gitlab.com/api/v4/search?scope=blobs&search={sub}&page={page}&per_page=100"
            r = requests.get(url, headers=headers)

            if r.status_code != 200:
                logger.warning(f"[yellow]GitLab API error for {sub}: {r.status_code}[/yellow]")
                break

            items = r.json()
            if not items:
                break

            for item in items:
                repo = item.get('project_name', '')
                path = item.get('filename', '')
                link = item.get('web_url', '')
                row = ['gitlab', sub, repo, path, link]

                if hunt_pii:
                    pii_matches = extract_pii_from_gitlab(link)
                    row.append(';'.join(pii_matches))

                writer.writerow(row)

            page += 1

def extract_pii_from_github(repo, path, token):
    """
    Download raw GitHub file and search for PII patterns.
    """
    matches = []
    try:
        branch = 'master'
        raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
        headers = {'Authorization': f'token {token}'}
        content = requests.get(raw_url, headers=headers, timeout=20).text

        for key, pattern in PII_PATTERNS.items():
            found = re.findall(pattern, content)
            for match in found:
                matches.append(f"{key}:{match}")

    except Exception as e:
        logger.warning(f"[yellow]Error extracting PII from GitHub {repo}/{path}: {e}[/yellow]")

    return matches

def extract_pii_from_gitlab(link):
    """
    Download raw GitLab file and search for PII patterns.
    """
    matches = []
    try:
        raw_url = link.replace('/-/blob/', '/-/raw/')
        content = requests.get(raw_url, timeout=20).text

        for key, pattern in PII_PATTERNS.items():
            found = re.findall(pattern, content)
            for match in found:
                matches.append(f"{key}:{match}")

    except Exception as e:
        logger.warning(f"[yellow]Error extracting PII from GitLab file: {e}[/yellow]")

    return matches
