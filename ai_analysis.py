import os
import json
import openai
import requests
import re
import time
import threading
import concurrent.futures
import sqlite3
import logging

from rich.console import Console
from db_manager import save_classification_analysis

console = Console()
logger = logging.getLogger("DomainSight")
openai_lock = threading.Lock()

def set_openai_api_key(api_key=None):
    if api_key:
        openai.api_key = api_key
    elif os.getenv("OPENAI_API_KEY"):
        openai.api_key = os.getenv("OPENAI_API_KEY")
    else:
        logger.warning("[yellow]No OpenAI API key provided![/yellow]")

def analyze_subdomain(subdomain: str, db_path: str):
    """
    Fingerprint & classify a subdomain (backend, purpose, etc.)
    and save results into ai_classification.
    """
    # (You may have an is_already_analyzed check here)

    # Build your classification prompt
    prompt = build_prompt(subdomain)  # assume you have a prompt builder for classification

    backoff = 1
    while True:
        try:
            with openai_lock:
                        response = openai.chat.completions.create(
            model="gpt-4o",          # or gpt-4o
            messages=[
                {"role": "system", "content": "You are a red team security expert."},
                {"role": "user",   "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )


            content = response.choices[0].message.content.strip()
            
            # Cleanup fences, parse JSON object:
            if content.startswith("```"):
                content = re.sub(r"^```[a-z]*", "", content)
                content = re.sub(r"```$", "", content).strip()
            result = json.loads(content)

            save_classification_analysis(subdomain, result, db_path)
            logger.info(f"[green]Classification complete for {subdomain}[/green]")
            break

        except openai.error.RateLimitError:
            logger.warning(f"[yellow]Rate limit hit for {subdomain}. Backing off {backoff}s...[/yellow]")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

        except Exception as e:
            logger.warning(f"[red]Failed classification for {subdomain}: {e}[/red]")
            break

def parallel_openai_analysis(subdomains: list, db_path: str, max_workers=5):
    console.log("[blue]Running parallel classification...[/blue]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        pool.map(lambda sd: analyze_subdomain(sd, db_path), subdomains)

def build_prompt(subdomain):
    """
    Build the AI prompt with collected fingerprint data.
    """
    return f"""
You are analyzing an external subdomain to determine its risk and purpose.

Subdomain name: {subdomain}



Tasks:
- Based on subdomain name , accessing and exploring the website, including analayzing the HTTP response headers, sitemap.xml and robots.txt files and JavaScript client side scripts + fingerprint, predict what this subdomain is used for.
- Classify the subdomain's purpose into one of:
  - Admin Portal
  - API Server
  - Authentication/Login
  - Development/Testing Environment
  - Monitoring/Status
  - Storage/Bucket
  - Public Website
  - Unknown

- Also guess the backend stack if possible.
- Identify common vulnerabilities likely for this type of asset.
- Suggest direct attack advice based on what you see.

Respond in STRICT JSON format:
{{
  "backend": "Likely backend stack",
  "vulnerabilities": "Short list or paragraph",
  "risk_score": 0,
  "direct_attack_advice": "One or two technical exploitation suggestions",
  "manual_website_exploring_result": "Summary of manual exploration tips",
  "purpose": "Selected category from the list"
}}
"""
