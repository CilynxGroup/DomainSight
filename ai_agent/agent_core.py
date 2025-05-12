import sqlite3
from ai_agent.context_builder import get_context_for_subdomain
from ai_agent.prompt_templates   import build_prompt
from ai_agent.openai_wrapper     import ask_openai
from db_manager                  import save_exploit_advice
from ai_agent.openai_wrapper import ask_openai
import os
import openai
import re
import logging

# Configure a dedicated logger
logger = logging.getLogger("DomainSight.openai")


# Ensure key is loaded
openai.api_key = os.getenv("OPENAI_API_KEY")
# ...
def run_agent_for(subdomain: str, db_path: str) -> dict:
    context = get_context_for_subdomain(subdomain, db_path)
    prompt  = build_prompt(context)
    try:
        result = ask_openai(prompt)
    except Exception as e:
        logger.error("run_agent_for(): unexpected error: %s", e, exc_info=True)
        result = {"error": str(e)}

    # Save on success
    if result.get("response_text"):
        save_exploit_advice(subdomain, result["response_text"], result["risk_score"], db_path)
    else:
        logger.warning("No response_text for subdomain %s, skipping save", subdomain)

    return {
        "subdomain": subdomain,
        "advice":    result.get("response_text", ""),
        "risk_score": result.get("risk_score", 0.0),
        "error":     result.get("error")
    }


def run_agent_for_all(db_path: str) -> list:
    """
    Iterate through all subdomains and run the agent.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT name FROM subdomains")
    names = [r[0] for r in c.fetchall()]
    conn.close()

    return [run_agent_for(name, db_path) for name in names]
