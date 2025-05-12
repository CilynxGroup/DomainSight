def build_prompt(context: dict) -> str:
    subdomain = context.get("subdomain", "unknown")
    ports = ", ".join(context.get("nmap", [])) or "N/A"
    tech_stack = ", ".join(context.get("tech_stack", [])) or "Unknown"

    vuln_lines = []
    for vuln in context.get("vulnerabilities", []):
        vuln_lines.append(
            f"- Template: {vuln['id']} ({vuln['severity'].capitalize()}) at {vuln['matched_at']}"
        )
    findings = "\n".join(vuln_lines) if vuln_lines else "None"

    prompt = f"""You are a red team expert.

Subdomain: {subdomain}
Open Ports/Services: {ports}
Tech Stack: {tech_stack}

Findings from Nuclei:
{findings}

Based on this information, provide realistic exploitation strategies.
Include tactics, tools, and possible attack chains.
Give professional, actionable insights.
At the end, include a 'Risk Score: X.Y' which will be used as indication if the subdomain might be exploited from 0 to 10."""
    return prompt
