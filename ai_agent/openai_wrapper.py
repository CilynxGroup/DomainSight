# ai_agent/openai_wrapper.py

import os
import openai
import re
import logging

# --- Logging setup ---
logger = logging.getLogger("DomainSight.openai")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s: %(message)s"))
logger.addHandler(handler)

# --- API key setup ---
openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    logger.error("OPENAI_API_KEY not set in environment!")

def ask_openai(prompt: str) -> dict:
    """
    Sends the prompt to GPT-4-turbo (or another model) via the v1.x API,
    returns {'response_text': str, 'risk_score': float} on success or
    {'error': str} on failure.
    """
   
    try:
        # NEW v1.x interface:
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
        score   = extract_risk_score(content)
       

        return {"response_text": content, "risk_score": score}

    except Exception:
        logger.exception("OpenAI request failed")
        return {"error": "OpenAI API request error, see logs for details."}


def extract_risk_score(text: str) -> float:
    """
    Extracts a numeric risk score from the AI’s response.
    Looks for “Risk Score: X.Y” or “X.Y/10” or “X.Y out of 10”.
    """
    # Pattern 1: “Risk Score: 7.5”
    m = re.search(r'(?i)risk score[:\s]*([0-9]{1,2}(?:\.\d+)?)', text)
    if m:
        try:
            return float(m.group(1))
        except:
            pass

    # Pattern 2: “7.5/10” or “7.5 out of 10”
    m = re.search(r'([0-9]{1,2}(?:\.\d+)?)\s*(?:/|out of)\s*10', text, re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except:
            pass

    return 0.0
