import requests
import json

# Ollama API endpoint
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3:mini"

def query_ollama(prompt: str) -> str:
    """Send a prompt to Ollama and get the response."""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            }
        )
        response.raise_for_status()
        return response.json().get("response", "")
    except Exception as e:
        return f"Error: Could not reach Ollama. Make sure it's running. Details: {str(e)}"

# ----------------------------------------------------------
# AI FEATURE 1: Red Team Mission Brief (SMART SUMMARIZATION)
# ----------------------------------------------------------
def generate_mission_brief(cve_id: str, description: str, cvss_score: float) -> str:
    """Generate a Red Team mission brief by summarizing the CVE description."""
    
    # Calculate severity label
    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    prompt = f"""
You are a professional cybersecurity trainer writing a mission brief for a Red Team exercise.

Read the vulnerability description below and summarize it into ONE clear, professional sentence that:
1. Explains what the vulnerability is.
2. States the objective (what the learner needs to do).
3. Does NOT mention the CVE number.
4. Does NOT just repeat the description word-for-word.
5. Sounds professional and urgent but not casual.

Vulnerability Description:
{description}

CVSS Severity: {severity}

Example of a good brief (DO NOT COPY THIS – use it only as a style guide):
"For this mission, you will exploit a stored XSS vulnerability in OpenCTI that allows attackers to steal admin cookies through malicious email-message data. Your objective: execute the attack and capture the flag."

Now generate a UNIQUE mission brief for this vulnerability:

Mission Brief:
"""
    return query_ollama(prompt)

# ----------------------------------------------------------
# AI FEATURE 2: Blue Team Brief (SMART SUMMARIZATION)
# ----------------------------------------------------------
def generate_blue_team_brief(cve_id: str, description: str) -> str:
    """Generate a Blue Team mission brief by summarizing the CVE description."""
    
    prompt = f"""
You are a professional cybersecurity trainer writing a mission brief for a Blue Team exercise.

Read the vulnerability description below and summarize it into ONE clear, professional sentence that:
1. Explains what the vulnerability is.
2. States the Blue Team objective (investigate logs, find traces, write a rule).
3. Does NOT mention the CVE number.
4. Does NOT just repeat the description word-for-word.
5. Sounds professional and clear.

Vulnerability Description:
{description}

Example of a good brief (DO NOT COPY THIS – use it only as a style guide):
"Your mission is to investigate the logs from a stored XSS attack on OpenCTI. You must locate the attack traces in the logs and write a detection rule to prevent session theft."

Now generate a UNIQUE Blue Team mission brief for this vulnerability:

Blue Team Brief:
"""
    return query_ollama(prompt)

# ----------------------------------------------------------
# AI FEATURE 3: Smart Hint (TEMPLATE-BASED)
# ----------------------------------------------------------
def generate_hint(task_name: str, current_step: str, user_actions: list) -> str:
    """Generate a hint using a strict template."""
    actions_text = ", ".join(user_actions) if user_actions else "No actions recorded yet"
    
    prompt = f"""
You are a cybersecurity instructor giving a hint to a learner.

CRITICAL INSTRUCTION: You MUST follow this exact template. Fill in the blanks.

TEMPLATE:
"Next step: [Insert one specific action the learner should try next]."

DO NOT use phrases like "encourage", "try to", or "consider". Write in DIRECT, ACTIVE voice.
DO NOT add any extra text, greetings, or explanations. ONLY return the completed template.

Example of correct output:
"Next step: Test different input values in the username field to identify the vulnerable parameter."

Now generate the hint using the template above.

Task: {task_name}
Current Step: {current_step}
What they've tried: {actions_text}

Hint:
"""
    return query_ollama(prompt)

# ----------------------------------------------------------
# AI FEATURE 4: Report Grading
# ----------------------------------------------------------
def grade_report(learner_report: str, expected_findings: list) -> dict:
    """Grade the learner's report against expected findings."""
    expected_text = ", ".join(expected_findings)
    
    prompt = f"""
You are a cybersecurity instructor grading a learner's incident report.

Learner's Report:
{learner_report}

Expected Findings (what they should have mentioned):
{expected_text}

Score the report from 0-100 based on:
1. Did they mention all expected findings? (70 points)
2. Is their explanation clear and professional? (30 points)

Return ONLY JSON in this exact format:
{{"score": 85, "feedback": "Good job, but you missed..."}}
"""
    response = query_ollama(prompt)
    
    try:
        return json.loads(response)
    except:
        return {"score": 50, "feedback": "Could not parse grade. Please review manually."}

# ----------------------------------------------------------
# AI FEATURE 5: CVE Interestingness Score
# ----------------------------------------------------------
def score_cve_interestingness(cve_id: str, description: str, cvss_score: float, kev_status: bool) -> int:
    """Score a CVE from 1-10 on how interesting it is for training."""
    kev_text = "Yes, this is actively exploited" if kev_status else "No, not on KEV list"
    
    prompt = f"""
You are a cybersecurity trainer choosing which vulnerabilities to turn into training missions.

CVE: {cve_id}
Description: {description}
CVSS Score: {cvss_score}
On KEV (actively exploited): {kev_text}

Score this CVE from 1-10 on how INTERESTING it would be for a training mission.
- 10 = Critical, actively exploited, complex attack
- 1 = Boring, low risk, simple

Return ONLY a number between 1 and 10.
Score:
"""
    response = query_ollama(prompt)
    
    try:
        score = int(response.strip())
        return min(max(score, 1), 10)
    except:
        return 5