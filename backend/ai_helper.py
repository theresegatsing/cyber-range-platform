import requests
import json

# Ollama API endpoint
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3:mini"

def query_ollama(prompt: str) -> str:
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
# AI FEATURE 1: Red Team Mission Brief
# ----------------------------------------------------------
def generate_mission_brief(cve_id: str, description: str, cvss_score: float, asset: str = "the application") -> str:
    """Generate a Red Team mission brief by summarizing the CVE description."""

    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    prompt = f"""
You are a professional cybersecurity trainer writing a MISSION BRIEF for a Red Team exercise.

Write a single paragraph that naturally integrates:
1. What the vulnerability is (based on the description)
2. What the attacker can do (impact)
3. Your objective (what the learner needs to achieve)

DO NOT:
- Mention the CVE number
- Use casual language
- Write as instructions
- Copy the description word-for-word
- Put the asset name in a separate sentence
- Do not have more than 4 phrases in the whole mission brief
- Avoid making it dramatic for nothing

DO:
- Write in second person for the vulnerability description
- Use "Your objective" for the mission goal
- Be specific about the impact
- Integrate everything into one flowing paragraph of 4 phrases

Vulnerability Description: {description}
Asset: {asset}
CVSS Severity: {severity}

Example format (DO NOT COPY – use as style guide):
"The vulnerability resides in the datamodel-code-generator tool, where GraphQL Union description values can inject arbitrary Python code into generated models. Successful exploitation enables attackers to execute malicious code when the models are imported, leading to information exfiltration, credential dumping, and lateral movement across the network. Your objective: exploit the vulnerability to capture the flag."

Now generate a UNIQUE mission brief for this vulnerability:

Mission Brief:
"""
    return query_ollama(prompt)

# ----------------------------------------------------------
# AI FEATURE 2: Blue Team Brief
# ----------------------------------------------------------
def generate_blue_team_brief(cve_id: str, description: str) -> str:
    """Generate a Blue Team mission brief by summarizing the CVE description."""
    
    prompt = f"""
You are a professional cybersecurity trainer writing a Blue Team mission brief.

Write a single sentence that:
1. Explains what the vulnerability is
2. States the Blue Team objective (investigate logs, find traces, write a rule)

Vulnerability Description: {description}

Example format (DO NOT COPY):
"Investigate the logs from the stored XSS attack on OpenCTI. Locate the attack traces and write a detection rule to prevent session theft."

Blue Team Brief:
"""
    return query_ollama(prompt)

# ----------------------------------------------------------
# AI FEATURE 3: Smart Hint (FIXED - Uses CVE Description)
# ----------------------------------------------------------
def generate_hint(task_name: str, current_step: str, user_actions: list, cve_description: str = "") -> str:
    """Generate a hint based on the CVE and what the learner has tried."""
    actions_text = ", ".join(user_actions) if user_actions else "No actions recorded yet"
    
    prompt = f"""
You are a cybersecurity instructor giving a hint to a learner.

The vulnerability is described as:
{cve_description}

The learner is on: {task_name} (Step: {current_step})
They have tried: {actions_text}

Give ONE specific, actionable hint that helps them figure out what to do next.
- Write in DIRECT, ACTIVE voice addressing the learner as "you"
- DO NOT use "encourage", "try to", or "consider"
- DO NOT give away the full answer
- Make it specific to the vulnerability described above
- Keep it under 30 words

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
def score_cve_interestingness(cve_id: str, description: str, cvss_score: float, is_kev: bool) -> int:
    """Score a CVE from 1-10 on how interesting it is for training."""
    kev_text = "Yes, this is actively exploited" if is_kev else "No, not on KEV list"
    
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