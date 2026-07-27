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
# AI FEATURE 1: Mission Brief Generation
# ----------------------------------------------------------
def generate_mission_brief(cve_id: str, description: str, cvss_score: float) -> str:
    """Generate a 2-3 sentence mission brief from a CVE."""
    prompt = f"""
You are a cybersecurity trainer. Write a 2-3 sentence mission brief for a training exercise.

Vulnerability: {cve_id}
Description: {description}
CVSS Score: {cvss_score}

Requirements:
- Use plain, everyday language.
- Make it sound urgent but not scary.
- Do not give away attack steps.
- Keep it under 50 words.

Mission Brief:
"""
    return query_ollama(prompt)

# ----------------------------------------------------------
# AI FEATURE 2: Smart Hint (Stuck Detector)
# ----------------------------------------------------------
def generate_hint(task_name: str, current_step: str, user_actions: list) -> str:
    """Generate a hint when the learner is stuck."""
    actions_text = ", ".join(user_actions) if user_actions else "No actions recorded yet"
    
    prompt = f"""
A learner is stuck in a cybersecurity training exercise.

Task: {task_name}
Current Step: {current_step}
What they've tried: {actions_text}

Give ONE specific, actionable hint to help them move forward.
Do NOT give the direct answer – guide their thinking.
Keep it under 30 words.

Hint:
"""
    return query_ollama(prompt)

# ----------------------------------------------------------
# AI FEATURE 3: Report Grading
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
    
    # Try to parse JSON response
    try:
        return json.loads(response)
    except:
        return {"score": 50, "feedback": "Could not parse grade. Please review manually."}

# ----------------------------------------------------------
# AI FEATURE 4: CVE Interestingness Score
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
    
    # Extract the number from the response
    try:
        score = int(response.strip())
        return min(max(score, 1), 10)  # Clamp between 1-10
    except:
        return 5  # Default if parsing fails