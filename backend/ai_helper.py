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
You are a professional cybersecurity trainer writing a BLUE TEAM MISSION BRIEF.

Write a single paragraph that:
1. Explains what the vulnerability is
2. States the Blue Team objective: investigate Splunk logs to find attack traces
3. Explicitly mentions using Splunk log analysis
4. States they must write a detection rule

Vulnerability Description: {description}

IMPORTANT REQUIREMENTS:
- MUST mention Splunk log analysis
- MUST mention writing a detection rule
- Be professional and clear
- Do NOT mention the CVE number
- Do not have more than 4 phrases in the whole mission brief

Example format (DO NOT COPY – use as style guide):
"Your mission is to investigate the Splunk logs from the stored XSS attack on OpenCTI. You must locate the attack traces in the Splunk logs and write a detection rule to prevent session theft. Use Splunk search queries to identify the malicious payload and the affected users."

Now generate a UNIQUE Blue Team mission brief for this vulnerability that includes Splunk log analysis:

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


#-----
# generate_command_suggestion
#-----
def generate_command_suggestion(goal: str, current_step: str, cve_description: str = "") -> str:
    """Suggest the exact simulated-terminal command that matches the learner's stated goal."""
    prompt = f"""
You are helping a learner in a cybersecurity training simulator.

The simulator's terminal ONLY understands this fixed set of command patterns:
- nmap <target>              -> runs reconnaissance, reveals open ports
- curl "<url>?id=1 OR 1=1"   -> attempts a SQL injection style request against the target
- cat brief                  -> reprints the mission brief
- index=main <search terms>  -> searches Splunk logs (Blue Team phase only)
- help                       -> lists available commands
- clear                      -> clears the terminal

The learner is on: {current_step}
Vulnerability context: {cve_description}
The learner describes their goal in their own words: "{goal}"

Based ONLY on the commands listed above, tell them the exact command to type next.
- Give ONE command, on its own line, exactly as they should type it
- Add one short sentence explaining what it does
- Do NOT invent commands or flags outside the list above
- Keep the whole response under 40 words

Command:
"""
    return query_ollama(prompt)


VULN_PATTERNS = ["sql_injection", "command_injection", "path_traversal", "reflected_xss"]

#------
# classify vulnerability pattern
#------

def classify_vulnerability_pattern(cve_id: str, description: str) -> str:
    """Map a CVE to the closest supported vulnerability template class, or 'unsupported' if none fit."""
    prompt = f"""
You are classifying a CVE into ONE vulnerability category for a training simulator.

CVE: {cve_id}
Description: {description}

Choose exactly ONE from this list (respond with ONLY the exact string, nothing else):
{', '.join(VULN_PATTERNS)}, unsupported

Only pick one of the specific categories if the CVE's actual exploitation mechanism
genuinely matches it. If the CVE is about something else entirely (auth bypass,
deserialization, SSRF, race conditions, misconfiguration, etc. that doesn't match
any category above), respond with exactly: unsupported

Category:
"""
    response = query_ollama(prompt).strip().lower()
    for pattern in VULN_PATTERNS:
        if pattern in response:
            return pattern
    return "unsupported"



#-----
# generate_template_params
#----
def generate_template_params(pattern: str, cve_id: str, description: str) -> dict:
    """Fill CVE-specific flavor text into a template (table names, error strings, etc)."""
    prompt = f"""
You are customizing a {pattern} training lab to match a specific CVE.

CVE: {cve_id}
Description: {description}

Return ONLY JSON with these exact keys (invent realistic, CVE-appropriate values):
{{"table_name": "...", "column_names": ["...", "..."], "app_title": "...", "sample_row_1": "...", "sample_row_2": "..."}}
"""
    response = query_ollama(prompt)
    try:
        return json.loads(response)
    except Exception:
        return {
            "table_name": "users", "column_names": ["id", "username", "secret"],
            "app_title": f"{cve_id} Training Lab",
            "sample_row_1": "1, admin, secretpass", "sample_row_2": "2, john, doe123"
        }