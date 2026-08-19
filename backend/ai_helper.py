import requests
import json
import secrets

# Ollama API endpoint
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3:mini"

def query_ollama(prompt: str, timeout: int = 120, json_mode: bool = False) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "30m",
        "options": {"num_predict": 300, "temperature": 0.4 if json_mode else 0.7},
    }
    if json_mode:
        payload["format"] = "json"
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json().get("response", "")
    except requests.exceptions.Timeout:
        return ""
    except Exception as e:
        print(f"[OLLAMA ERROR] {e}")
        return ""
    
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
def generate_hint(task_name: str, current_step: str, user_actions: list,
                  cve_description: str = "", target_activity: list = None,
                  lab_info: dict = None) -> str:
    """Hint informed by BOTH terminal commands and real requests hitting the container."""
    actions_text = ", ".join(user_actions) if user_actions else "nothing yet"
    activity = target_activity or []
    activity_text = "\n".join(f"  {a}" for a in activity[-8:]) if activity else "  (no requests yet)"

    lab = lab_info or {}
    lab_text = ""
    if lab.get("endpoint"):
        lab_text = (f"The lab exposes /{lab['endpoint']} taking a "
                    f"'{lab.get('param_name', 'input')}' parameter.")

    prompt = f"""
You are a cybersecurity instructor guiding a learner through a hands-on lab.

Vulnerability: {cve_description}
{lab_text}

The learner is on: {task_name} ({current_step})
Terminal commands they typed: {actions_text}
Actual HTTP requests that reached the target:
{activity_text}

Give ONE specific next action, based on what they have ALREADY tried.
- If they have sent no requests, tell them to explore the target's main page first.
- If they are sending normal requests, nudge them toward modifying the parameter.
- If they are close (partial payload), refine it — do not restate what worked.
- Address them as "you", under 30 words, no preamble.
- Never reveal the full winning payload.
- Structure every hint as: the technique + where to apply it.
  Good: "The viewer joins your input onto a base directory — feed it a path that
  climbs out of that directory instead of a filename."
  Bad: "try sessionId=to_exploit" (a placeholder value teaches nothing).
- Name the parameter only alongside the technique, never alone.
- If their requests show identical responses to different inputs, tell them the
  parameter name is likely wrong and to re-read the page source.

Hint:
"""
    return query_ollama(prompt) or "Explore the target's main page, then try altering the parameter value."



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




import re

# Each pattern declares the keys its template needs, plus safe fallbacks.
PATTERN_SCHEMAS = {
    "path_traversal": {
        "keys": {
            "app_title":    "Document Viewer Lab",
            "asset_name":   "the file service",
            "endpoint":     "vuln",
            "param_name":   "file",
            "public_file":  "readme.txt",
            "secret_file":  "secret.txt",
        },
        "hint": ("endpoint = the vulnerable route name from the CVE (no slash). "
                 "param_name = the exact query/argument name the CVE says is manipulated. "
                 "public_file = a harmless document name. "
                 "secret_file = a plausible confidential filename the attacker would target."),
    },
    "sql_injection": {
        "keys": {
            "app_title":    "Vulnerable App",
            "asset_name":   "the application",
            "endpoint":     "vuln",
            "param_name":   "id",
            "table_name":   "users",
            "column_names": ["id", "username", "secret"],
            "sample_row_1": "1, admin, secretpass",
            "sample_row_2": "2, john, doe123",
        },
        "hint": ("table_name and column_names should reflect the data the CVE exposes. "
                 "param_name = the injectable parameter named in the CVE."),
    },
    "command_injection": {
        "keys": {
            "app_title":  "Diagnostics Console",
            "asset_name": "the admin utility",
            "endpoint":   "vuln",
            "param_name": "host",
            "base_command": "ping -c 1",
        },
        "hint": "base_command = the shell command the app legitimately runs with user input appended.",
    },
    "reflected_xss": {
        "keys": {
            "app_title":  "Search Portal",
            "asset_name": "the web interface",
            "endpoint":   "vuln",
            "param_name": "q",
        },
        "hint": "param_name = the parameter reflected unsanitized into the response.",
    },
}

IDENT_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]{0,31}$')
FILE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$')


def _clean_text(v, fallback, maxlen=60):
    if not isinstance(v, str):
        return fallback
    v = v.replace("{", "").replace("}", "").replace('"', "'").strip()
    v = " ".join(v.split())
    return v[:maxlen] if v else fallback


def _sanitize(pattern: str, params: dict) -> dict:
    """Values are injected into generated Python source — they must be tightly constrained."""
    schema = PATTERN_SCHEMAS[pattern]["keys"]
    out = {}
    for key, default in schema.items():
        val = params.get(key)

        if key == "column_names":
            if isinstance(val, str):
                val = [c.strip() for c in val.split(",")]
            if not isinstance(val, list) or not val:
                val = default
            val = [c for c in (str(c).strip() for c in val) if IDENT_RE.match(c)]
            out[key] = val or default

        elif key in ("endpoint", "param_name", "table_name"):
            v = str(val).strip().strip('/') if val else ""
            out[key] = v if IDENT_RE.match(v) else default

        elif key in ("public_file", "secret_file"):
            v = str(val).strip().lstrip('./') if val else ""
            out[key] = v if FILE_RE.match(v) else default

        else:
            out[key] = _clean_text(val, default)

    return out


def generate_template_params(pattern: str, cve_id: str, description: str) -> dict:
    """Fill CVE-specific flavor into a pattern's template. Never raises."""
    if pattern not in PATTERN_SCHEMAS:
        return {}

    schema = PATTERN_SCHEMAS[pattern]
    example = json.dumps({k: (v if not isinstance(v, list) else v) for k, v in schema["keys"].items()})

    prompt = f"""
You are customizing a {pattern} training lab so it mirrors a specific real CVE.

CVE: {cve_id}
Description: {description}

Return ONLY a JSON object with exactly these keys, no prose, no markdown fences:
{example}

Guidance: {schema["hint"]}

Rules:
- Draw names DIRECTLY from the CVE description wherever it names an endpoint,
  parameter, table, column, or file. If the description names a parameter, use it verbatim.
- endpoint, param_name and table_name must be single words: letters, digits, underscores only.
- public_file and secret_file must be plain filenames like "notes.txt" — no slashes, no dots-dot.
- app_title should read like a real product screen, under 50 characters.
- Invent plausible values only for what the description does not specify.

JSON:
"""
    raw = query_ollama(prompt, json_mode=True)
    print(f"[PARAMS RAW] {pattern}: {raw[:300]}")
    parsed = {}
    try:
        # models love wrapping JSON in fences or chatter — grab the first object
        m = re.search(r'\{.*\}', raw, re.S)
        if m:
            parsed = json.loads(m.group(0))
    except Exception:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}

    parsed.update(_seed_from_description(description))   # CVE text overrides the model
    params = _sanitize(pattern, parsed)

    FLAG_TEXT = {
        "path_traversal":    "you escaped the document directory and read a protected file",
        "sql_injection":     "you bypassed the query filter and dumped the table",
        "command_injection": "you chained a shell command through the input",
        "reflected_xss":     "your payload was reflected unsanitized into the response",
    }

    params = _sanitize(pattern, parsed)

    params["cve_id"] = cve_id
    params["flag_token"] = secrets.token_hex(8)
    params["flag_reason"] = {
        "path_traversal":    "you escaped the document directory and read a protected file",
        "sql_injection":     "you bypassed the query filter and dumped the table",
        "command_injection": "you chained a shell command through the input",
        "reflected_xss":     "your payload was reflected unsanitized into the response",
    }.get(pattern, "exploited successfully")
    return params


def _seed_from_description(description: str) -> dict:
    """Extract identifiers the CVE text states outright. Beats the model every time."""
    seed = {}
    m = re.search(r"\b([A-Za-z_]\w*)\s+(?:argument|parameter|param|field)\b", description, re.I)
    if m and IDENT_RE.match(m.group(1)):
        seed["param_name"] = m.group(1)
    m = re.search(r"\b([A-Za-z_]\w*)\s+function\b", description, re.I)
    if m and IDENT_RE.match(m.group(1)):
        seed["endpoint"] = m.group(1)
    m = re.search(r"\b(?:table|relation)\s+[`'\"]?([A-Za-z_]\w*)", description, re.I)
    if m and IDENT_RE.match(m.group(1)):
        seed["table_name"] = m.group(1)
    return seed



