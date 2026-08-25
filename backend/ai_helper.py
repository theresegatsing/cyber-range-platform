import requests
import json
import secrets
import re as _re

# Ollama API endpoint
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3:mini"

def query_ollama(prompt: str, timeout: int = 120, json_mode: bool = False,
                 stop: list = None) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "30m",
        "options": {
            "num_predict": 300 if not json_mode else 300,
            "temperature": 0.4 if json_mode else 0.7,
        },
    }
    if stop:
        payload["options"]["stop"] = stop
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

BRIEF_JUNK = _re.compile(
    r'^\s*(mission brief|brief|red team brief|blue team brief|output|response|answer)\s*:\s*',
    _re.I)

BRIEF_CUTOFF = _re.compile(
    r'(?:\n\s*-{3,}|\n\s*(?:mission brief|write a|now generate|instructions?|'
    r'constraints?|example format|task|note)\s*:|\n\s*\d\.\s)', _re.I)


def _clean_brief(text: str) -> str:
    """Strip prompt echo, leading labels, and any continuation the model invented."""
    if not text:
        return ""
    t = text.strip()

    # cut everything from the first sign the model started a new document
    m = BRIEF_CUTOFF.search(t)
    if m:
        t = t[:m.start()]

    # drop repeated leading labels ("Mission Brief: Mission Brief: ...")
    for _ in range(3):
        new = BRIEF_JUNK.sub("", t).strip()
        if new == t:
            break
        t = new

    t = t.strip().strip('"').strip()

    # keep only the first paragraph
    t = t.split("\n\n")[0].strip()

    # cap at 5 sentences — the prompt asks for 4
    sentences = _re.split(r'(?<=[.!?])\s+', t)
    if len(sentences) > 5:
        t = " ".join(sentences[:5])

    return t

def _looks_broken(text: str) -> bool:
    if not text or len(text) < 40:
        return True
    low = text.lower()
    tells = ["write a mission brief", "your task is to write", "constraints:",
             "instructions:", "example format", "do not:", "flag name",
             "the brief must", "now generate"]
    return any(t in low for t in tells)



_VOWELS = set("aeiouy")


def _is_gibberish(text: str) -> bool:
    """
    Structural check only — no vocabulary list, no topic assumptions.
    Detects keyboard-mashing. Deliberately conservative: when unsure, says no.
    """
    if not isinstance(text, str):
        return True
    t = text.strip()
    if len(t) < 15:
        return True

    words = _re.findall(r"[A-Za-z']{1,}", t)
    if len(words) < 4:
        return True

    lower = [w.lower() for w in words]
    letters = "".join(lower)
    if not letters:
        return True

    signals = 0

    # 1. Every English word has a vowel (bar a handful like "hmm", "nth").
    #    Mashing produces long vowel-free strings.
    vowelless = sum(1 for w in lower if len(w) >= 4 and not (_VOWELS & set(w)))
    if vowelless >= 2 or vowelless / len(lower) > 0.25:
        signals += 1

    # 2. Overall vowel ratio. English prose sits around 0.35-0.42.
    ratio = sum(1 for c in letters if c in _VOWELS) / len(letters)
    if ratio < 0.22 or ratio > 0.62:
        signals += 1

    # 3. Consonant runs. English tops out near 4 ("strengths"); mashing goes further.
    if _re.search(r"[bcdfghjklmnpqrstvwxz]{6,}", letters):
        signals += 1

    # 4. Home-row bias — asdf/jkl; dominate real text only when mashed.
    home = sum(1 for c in letters if c in "asdfghjkl")
    if home / len(letters) > 0.72:
        signals += 1

    # 5. Repeated identical tokens ("test test test test").
    uniq = len(set(lower)) / len(lower)
    if len(lower) >= 4 and uniq < 0.5:
        signals += 1
    if len(lower) >= 6 and uniq < 0.3:
        signals += 1   # severe repetition counts twice

    # 6. No sentence-like structure at all: no spaces in a long string.
    if len(t) > 40 and " " not in t.strip():
        signals += 1

    # two independent signals before rejecting
    return signals >= 2


# ----------------------------------------------------------
# AI FEATURE 1: Red Team Mission Brief
# ----------------------------------------------------------
def generate_mission_brief(cve_id: str, description: str, cvss_score: float,
                           asset: str = "the application") -> str:
    """Generate a Red Team mission brief. Falls back to a deterministic brief on failure."""

    if cvss_score >= 9.0:
        severity = "critical"
    elif cvss_score >= 7.0:
        severity = "high"
    elif cvss_score >= 4.0:
        severity = "medium"
    else:
        severity = "low"

    prompt = f"""You are a cybersecurity trainer writing a mission brief for a Red Team lab exercise.

Vulnerability description: {description}
Affected asset: {asset}
Severity: {severity}

Write ONE paragraph of at most four sentences that covers, in order:
- what the vulnerability is, in your own words
- what an attacker gains by exploiting it
- the learner's goal, phrased as "Your objective: ..."

Rules:
- Do not mention any CVE number.
- Do not copy the description verbatim.
- Do not write headings, lists, labels, or instructions.
- Do not add anything after the paragraph.
- Write plainly. No drama, no hype.

Paragraph:"""

    for attempt in range(2):
        raw = query_ollama(prompt, stop=[
            "\n\n", "Paragraph:", "Mission Brief:", "---",
            "Write a", "Now generate", "Rules:", "Vulnerability description:",
            "Instructions:", "Constraints:",
        ])
        brief = _clean_brief(raw)
        if not _looks_broken(brief):
            return brief
        print(f"[BRIEF] Retry {attempt + 1} for {cve_id} — model echoed the prompt")

    # deterministic fallback — plain but always correct
    summary = description.strip().rstrip('.')
    if len(summary) > 220:
        summary = summary[:220].rsplit(' ', 1)[0] + '…'
    return (f"A {severity}-severity vulnerability affects {asset}. {summary}. "
            f"Your objective: exploit this flaw in the lab environment and capture the flag.")

# ----------------------------------------------------------
# AI FEATURE 2: Blue Team Brief
# ----------------------------------------------------------
def generate_blue_team_brief(cve_id: str, description: str,
                             asset: str = "the application") -> str:
    """Generate a Blue Team mission brief. Falls back to a deterministic brief on failure."""

    prompt = f"""You are a cybersecurity trainer writing a Blue Team brief for a lab exercise.

Vulnerability description: {description}

Write ONE paragraph of at most four sentences that covers, in order:
- what the attacker exploited, in your own words
- the goal: investigate the Splunk logs to locate the attack traces
- the deliverable: write a rule that would block or detect this technique

Rules:
- Mention Splunk log analysis explicitly.
- Mention writing the rule explicitly.
- Do not mention any CVE number.
- Do not copy the description verbatim.
- Do not write headings, lists, labels, or instructions.
- Do not add anything after the paragraph.
- Write plainly. No drama, no hype.

Paragraph:"""

    for attempt in range(2):
        raw = query_ollama(prompt, stop=[
            "\n\n", "Paragraph:", "Blue Team Brief:", "Mission Brief:", "---",
            "Write a", "Now generate", "Rules:", "Vulnerability description:",
            "Instructions:", "Constraints:",
        ])
        brief = _clean_brief(raw)
        if not _looks_broken(brief) and "splunk" in brief.lower():
            return brief
        print(f"[BLUE BRIEF] Retry {attempt + 1} for {cve_id} — output rejected")

    # deterministic fallback — plain but always correct
    return (f"An attacker successfully exploited a vulnerability in {asset} and "
            f"retrieved data they should not have been able to reach. Your objective: "
            f"search the Splunk logs to find the requests that carried out the attack, "
            f"then write a rule that would block that technique in future.")

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
    return _clean_brief(query_ollama(
            prompt,
            stop=["\n\n", "Mission Brief:", "---", "Write a", "Now generate",
                  "Example format", "Vulnerability Description:", "Instructions:"]
        )) or "Explore the target's main page, then try altering the parameter value."



# ----------------------------------------------------------
# AI FEATURE 4: Report Grading
# ----------------------------------------------------------
def grade_report(attack: str = "", detection: str = "", rule: str = "",
                 recommendations: str = "", cve_id: str = "", pattern: str = "",
                 payload: str = "") -> dict:
    """Grade an incident report section by section. Empty sections score zero."""

    provided = {
        "attack": not _is_gibberish(attack),
        "detection": not _is_gibberish(detection),
        "rule": len(rule.strip()) >= 3,
        "recommendations": not _is_gibberish(recommendations),
    }

    if not any(provided.values()):
        return {"score": 0, "sections": {k: 0 for k in provided},
                "strengths": [], "improvements": ["Complete the report before submitting."],
                "feedback": "No sections were completed."}

    learner_report = (
        f"1. ATTACK DESCRIPTION\n{attack or '(not provided)'}\n\n"
        f"2. DETECTION METHOD\n{detection or '(not provided)'}\n\n"
        f"3. BLOCKING RULE\n{rule or '(not provided)'}\n\n"
        f"4. RECOMMENDATIONS\n{recommendations or '(not provided)'}"
    )

    prompt = f"""
You are a SOC lead grading a junior analyst's incident report.

CVE: {cve_id or 'unspecified'}
Vulnerability class: {pattern or 'unspecified'}
The attack they performed: {payload or 'not recorded'}
The blocking rule they deployed and verified: {rule or 'none'}

Their report:
{learner_report}

Grade four sections out of 25 each:
1. Attack Description — do they explain the mechanism, not just restate the payload?
2. Detection Method — do they describe how it was found in the logs?
3. Blocking Rule — is the rule sound, and do they explain what it matches?
4. Recommendations — do they propose a real fix (input validation, canonicalisation,
   least privilege) rather than only the WAF rule?

Any section marked "(not provided)" scores 0.
Be fair but not generous.

Return ONLY JSON:
{{"score": 78,
  "sections": {{"attack": 20, "detection": 18, "rule": 22, "recommendations": 18}},
  "strengths": ["one specific thing done well"],
  "improvements": ["one specific, actionable gap"],
  "feedback": "two sentences of overall assessment"}}
"""
    raw = query_ollama(prompt, json_mode=True)
    try:
        m = _re.search(r'\{.*\}', raw, _re.S)
        data = json.loads(m.group(0)) if m else {}
    except Exception:
        data = {}

    if not isinstance(data, dict) or "score" not in data:
        base = 60 if all(provided.values()) else 40
        data = {"score": base, "sections": {}, "strengths": [], "improvements": [],
                "feedback": "Automated grading was unavailable. Review this report manually."}

    sections = data.get("sections") or {}
    for key, filled in provided.items():
        try:
            val = int(sections.get(key, 0))
        except Exception:
            val = 0
        sections[key] = 0 if not filled else max(0, min(25, val))

    data["sections"] = sections
    data["score"] = min(int(data.get("score", 0) or 0), sum(sections.values()))
    data["score"] = max(0, min(100, data["score"]))
    for k in ("strengths", "improvements"):
        v = data.get(k)
        data[k] = v if isinstance(v, list) else ([str(v)] if v else [])
    data["feedback"] = str(data.get("feedback", ""))[:600]

    missing = [k for k, f in provided.items() if not f]
    if missing:
        data["improvements"].insert(0, "Incomplete sections scored zero: " + ", ".join(missing) + ".")
    return data

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
def generate_command_suggestion(goal: str, current_step: str, cve_description: str = "",
                                lab: dict = None) -> str:
    lab = lab or {}
    surface = ""
    if lab.get("endpoint"):
        surface = (f"\nThe target exposes /{lab['endpoint']} taking a "
                   f"'{lab.get('param_name', 'input')}' parameter. "
                   f"A known-good value is '{lab.get('public_file', 'default')}'.")

    prompt = f"""
You are helping a learner in a hands-on cybersecurity lab.

The terminal sends REAL HTTP requests to a live vulnerable container.
Available commands:
- nmap <target>            reconnaissance; reveals the open HTTP service
- curl "/path?param=value" sends a real GET request and prints the response
- source /path             prints raw HTML source, revealing form field names
- lab                      prints the target's endpoint and parameter name
- open /path               loads a path in the Target browser tab
- history                  lists requests that reached the target
- cat brief                reprints the mission brief
- hint                     asks the instructor for guidance
- clear, help, next

Vulnerability context: {cve_description}{surface}
The learner is on: {current_step}
Their stated goal: "{goal}"

Give exactly ONE command from the list above, on its own line, ready to type.
Then one short sentence explaining what it does.
Never invent commands or flags. Never give a complete working exploit payload —
if they are asking how to exploit, suggest the reconnaissance step that reveals it.
Under 40 words total.

Command:
"""
    return query_ollama(prompt) or 'curl "/"\nFetch the main page to see what the target exposes.'

VULN_PATTERNS = [
    "path_traversal",
    "nosql_injection",
    "sql_injection",
    "command_injection",
    "reflected_xss",
    "ssrf",
    "ssti",
    "xxe",
    "privilege_escalation",
    "idor",
    "open_redirect",
    "auth_bypass",
]

#------
# classify vulnerability pattern
#------

def classify_vulnerability_pattern(cve_id: str, description: str) -> str:
    prompt = f"""
You are classifying a CVE into ONE vulnerability category for a training simulator.

CVE: {cve_id}
Description: {description}

Choose exactly ONE from this list (respond with ONLY the exact string, nothing else):
{', '.join(VULN_PATTERNS)}, unsupported

Only pick a specific category if the CVE's actual exploitation mechanism genuinely
matches it. Notes on the trickier ones:
- nosql_injection is for document stores (MongoDB and similar), sql_injection for relational
- idor is unauthorised access to another user's object by changing an identifier;
  privilege_escalation is gaining a higher role than you were granted
- ssrf is the server fetching a URL you supply; open_redirect is the browser being sent elsewhere
- ssti is input evaluated as template code; reflected_xss is input rendered as markup

If it's something else entirely (deserialization, race conditions, memory corruption,
misconfiguration, cryptographic weakness), respond with exactly: unsupported

Category:
"""
    response = query_ollama(prompt).strip().lower()

    # exact match first — "sql_injection" is a substring of "nosql_injection"
    for pattern in VULN_PATTERNS:
        if response == pattern:
            return pattern

    # then longest-first substring match, so the more specific name wins
    for pattern in sorted(VULN_PATTERNS, key=len, reverse=True):
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
    "ssrf": {
        "keys": {"app_title": "URL Preview Service", "asset_name": "the fetch service",
                 "endpoint": "fetch", "param_name": "url", "public_file": "http://example.com",
                 "secret_file": "metadata"},
        "hint": "param_name = the parameter accepting a URL.",
    },
    "privilege_escalation": {
        "keys": {"app_title": "Account Portal", "asset_name": "the user service",
                 "endpoint": "profile", "param_name": "role", "public_file": "user",
                 "secret_file": "admin"},
        "hint": "param_name = the field controlling privilege level.",
    },
    "idor": {
        "keys": {"app_title": "Records Portal", "asset_name": "the records API",
                 "endpoint": "record", "param_name": "id", "public_file": "1",
                 "secret_file": "99"},
        "hint": "param_name = the object identifier the user can change.",
    },
    "ssti": {
        "keys": {"app_title": "Greeting Service", "asset_name": "the template renderer",
                 "endpoint": "greet", "param_name": "name", "public_file": "world",
                 "secret_file": "config"},
        "hint": "param_name = the value rendered into a template.",
    },
    "xxe": {
        "keys": {"app_title": "XML Import Tool", "asset_name": "the import service",
                 "endpoint": "import", "param_name": "xml", "public_file": "<doc>hi</doc>",
                 "secret_file": "secret.txt"},
        "hint": "param_name = the parameter accepting XML.",
    },
    "open_redirect": {
        "keys": {"app_title": "Link Router", "asset_name": "the redirect handler",
                 "endpoint": "go", "param_name": "next", "public_file": "/home",
                 "secret_file": "external"},
        "hint": "param_name = the redirect destination parameter.",
    },
    "auth_bypass": {
        "keys": {"app_title": "Admin Console", "asset_name": "the auth layer",
                 "endpoint": "admin", "param_name": "token", "public_file": "guest",
                 "secret_file": "admin"},
        "hint": "param_name = the parameter checked for authorization.",
    },
    "nosql_injection": {
        "keys": {"app_title": "User Lookup", "asset_name": "the document store",
                 "endpoint": "find", "param_name": "username", "public_file": "john",
                 "secret_file": "admin"},
        "hint": "param_name = the queried field.",
    },

}

PATTERN_EXPLAINERS = {
    "path_traversal": {
        "name": "Path Traversal",
        "plain": "The app builds a file path from your input without checking it. "
                 "By climbing out of the intended folder you can read files you shouldn't.",
        "look_for": "A parameter that names a file or document.",
        "then_try": "Feed it a path that escapes the folder, or an absolute path to a known file.",
    },
    "sql_injection": {
        "name": "SQL Injection",
        "plain": "Your input is pasted straight into a database query. Add your own SQL "
                 "and the database runs it as if the application wrote it.",
        "look_for": "A parameter used to look up a record.",
        "then_try": "Break out of the quoted value and add a condition that's always true.",
    },
    "command_injection": {
        "name": "Command Injection",
        "plain": "The app runs a shell command with your input appended. Shell "
                 "metacharacters let you chain a second command of your own.",
        "look_for": "A parameter feeding a system utility like ping or lookup.",
        "then_try": "End the intended command and start another one.",
    },
    "reflected_xss": {
        "name": "Reflected Cross-Site Scripting",
        "plain": "Your input is written back into the page unsanitised, so markup you "
                 "send becomes part of the page and executes in the victim's browser.",
        "look_for": "A parameter echoed back in the response.",
        "then_try": "Send markup instead of plain text and see if it renders.",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "plain": "You supply a URL and the SERVER fetches it, not your browser. Because "
                 "the server sits inside the network, it can reach internal services you can't.",
        "look_for": "A parameter accepting a URL or address.",
        "then_try": "Point it inward — at the server itself or an internal address.",
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "plain": "The app decides what you're allowed to do based on a value you control. "
                 "Change the value, gain the permissions.",
        "look_for": "A parameter naming a role, level, or account type.",
        "then_try": "Claim a higher-privileged role than the one you were given.",
    },
    "idor": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "plain": "The app fetches a record by the ID you pass in, without checking the "
                 "record belongs to you. Change the ID, read someone else's data.",
        "look_for": "A numeric or sequential identifier in the request.",
        "then_try": "Change the ID to one you were never shown.",
    },
    "ssti": {
        "name": "Server-Side Template Injection (SSTI)",
        "plain": "Your input is treated as template code rather than text, so the server "
                 "evaluates it. Expressions you send get calculated and returned.",
        "look_for": "A parameter inserted into a rendered message.",
        "then_try": "Send an arithmetic expression in template syntax and see if it's evaluated.",
    },
    "xxe": {
        "name": "XML External Entity (XXE)",
        "plain": "XML documents can declare entities that pull in external files. A parser "
                 "that allows this will read local files and return their contents.",
        "look_for": "A parameter accepting XML.",
        "then_try": "Declare an entity pointing at a local file and reference it in the document.",
    },
    "open_redirect": {
        "name": "Open Redirect",
        "plain": "The app redirects to whatever destination you supply. Attackers use it "
                 "to make malicious links look like they come from a trusted site.",
        "look_for": "A parameter naming where to go next.",
        "then_try": "Supply an external destination instead of an internal path.",
    },
    "auth_bypass": {
        "name": "Authentication Bypass",
        "plain": "The check that's supposed to prove who you are can be satisfied with a "
                 "value you can guess, forge, or simply omit.",
        "look_for": "A token or flag the app trusts.",
        "then_try": "Supply the privileged value, or remove the parameter entirely.",
    },
    "nosql_injection": {
        "name": "NoSQL Injection",
        "plain": "Document databases accept query operators as data. If your input becomes "
                 "part of the query structure, you can make it match everything.",
        "look_for": "A lookup field on a document store.",
        "then_try": "Send a query operator instead of a plain value.",
    },
}


def get_pattern_explainer(pattern: str) -> dict:
    return PATTERN_EXPLAINERS.get(pattern, {
        "name": "Unclassified",
        "plain": "This vulnerability doesn't map to a lab template yet. "
                 "Study the description and write up your analysis.",
        "look_for": "—", "then_try": "—",
    })

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


    params["cve_id"] = cve_id
    params["flag_token"] = secrets.token_hex(8)
    params["flag_reason"] = {
        "path_traversal":     "you escaped the document directory and read a protected file",
        "sql_injection":      "you bypassed the query filter and dumped the table",
        "command_injection":  "you chained a shell command through the input",
        "reflected_xss":      "your payload was reflected unsanitized into the response",
        "ssrf":               "you made the server fetch an internal resource on your behalf",
        "privilege_escalation": "you claimed a role you were never granted",
        "idor":               "you read a record belonging to someone else",
        "ssti":               "your input was evaluated as template code by the server",
        "xxe":                "your XML entity pulled a local file off the server",
        "open_redirect":      "you redirected the application to an external destination",
        "auth_bypass":        "you reached a protected area without valid credentials",
        "nosql_injection":    "your query operator matched every document in the store",
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



