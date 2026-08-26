# Purple-Team Cyber Range Platform

Turns a vulnerability scanner's daily findings into hands-on attack-and-defense labs,
automatically, one lab per CVE.

A learner exploits a real vulnerable container, finds their own attack in Splunk,
writes a blocking rule, and the platform **redeploys the target and replays their
attack** to prove whether the rule actually holds. Then it grades the write-up and
produces a PDF incident report.

Learners need nothing installed — just a browser and a URL.

---

## Table of contents

1. [What the platform does](#1-what-the-platform-does)
2. [Architecture](#2-architecture)
3. [The mission lifecycle](#3-the-mission-lifecycle)
4. [Technology choices and why](#4-technology-choices-and-why)
5. [Repository layout](#5-repository-layout)
6. [Setting up a new machine](#6-setting-up-a-new-machine)
7. [Multi-user access and deployment](#7-multi-user-access-and-deployment)
8. [Splunk setup](#8-splunk-setup)
9. [Configuration reference](#9-configuration-reference)
10. [Running the platform](#10-running-the-platform)
11. [The vulnerability template system](#11-the-vulnerability-template-system)
12. [The learner's terminal](#12-the-learners-terminal)
13. [The blocking-rule replay loop](#13-the-blocking-rule-replay-loop)
14. [API reference](#14-api-reference)
15. [AI features](#15-ai-features)
16. [Operations and maintenance](#16-operations-and-maintenance)
17. [Troubleshooting](#17-troubleshooting)
18. [Known limitations](#18-known-limitations)
19. [Demo video](#19-demo-video)
20. [Development history](#20-development-history)

---

## 1. What the platform does

Most security training runs on generic labs — DVWA, WebGoat, a decade-old teaching
app. Teams then go and defend against vulnerabilities specific to their own stack.
This platform closes that gap: it reads the CVEs **your own scanner found this week**
and builds a working lab for each one.

Every mission has four phases:

| Phase | What the learner does | What the platform verifies |
|-------|----------------------|---------------------------|
| 1. Reconnaissance | Scans the target, reads the page source, finds the vulnerable parameter | Real HTTP requests reach a real container |
| 2. Exploit (Red Team) | Crafts a payload that retrieves a protected secret | The container returns a per-mission flag token — no string matching on the learner's input |
| 3. Investigate (Blue Team) | Finds the attack traces in Splunk | The container's own stdout/stderr is forwarded to Splunk by the Docker log driver |
| 4. Defend + report | Writes a blocking regex, then documents the incident | The rule is **deployed and the attack is replayed**; the report is graded section by section |

The verification in phase 4 is the part that distinguishes this from a quiz. A rule
isn't marked correct because a model approves of it — it's marked correct because
the exact request that captured the flag now returns 403, while legitimate traffic
still returns 200.

---

## 2. Architecture

```
┌────────────────────────┐
│ Vulnerability Scanner  │   (external, read-only SQLite)
│ vulnerability_mgmt.db  │
└───────────┬────────────┘
            │  scanner_import.py  (daily / on demand)
            ▼
┌────────────────────────┐        ┌─────────────────────┐
│ PostgreSQL             │◄──────►│ Ollama (phi3:mini)  │
│ platform_vulnerabilities│        │ scoring, briefs,    │
│ missions               │        │ classification,     │
└───────────┬────────────┘        │ hints, grading      │
            │                     └─────────────────────┘
            ▼
┌─────────────────────────────────────────────────────────┐
│ FastAPI backend  (backend/main.py)  :8000               │
│  • serves the frontend to every learner's browser       │
│  • streams mission build progress over SSE              │
│  • proxies learner traffic to the target container      │
│  • redeploys targets with a WAF rule and replays attacks│
│  • grades reports, renders PDFs                         │
└───────┬─────────────────────────────────┬───────────────┘
        │ Docker SDK                      │ HTTP
        ▼                                 ▼
┌──────────────────────────┐    ┌──────────────────────┐
│ mission-<id>-<session>   │    │ Splunk HEC :8088     │
│ one container per learner│───►│ index=cyber_range    │
│ Flask lab built per CVE  │    │ Splunk Web :8000     │
└──────────────────────────┘    └──────────────────────┘
        ▲
        │ built from
┌────────────────────┐
│ vuln_templates/    │  12 parametrized vulnerability classes
└────────────────────┘
```

### Data flow in one sentence

Scanner findings → PostgreSQL → AI classifies the CVE into a vulnerability class →
a template is filled with CVE-specific names → Docker builds and caches an image per
CVE → a container runs per learner with the Splunk log driver → the learner attacks it
through a backend proxy → the container's logs land in Splunk → the learner's blocking
rule is injected as an environment variable and the attack is replayed.

---

## 3. The mission lifecycle

What happens between clicking **Start Mission** and the terminal appearing:

| Stage | Component | Notes |
|-------|-----------|-------|
| Preview | `preview_mission` | Generates the Red and Blue briefs, caches them in `BRIEF_CACHE`. Shown in the modal. No container is created. |
| Start (SSE) | `start_mission_stream` → `_run_mission_start` | Runs in a background thread; progress is streamed to the browser as it happens. |
| Briefs | `BRIEF_CACHE` lookup | Reuses the preview briefs — no second AI call. |
| Cleanup | Docker SDK | Removes this learner's previous `mission-<id>-<session>` container, if any. |
| Image | `build_cve_image` | Checks the image cache by tag **and template fingerprint**. Rebuilds if the template changed. Shared across learners. |
| Classify | `classify_vulnerability_pattern` | Only on a cache miss. Maps the CVE to one of 12 classes, or `unsupported`. |
| Params | `generate_template_params` | Extracts the endpoint / parameter names from the CVE text by regex first, model second. |
| Build | `docker api.build` | Streams `Step n/m` lines to the browser. |
| Port | `claim_free_port` | Reserves a port under a lock so two simultaneous starts can't collide. |
| Run | Docker SDK | Starts with the Splunk log driver; falls back to no logging if Splunk is unreachable. |
| Ready | `wait_for_container_ready` | Polls the target until it answers HTTP. |
| Mission | frontend | Terminal, Target browser, Splunk and Report tabs unlock in sequence. |

A cached image with an unchanged template skips classify, params and build entirely —
that's the difference between a ~90-second first run and a ~10-second repeat.

---

## 4. Technology choices and why

| Tool | Role | Why this one |
|------|------|--------------|
| **FastAPI** | Backend API | Async, native SSE support for streaming build progress, automatic OpenAPI docs at `/docs`. |
| **PostgreSQL** | Platform database | Holds imported CVEs and mission history. Separate from the scanner's own database, which is treated as read-only. |
| **SQLite** | Scanner database | Not ours — read-only input. Also used *inside* the SQL injection lab container. |
| **Docker** | Lab isolation | Each mission is a disposable container. Also gives us the Splunk log driver for free. |
| **Ollama + phi3:mini** | Local LLM | Runs on the training server with no external API calls, so CVE data never leaves the network. |
| **Splunk (HEC)** | Log platform | What the Blue Team phase investigates. Containers forward stdout/stderr via Docker's built-in `splunk` log driver. |
| **Flask** | Lab containers | Small enough that a whole vulnerable app fits in one templated file. |
| **xterm.js** | Learner terminal | A real terminal emulator in the browser — history, cursor movement, copy/paste. |
| **reportlab** | PDF reports | Generates the graded incident report as a downloadable deliverable. |
| **Server-Sent Events** | Progress streaming | One-way server→client, far simpler than WebSockets for build logs and import progress. |

### Why we build the lab containers ourselves

The project started on DVWA and moved away from it:

| Problem with pre-built images | Our templated labs |
|-------------------------------|--------------------|
| Login, CSRF tokens, sessions in the way | No authentication — direct URL access |
| Apache/PHP configuration | Pure Python Flask |
| Unknown URL structure | Endpoint and parameter names are known and CVE-derived |
| One fixed app for all lessons | A different app per CVE, named after the real vulnerability |
| Can't verify a blocking rule | A `WAF_RULE` environment variable makes rule testing possible |

---

## 5. Repository layout

```
cyber-range-platform/
├── backend/
│   ├── main.py                 FastAPI app — all endpoints
│   ├── ai_helper.py            Ollama prompts: briefs, hints, classification,
│   │                           template params, grading, explainers
│   ├── container_builder.py    Template → Docker image, with fingerprint caching
│   ├── database.py             PostgreSQL + scanner SQLite access
│   ├── scanner_import.py       Import pipeline (run as a subprocess)
│   ├── setup_db.py             Creates the platform schema
│   ├── check_tables.py         Schema sanity check
│   └── vuln_templates/
│       ├── path_traversal/     app.py.template + Dockerfile.template
│       ├── sql_injection/
│       ├── command_injection/
│       ├── reflected_xss/
│       ├── ssrf/
│       ├── ssti/
│       ├── xxe/
│       ├── privilege_escalation/
│       ├── idor/
│       ├── open_redirect/
│       ├── auth_bypass/
│       ├── nosql_injection/
│       └── unsupported/        Read-only fallback lab
├── frontend/
│   └── index.html              Entire UI — HTML, CSS and JS in one file
├── containers/
│   ├── app.py                  Original hand-written SQLi lab (legacy)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── test_splunk.ps1
├── scripts/
│   ├── exploit_sqli.py         Standalone exploit demo
│   ├── install_ubuntu.sh       Production setup
│   └── setup_windows.ps1       Development setup
├── docs/
├── .env                        Secrets and connection strings — NOT committed
├── requirements.txt
└── README.md
```

---

## 6. Setting up a new machine

### Who installs what

| Role | Needs |
|------|-------|
| **End user (learner)** | Nothing. A modern browser and the platform URL. |
| **Administrator / developer** | Docker Desktop, Python 3.11+, PostgreSQL, Ollama, Git |
| **Production server** | Docker Engine, Docker Compose, Python 3.11+, PostgreSQL, Ollama, network access to Splunk |

Learners never clone the repo, install Docker, or run anything locally.

### 6.1 Prerequisites

Install and verify each:

```bash
docker version          # Docker Desktop or Engine, must be RUNNING
python --version        # 3.11 or newer
psql --version          # PostgreSQL client
ollama --version        # Ollama
git --version
```

Docker must be **running**, not just installed — the backend talks to the Docker
daemon on startup and will refuse to build missions without it.

### 6.2 Clone and install Python dependencies

```bash
git clone https://github.com/YOUR_USERNAME/cyber-range-platform.git
cd cyber-range-platform
pip install -r requirements.txt
```

`requirements.txt` should include at minimum:

```
fastapi
uvicorn[standard]
docker
psycopg2-binary
python-dotenv
requests
reportlab
pydantic
```

### 6.3 Pull the AI model

```bash
ollama pull phi3:mini
ollama serve            # if not already running as a service
```

Verify:

```bash
curl http://localhost:11434/api/tags
```

### 6.4 Create the PostgreSQL database

```sql
CREATE DATABASE cyber_range;
CREATE USER cyber_range_user WITH PASSWORD 'your-password-here';
GRANT ALL PRIVILEGES ON DATABASE cyber_range TO cyber_range_user;
```

Then create the schema:

```bash
cd backend
python setup_db.py
python check_tables.py    # confirm the tables exist
```

### 6.5 Write the `.env` file

`.env` lives at the **repository root**, one level above `backend/`.
See [section 9](#9-configuration-reference) for every variable.

> **`.env` syntax matters:** no spaces around `=`, no quotes around values.
> `SPLUNK_WEB_URL = "http://host:8000"` will be read as a key named
> `SPLUNK_WEB_URL ` with quotes included in the value.

### 6.6 Point the platform at your scanner database

The scanner's SQLite path is currently hard-coded in `backend/database.py`:

```python
SCANNER_DB_FILE = r"C:\path\to\vulnerability_management.db"
```

Change it to your own path. The platform only ever **reads** this file.

### 6.7 Configure Splunk

See [section 8](#8-splunk-setup). The platform runs without Splunk — the Blue Team
phase just has no data to investigate.

### 6.8 First run

```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

You should see:

```
🔑 Splunk token loaded: 36 chars
✅ Connected to Docker
INFO:     Application startup complete.
```

Open `http://localhost:8000/`, click **Import Scanner**, wait for the progress bar,
then start a mission.

---

## 7. Multi-user access and deployment

### 7.1 How it works

This is a **web application**, not a desktop tool. One machine — the **host** —
runs everything. Everybody else opens a URL in a browser.

| Component | Where it runs |
|-----------|---------------|
| Browser UI | Each learner's own machine |
| FastAPI backend | Host only |
| Docker + mission containers | Host only |
| Ollama (AI) | Host only |
| PostgreSQL | Host only |
| Splunk | Its own server, reachable from both |

The administrator runs the backend on the host and works at `http://localhost:8000/`.
Everyone else uses `http://<host-ip>:8000/` — the same application, reached across the
network.

The learner's browser never talks to a mission container directly. Every request —
terminal `curl` commands and the Target tab alike — is relayed by the backend on the
host. That is why learners need no Docker, no Python, and no repository clone.

**The host must stay running.** If the backend or Docker Desktop is closed, every
learner's session ends. Only the administrator starts, stops or restarts the backend.

### 7.2 One-time setup on the host

**a) The frontend must resolve the API dynamically.** In `frontend/index.html`:

```js
const API_BASE = window.location.origin;
```

Not a hard-coded `http://localhost:8000` — that would point at each learner's *own*
machine, and nothing would load.

**b) The backend must bind all interfaces.** The standard start command already does:

```bash
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

`0.0.0.0` means "listen on every network interface," not just the loopback.

**c) Open port 8000 in the firewall.** This must run in an **elevated** PowerShell.
Press **Win**, type `powershell`, right-click **Windows PowerShell**, choose
**Run as administrator**, and accept the UAC prompt. The title bar will read
"Administrator: Windows PowerShell". Then:

```powershell
New-NetFirewallRule -DisplayName "Cyber Range 8000" -Direction Inbound `
  -LocalPort 8000 -Protocol TCP -Action Allow
```

Success prints the rule's details, including `Enabled : True`.
`Access is denied` means the window is not elevated — close it and reopen as
administrator.

This is a one-time step; the rule persists across reboots.

On Ubuntu the equivalent is:

```bash
sudo ufw allow 8000/tcp
```

### 7.3 Finding the host's IP address

Learners connect to `http://<host-ip>:8000/`, so you need the host's address on the
network.

**On Windows:**

```powershell
ipconfig | Select-String "IPv4"
```

Example output:

```
   IPv4 Address. . . . . . . . . . . : 172.20.16.1
   IPv4 Address. . . . . . . . . . . : 172.16.102.146
```

> **Pick the right one.** A machine running Docker Desktop shows extra *virtual*
> adapters — usually WSL or Hyper-V — that other machines cannot reach. In the example
> above, `172.20.16.1` is Docker's internal adapter and `172.16.102.146` is the real
> one. If in doubt, run `ipconfig` with no filter and take the IPv4 address listed
> under your **Wi-Fi** or **Ethernet** adapter, not under `vEthernet (WSL)` or
> `Docker Desktop`.

**On Linux (production server):**

```bash
hostname -I | awk '{print $1}'
# or, to see adapter names too:
ip -4 addr show | grep inet
```

Ignore `127.0.0.1` (loopback) and anything on `docker0` or `br-*` (Docker bridges).

**Confirm it's reachable** — run this from a *learner's* machine, not the host:

```powershell
Test-NetConnection <host-ip> -Port 8000
```

`TcpTestSucceeded : True` means you're ready. `False` means the firewall rule is
missing, the backend isn't running, or the network blocks client-to-client traffic
(common on guest Wi-Fi — an IT question, not a platform one).

### 7.4 Sharing with learners

Send them one line:

```
http://<host-ip>:8000/
```

Nothing else. No install, no clone, no platform credentials.

### 7.5 When the platform moves to a central server

The URL changes; nothing else does. On the new server:

1. Complete [section 6](#6-setting-up-a-new-machine) on that machine.
2. Find its IP with the commands in [7.3](#73-finding-the-hosts-ip-address).
3. Open port 8000 in its firewall.
4. Update `SPLUNK_HEC_URL` and `SPLUNK_WEB_URL` in `.env` if Splunk's address differs
   from the new server's viewpoint.
5. Distribute the new `http://<server-ip>:8000/`.

**A central server should get a DNS name.** Ask whoever runs your DNS to point
something like `training.company.local` at the server's IP. The URL then never changes
again, even if the server's address does — and learners get a link they can remember.
That is purely a networking task; the platform needs no change, because `API_BASE`
follows whatever hostname the browser used.

For a permanent deployment, also run the backend as a service rather than from a
terminal (systemd on Linux, NSSM or Task Scheduler on Windows) so it survives reboots
and logouts. Drop `--reload`, which is a development convenience.

### 7.6 Concurrent learners

Multiple people can run **the same mission at the same time**.

Each browser tab generates a random session id stored in `sessionStorage`. Containers
are named `mission-<vulnerability-id>-<session>`, so two learners on the same CVE get
two separate containers on two separate ports:

```
mission-97-rdocxl4o   0.0.0.0:8080->80/tcp
mission-97-hzgf3uho   0.0.0.0:8081->80/tcp
```

Everything downstream is scoped the same way — request history, flag-capture state,
WAF rule tests, and the Splunk search tag. One learner's exploit never appears in
another's logs, and one learner's blocking rule never redeploys another's target.

What is deliberately **shared**: the Docker image for a given CVE, and the cached
mission briefs. Both are identical per CVE, so sharing them saves a full rebuild and
several AI calls per learner.

Two things worth knowing:

- **Ollama serializes by default.** If two learners start *different, uncached* CVEs
  at the same moment, the second waits for the first's briefs. Set
  `OLLAMA_NUM_PARALLEL=2` (or higher) on the host to overlap them.
- **Ports are claimed under a lock**, so simultaneous starts can't pick the same one.
  The range is 8080–8379, which is ample.

---

## 8. Splunk setup

### 8.1 Create the index

Splunk Web → **Settings → Indexes → New Index**

| Field | Value |
|-------|-------|
| Index Name | `cyber_range` |
| Data Type | Events |
| Max Data Size | your choice |

### 8.2 Enable HEC globally

**Settings → Data Inputs → HTTP Event Collector → Global Settings**

- All Tokens: **Enabled**
- Default Index: `cyber_range`
- HTTP Port: `8088`

### 8.3 Create a HEC token

**Settings → Data Inputs → HTTP Event Collector → New Token**

| Field | Value |
|-------|-------|
| Name | `cyber_range_token` |
| Default Index | `cyber_range` |
| Allowed Indexes | `cyber_range` |

Copy the token into `.env` as `SPLUNK_HEC_TOKEN`. It is not shown again.

### 8.4 Allow iframe embedding (optional)

Splunk sends `X-Frame-Options: SAMEORIGIN` by default, which prevents embedding it
in the platform. To allow it, edit on the Splunk host:

```
$SPLUNK_HOME/etc/system/local/web.conf
```

```ini
[settings]
x_frame_options_sameorigin = false
```

> **The `[settings]` stanza header is required.** A bare line added under an
> `[expose:...]` block is read as a property of that block and silently ignored.
> If the file already has a `[settings]` stanza, add the line inside it — do not
> create a second one.

Restart Splunk:

```bash
sudo /opt/splunk/bin/splunk restart
```

Verify from the platform machine — no output means the header is gone:

```powershell
curl.exe -sI http://<splunk-host>:8000/en-US/account/login | Select-String "X-Frame-Options"
```

**Even with the header removed**, browsers block Splunk's session cookie inside a
cross-origin iframe (`SameSite`), which produces *"No cookie support detected"*.
Because of this the Splunk tab ships as a **launcher panel** — it shows the exact SPL
query and opens Splunk in a new tab. Full embedding requires Splunk Web on HTTPS or
the reverse proxy at `/splunk-proxy/`.

Learners must be able to reach Splunk's address from **their own** machines, since the
link opens in their browser. They also need Splunk credentials.

### 8.5 Verify the pipeline

Test HEC directly (PowerShell 5.1 needs the certificate workaround first):

```powershell
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

Invoke-RestMethod -Method Post `
  -Uri "https://<splunk-host>:8088/services/collector/event" `
  -Headers @{ Authorization = "Splunk <your-token>" } `
  -Body '{"event":"hec test","index":"cyber_range","sourcetype":"docker"}'
```

Expect `{"text":"Success","code":0}`, then search `index=cyber_range` over
**Last 15 minutes** (not a real-time window — real-time only shows events arriving
from that moment forward).

Confirm the Docker log driver can reach Splunk from inside the daemon's network:

```powershell
docker run --rm curlimages/curl -k -s -o /dev/null -w "%{http_code}`n" `
  https://<splunk-host>:8088/services/collector/health
```

### 8.6 Searching for a mission's logs

Docker's splunk driver writes the container tag into a JSON field named `tag`.
**`tag` is a reserved keyword in SPL**, so a field search fails with
*"The tag '...' does not exist or is deactivated."*

Use a free-text phrase search instead, with the full session-scoped tag:

```
index=cyber_range "mission-97-rdocxl4o"
```

The platform builds this query for you in the Splunk tab. To narrow to the attack:

```
index=cyber_range "mission-97-rdocxl4o" ".."          # path traversal
index=cyber_range "mission-97-rdocxl4o" "OR"          # SQL injection
index=cyber_range "mission-97-rdocxl4o" ";"           # command injection
index=cyber_range "mission-97-rdocxl4o" "<script"     # reflected XSS
```

---

## 9. Configuration reference

`.env` at the repository root:

```dotenv
# ============================================================
# PLATFORM DATABASE (PostgreSQL)
# ============================================================
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=cyber_range
POSTGRES_USER=cyber_range_user
POSTGRES_PASSWORD=change-me
POSTGRES_PASSWORD_ADMIN=change-me-too

# ============================================================
# SPLUNK
# ============================================================
SPLUNK_HEC_TOKEN=your-hec-token-here
SPLUNK_HEC_URL=https://172.16.25.2:8088
SPLUNK_WEB_URL=http://172.16.25.2:8000

# ============================================================
# SERVER
# ============================================================
HOST=0.0.0.0
PORT=8000
RELOAD=True
```

| Variable | Used by | Notes |
|----------|---------|-------|
| `POSTGRES_*` | `database.py` | Platform database connection |
| `SPLUNK_HEC_TOKEN` | `main.py` log config | 36 characters. Rotate if it has ever been committed. |
| `SPLUNK_HEC_URL` | `main.py` log config | **https**, port 8088 |
| `SPLUNK_WEB_URL` | `main.py` proxy | **http**, port 8000 |

Two values are still hard-coded and worth knowing about:

| Value | Location | Purpose |
|-------|----------|---------|
| `SCANNER_DB_FILE` | `backend/database.py` | Path to the scanner's SQLite file |
| `SPLUNK_URL` | `frontend/index.html` | Used to build "Open in Splunk" links |

`load_dotenv` uses an absolute path so the working directory doesn't matter:

```python
load_dotenv(Path(__file__).parent.parent / ".env")
```

---

## 10. Running the platform

### Start the backend — administrator only

```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The administrator opens `http://localhost:8000/` on the host. Everyone else uses
`http://<host-ip>:8000/`. The backend serves the frontend, so there is no separate
frontend server.

### Import CVEs

Click **Import Scanner** in the header. Progress streams live: current CVE, count,
percentage, and elapsed time.

The importer skips the AI scoring call for CVEs already in the platform, so a second
import over the same window is fast. A first import of ~100 new CVEs takes several
minutes because each one needs a model call.

The import survives a browser refresh — the page reattaches to the running job via
`/admin/import_status`.

### Start a mission

1. Pick a card from **Active** (or **Archived**)
2. Read the brief in the modal, click **Enter Mission**
3. Watch the build stream — first run for a CVE builds an image, later runs are cached
4. Work through the four tabs as they unlock

### Mission state survives a refresh

Mission progress is saved to `sessionStorage` every five seconds. Reloading mid-mission
restores the mission, step, timer, flag state and rule — and because the session id
lives in the same store, it reconnects to the *same* container. Terminal scrollback and
command history are not preserved.

---

## 11. The vulnerability template system

### The idea

Rather than writing a lab per CVE (impossible) or using one generic lab for all CVEs
(useless), the platform keeps a small library of **parametrized vulnerability classes**.
For each incoming CVE it classifies which class the CVE belongs to, then fills that
class's template with names pulled from the CVE description.

The exploit mechanism is therefore always correct — it comes from a template that was
written and tested by hand — while the endpoint, parameter, filenames and flavour text
are specific to the real CVE.

### The twelve classes

| Class | Vulnerable mechanism | Example winning payload |
|-------|---------------------|------------------------|
| `path_traversal` | `os.path.join` with unsanitized input | `?file=../secret.txt` or `?file=/etc/passwd` |
| `sql_injection` | String-concatenated SQL | `?id=1' OR '1'='1` |
| `command_injection` | `subprocess` with `shell=True` | `?host=127.0.0.1; cat /app/secret.txt` |
| `reflected_xss` | Input echoed into the response unescaped | `?q=<script>alert(1)</script>` |
| `ssrf` | Server fetches a user-supplied URL | `?url=http://127.0.0.1:8081/` |
| `ssti` | Input rendered as a template | `?name={{7*7}}` |
| `xxe` | XML parser resolves external entities | `?xml=<!DOCTYPE d [<!ENTITY x SYSTEM "file:///app/secret.txt">]><d>&x;</d>` |
| `privilege_escalation` | Role taken from user input | `?role=admin` |
| `idor` | No ownership check on the object ID | `?id=99` |
| `open_redirect` | Unvalidated redirect destination | `?next=http://evil.example` |
| `auth_bypass` | Missing parameter treated as trusted | omit the token entirely |
| `nosql_injection` | Query operators accepted as data | `?username={"$ne":null}` |
| `unsupported` | — | Read-only lab; the learner analyses and reports only |

### Template anatomy

Each directory holds two files:

- `app.py.template` — a Flask app with `{placeholder}` fields
- `Dockerfile.template` — copied verbatim, no formatting applied

Every template contains:

```python
FLAG_TOKEN = "{flag_token}"
FLAG_REASON = "{flag_reason}"

def _flag():
    # assembled at runtime so the marker never appears verbatim in this source
    return "FLAG" + "-FOUND: " + "{cve_id}" + " [" + FLAG_TOKEN + "] — " + FLAG_REASON + "."
```

The flag is **assembled at runtime**, never stored as a literal. This matters because
several classes let the learner read the app's own source — path traversal and command
injection both can. If the flag string appeared in the source, reading `app.py` would
falsely trigger a capture.

Every template also carries the WAF middleware that makes rule testing possible:

```python
WAF_RULE = os.environ.get("WAF_RULE", "").strip()

@app.before_request
def _waf():
    if not WAF_RULE:
        return None
    try:
        rx = _re.compile(WAF_RULE, _re.IGNORECASE)
    except _re.error:
        return None
    if rx.search(request.full_path):
        return "<pre>403 — request blocked by detection rule</pre>", 403
    return None
```

> **Braces must be doubled.** Templates are filled with `str.format()`, so any literal
> `{` or `}` in the app code — dicts, f-strings, template syntax — must be written
> `{{` and `}}`.

### How parameters are chosen

`generate_template_params` works in three layers, most reliable first:

1. **Regex extraction from the CVE text.** "manipulating the `sessionId` argument"
   and "the `getEnrichedData` function" yield `param_name=sessionId` and
   `endpoint=getEnrichedData` with no model involvement. A stopword list rejects
   matches like "the ... argument".
2. **The model**, called in JSON mode with a per-class schema.
3. **Sanitization and defaults.** Every value is validated — identifiers must match
   `^[A-Za-z][A-Za-z0-9_]{0,31}$`, filenames must be plain names — because these
   strings are injected into generated Python source. An unescaped quote produces a
   container that won't boot.

### Image caching and rebuilds

Images are tagged `cve-vuln-<cve-id>` and labelled with:

| Label | Purpose |
|-------|---------|
| `cyber_range_pattern` | Which class was chosen |
| `cyber_range_fingerprint` | SHA-256 of the template files + `TEMPLATE_VERSION` |
| `cyber_range_lab` | JSON of the endpoint, parameter, filenames and flag token |

On each mission start the fingerprint is recomputed. If it differs from the cached
image's label — because you edited a template — the stale image is removed and rebuilt
automatically. **Editing a template requires no manual cleanup.**

To force a global rebuild (for example after changing a prompt, which isn't covered by
the fingerprint), bump `TEMPLATE_VERSION` in `container_builder.py`.

---

## 12. The learner's terminal

The terminal is **not a shell on the target**. It's an HTTP client: `curl` commands
are relayed through the backend to the mission's container, and the real response comes
back. There is no filesystem to `cd` into.

| Command | Effect |
|---------|--------|
| `nmap <target>` | Reports the open HTTP service; advances step 1 |
| `curl "/path?param=value"` | Sends a **real** GET to the container and prints the response |
| `source /path` | Same request, but prints raw HTML — reveals form field names |
| `lab` | Prints the target surface: endpoint, parameter, known file |
| `open /path` | Loads that path in the Target tab |
| `cat brief` | Reprints the Red Team brief |
| `history` | Lists every request that reached the target |
| `hint` | Asks the AI instructor (Red Team phase only) |
| `what` / `explain` | Plain-English explanation of this vulnerability class |
| `index=<terms>` | Lists recorded attack traces (Blue Team phase) |
| `help`, `clear`, `next` | Utility |

Supporting behaviour: arrow-key history, Home/End/Delete, Ctrl+U, Ctrl+L, right-click
paste, and Ctrl+C to copy a selection. Query strings written as `param = value` are
corrected to `param=value` with a warning, since that mistake is common and otherwise
silently sends a parameter whose name has a trailing space.

### Discoverability

Recon is a genuine step, not a formality. `curl "/"` prints the page **and** summarizes
any form it finds:

```
[form] /vuln  inputs: sessionId
try: curl "/vuln?sessionId=<value>"
```

This mirrors what a browser user sees in the page source, so it hands over the attack
surface without handing over the exploit.

### Flag capture from either surface

The Target tab is served through `/missions/{id}/browse`, not directly from the
container, so form submissions in the browser are observed too. The frontend polls
`/flag_status` every three seconds, meaning a learner who solves the lab entirely in
the browser still advances to the Blue Team phase.

Capture requires the response to contain `FLAG-FOUND` **and** the mission's unique
`flag_token`, **and** not to look like template source. All three conditions must hold.

---

## 13. The blocking-rule replay loop

This is the platform's distinguishing feature, and the answer to "how do you know the
learner's detection actually works?"

### What the learner writes

A **regular expression**, matched against every incoming request. Not prose, not SPL,
not Snort syntax:

```
\.\./                    blocks literal ../
(\.\.|%2e%2e|/etc/)      also catches URL-encoded and absolute-path variants
('|%27|--|\bUNION\b)     SQL injection
[;&|`]|\$\(              command injection
```

The panel above the input explains regex escaping, because `../` unescaped means
"any two characters followed by a slash" and would block `/app/files/readme.txt` too.

### What the platform does

`POST /missions/{id}/test_rule`:

1. Compiles the rule — an invalid pattern is rejected immediately
2. Removes **this learner's** container and recreates it on the same port with
   `WAF_RULE` set to their regex
3. Waits for the target to come back up
4. **Replays the exact request that captured the flag**
5. Also requests `/` to check normal traffic still works

### The three verdicts

| Verdict | Condition | What it teaches |
|---------|-----------|-----------------|
| `effective` | Attack blocked, `/` still returns 200 | A deployable rule |
| `bypassed` | The replayed attack still returns the flag | The rule missed the characteristic that makes the request malicious |
| `overblocking` | Attack blocked but `/` also fails | A rule that breaks the application isn't deployable |

The `bypassed` case is the most valuable one. A learner who blocks `\.\./` after
capturing the flag with `/app/secret.txt` — an absolute path, no `../` in it — watches
their own payload defeat their own rule. No amount of AI grading produces that lesson.

### Is this CI/CD?

**CI/CD** means Continuous Integration / Continuous Delivery: changes are integrated
frequently and automatically built and tested, and what passes is automatically
deployed. It is a *practice*, not a tool — GitHub Actions and Jenkins are
implementations of it.

This loop applies CI/CD **principles** to security controls: a change (the rule)
triggers an automated redeploy, an automated test runs against the deployed artifact,
and pass/fail returns in seconds. What's missing from a textbook pipeline is a version
control trigger, a build stage, and a pipeline orchestrator. Describe it as
*"an automated deploy-and-verify loop applying CI/CD principles to security control
validation"* rather than as a CI/CD pipeline.

---

## 14. API reference

Interactive documentation is generated automatically at `http://<host>:8000/docs`.

All mission endpoints accept a `session` parameter identifying the learner's browser
tab. It defaults to `solo`, so single-user use needs no change.

### Missions

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/missions/{id}/preview` | Generate and cache both briefs; no container |
| `GET` | `/missions/{id}/start_stream?session=` | **SSE.** Build and start the mission, streaming progress |
| `GET` | `/missions/{id}/proxy?path=&session=` | Relay one request to the container (used by the terminal) |
| `GET` | `/missions/{id}/browse?path=&session=` | Serve the target through the backend (used by the Target tab) |
| `GET` | `/missions/{id}/activity?session=` | Every request that reached this learner's target |
| `GET` | `/missions/{id}/flag_status?session=` | Whether the flag has been captured, and by which request |
| `POST` | `/missions/{id}/test_rule` | Redeploy with a WAF rule and replay the attack |
| `POST` | `/missions/{id}/end?session=` | Remove this learner's container and clear its state |

`start_stream` is a `GET` because `EventSource` only issues GETs.

### Vulnerabilities

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/vulnerabilities/top?limit=` | Highest-scoring active CVEs |
| `GET` | `/vulnerabilities/archived?min_score=` | Archived CVEs |
| `GET` | `/vulnerabilities/pending` | Imported but not yet activated |
| `GET` | `/missions`, `/missions/active` | Mission history |

### AI

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/ai/hint` | Context-aware hint; reads the container's real request log |
| `GET` | `/ai/brief`, `/ai/blue_brief` | Generate a brief standalone |
| `GET` | `/ai/score` | Score one CVE's training value |
| `GET` | `/ai/command_suggest` | Suggest a terminal command for a stated goal |
| `POST` | `/ai/grade` | Grade a report section by section |

### Reports and admin

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/report/pdf` | Render the graded incident report as a PDF |
| `GET` | `/admin/import_stream` | **SSE.** Run the scanner import with live progress |
| `GET` | `/admin/import_status` | Whether an import is running, and how far along |
| `POST` | `/admin/import_stop` | Terminate a running import |
| `POST` | `/admin/purge_images` | Remove all generated lab images and containers |
| `GET` | `/splunk-proxy/{path}` | Reverse proxy for Splunk Web |

> `/admin/*` endpoints are unauthenticated and destructive. With the platform exposed
> on the network, anyone who can reach it can call them. Trusted networks only until
> authentication is added.

---

## 15. AI features

All model calls go to a local Ollama instance. No CVE data leaves the network.

| Feature | Function | Notes |
|---------|----------|-------|
| CVE scoring | `score_cve_interestingness` | 1–10 training value; skipped for CVEs already imported |
| Red Team brief | `generate_mission_brief` | One paragraph, four sentences, no CVE number |
| Blue Team brief | `generate_blue_team_brief` | Must mention Splunk and the rule; rejected and retried if it doesn't |
| Classification | `classify_vulnerability_pattern` | Maps a CVE to one of 12 classes or `unsupported` |
| Template params | `generate_template_params` | JSON mode; regex extraction takes priority over the model |
| Hints | `generate_hint` | Sees both terminal commands **and** the container's real request log |
| Grading | `grade_report` | Four sections × 25, with three layers of enforcement |
| Explainers | `PATTERN_EXPLAINERS` | Static, not generated — plain-English class descriptions |

### Guarding against small-model failure

phi3:mini is fast and private but weak at instruction-following. Three defences:

**Stop tokens.** `"\n\n"`, `"Write a"`, `"Now generate"` and similar cut the model off
when it starts writing a new document instead of answering.

**Post-processing.** `_clean_brief` strips echoed labels, cuts at any sign of a new
instruction block, keeps the first paragraph, and caps at five sentences.

**Reject and retry, then fall back.** `_looks_broken` detects prompt echo. After two
attempts the platform returns a deterministic brief built from the CVE description —
plain, but always correct. The learner never sees a failure.

The same layered approach applies to JSON outputs: `format: json` at the sampler level,
regex extraction of the first `{...}`, schema validation, and typed defaults.

### Grading enforcement

Grading is constrained in **code**, not by prompt, because small models are
relentlessly generous. Three layers:

1. **Structural gibberish detection** (`_is_gibberish`) — vowel ratios, consonant
   runs, home-row bias, token repetition. No vocabulary list, so it doesn't punish
   someone who writes well but uses unexpected words. Two independent signals are
   required before rejecting.
2. **Relevance judged against verified facts** — the prompt receives the payload that
   actually captured the flag and the rule that actually passed the replay test, so
   the model compares the write-up against ground truth rather than grading style.
3. **An arithmetic cap** — `score = min(model_score, sum(sections))`, and any section
   failing layer 1 is forced to 0. Two empty or nonsense sections make a score above
   50 impossible regardless of what the model claims.

If a bad report still scores well, check which of the three layers isn't running.

If the brief-retry line appears in your logs on most missions, the model is the
bottleneck. `llama3.2:3b` or `qwen2.5:3b` follow instructions considerably better at
similar CPU cost.

---

## 16. Operations and maintenance

### Routine

```bash
# Import today's findings — or use the UI button
cd backend && python -u scanner_import.py
```

Stopped mission containers are removed automatically on backend startup. **Running**
containers are left alone, so restarting the backend does not kill active learner
sessions.

### Manual cleanup

```powershell
# Remove all mission containers (ends every session)
docker ps -aq --filter "name=mission-" | ForEach-Object { docker rm -f $_ }

# Remove all generated lab images
docker images -q "cve-vuln-*" | ForEach-Object { docker rmi -f $_ }
```

Or `POST /admin/purge_images`, which does both and clears the brief cache.

Stop mission containers before removing images — a running container pins its image.

### After editing a template

Nothing. The fingerprint check rebuilds affected images on the next mission start.

### After editing an AI prompt

Bump `TEMPLATE_VERSION` in `container_builder.py` — prompt changes affect the baked-in
parameters but aren't covered by the template fingerprint.

### Rotating the Splunk token

1. Create a new token in Splunk
2. Update `SPLUNK_HEC_TOKEN` in `.env`
3. Restart the backend

Existing containers keep the old token until recreated.

---

## 17. Troubleshooting

### Access from other machines

**The page doesn't load from another machine**
Check three things in order: `API_BASE` is `window.location.origin` and not a
hard-coded localhost; the backend was started with `--host 0.0.0.0`; the firewall rule
from [7.2](#72-one-time-setup-on-the-host) exists. Then run
`Test-NetConnection <host-ip> -Port 8000` from the learner's machine.

**The page loads but nothing works**
The frontend reached the host but the API calls didn't. Open DevTools → Network on the
learner's machine and check which host the failing requests address. If it's
`localhost`, `API_BASE` is still hard-coded, or the browser cached the old file —
hard-refresh with Ctrl+Shift+R.

**Wrong IP address**
Docker Desktop adds virtual adapters. Use the IPv4 address under your Wi-Fi or Ethernet
adapter, not `vEthernet (WSL)` or `Docker Desktop`.

### Missions

**"You already have this mission starting"**
Only fires for the *same browser tab*. Another learner on the same CVE is fine.

**"Failed to start mission: ... failed to initialize logging driver"**
Docker can't reach Splunk HEC. The platform falls back to running without log
forwarding and says so in the build log. Check
`Test-NetConnection <splunk-host> -Port 8088` and that the container test in §8.5
returns 200.

**Container starts with `"Type":"json-file"` instead of `"splunk"`**
The log config didn't apply. `LogConfig(driver=..., options=...)` **silently produces
an empty config** — the constructor signature is `LogConfig(type=..., config=...)`.
Use a plain dict instead:

```python
log_config = {"Type": "splunk", "Config": { ... }}
```

Verify with:

```powershell
docker inspect mission-<id>-<session> --format "{{json .HostConfig.LogConfig}}"
```

**The lab doesn't match the CVE description**
The parameter names fell back to defaults. Check the backend log for `[PARAMS RAW]` to
see what the model returned, and `[BUILD:params]` for what was used.

**Every input returns the same response**
The parameter name is wrong, so `request.args.get(name, default)` always returns the
default. Run `lab`, or `source /` to see the form's real field name.

### Import

**Import button does nothing**
Open DevTools — a thrown exception stops the handler silently. Check that the
`import_stream` request appears in the Network tab.

**Import starts but no output appears**
`cwd=os.path.dirname(__file__)` returns an empty string when uvicorn is launched from
inside `backend/`, because `__file__` is then just `"main.py"`. Use:

```python
cwd=os.path.dirname(os.path.abspath(__file__))
```

**All CVEs archived, nothing active**
`archive_old_vulnerabilities` archives anything whose `last_seen` isn't today. If the
scanner found nothing new in its window, everything ages out. Run the scanner, widen
the import window, or start missions from the **Archived** tab.

### Splunk

**`index=cyber_range` returns nothing**
Check the time picker isn't on a real-time window — real-time shows only events
arriving from now on. Then test HEC directly (§8.5).

**`tstats` fails with "not supported in a real-time search"**
Same cause. Choose **All time** from Presets, not "All time (real-time)".

**"The tag '...' does not exist or is deactivated"**
`tag` is a reserved SPL keyword. Use a phrase search:
`index=cyber_range "mission-97-..."`.

**"No cookie support detected" in the Splunk tab**
The session cookie is blocked in a cross-origin iframe. Use the launcher panel, put
Splunk Web on HTTPS, or serve it through `/splunk-proxy/`.

### Frontend

**The page renders as a wall of plain text**
Something closed the `<style>` block early. HTML parsers end a style element at the
first `</style>` they see — **including inside a CSS comment**. Never write `</style>`
in a comment.

**A button does nothing at all**
Almost always a thrown exception. Check the console first; silent inaction is rarely a
logic bug and usually a `ReferenceError`.

**Panels vanish after editing `switchWorkspace`**
A partial paste — a variable used but not declared. Replace the whole function rather
than patching lines.

---

## 18. Known limitations

| Limitation | Detail |
|-----------|--------|
| **No authentication** | Anyone who can reach the host can start missions and call `/admin/*`. Trusted networks only. |
| **Host is a single point of failure** | Closing the backend or Docker ends every learner's session. |
| **In-memory session state** | Flag-capture state lives in the backend process. A restart leaves containers running but resets recorded progress; re-running the winning request re-captures the flag. |
| **Splunk embedding** | Blocked by cross-origin cookie policy. The Splunk tab is a launcher, not an embed. |
| **No programmatic Splunk read** | Port 8089 (management API) is typically closed, so the platform cannot verify SPL the learner writes. This is why rule validation uses WAF replay instead. |
| **XSS verification is weak** | Nothing executes server-side, so the flag fires on a marker match. The Target tab is where XSS becomes real. |
| **SSRF is simulated** | The lab recognizes internal addresses rather than actually fetching them — a container making arbitrary outbound requests on user input would be a liability. |
| **Classification accuracy** | With twelve classes, phi3 confuses similar pairs (IDOR vs privilege escalation especially). Check `[BUILD:classify]` in the logs. |
| **Ollama serialization** | Concurrent uncached mission starts queue at brief generation unless `OLLAMA_NUM_PARALLEL` is raised. |
| **No scoring history** | Reports are graded and exported but not persisted per learner. |

---

## 19. Demo video

A recorded walkthrough of the platform — importing CVEs, starting a mission,
exploiting the target, investigating in Splunk, deploying a blocking rule, and
generating the report.

<!-- Replace the placeholder below with the video link or embed once uploaded. -->

**▶ Watch the demo:** [`cyber_range_demo.mp4`](cyber_range_demo.mp4)

Contents of the recording:

| Segment | Shows |
|---------|-------|
| 0:00 | Dashboard — imported CVEs, severity and interest scores |
| 0:30 | Mission brief modal, entering a mission, live build stream |
| 1:00 | Recon in the terminal — `curl "/"`, form discovery, `what` |
| 2:00 | Exploiting the target and capturing the flag |
| 3:00 | Splunk investigation of the learner's own requests |
| 4:00 | Writing a blocking rule and watching the replay verdict |
| 5:00 | Report, grading, PDF download |
| 6:00 | Two machines running the same mission simultaneously |

---

## 20. Development history

| Phase | What was built |
|-------|---------------|
| 1 | Custom Flask SQL injection lab, replacing DVWA. Manual exploit script. |
| 2 | FastAPI backend controlling Docker containers. |
| 3 | Learner interface — the exploit had to be typed, not clicked. |
| 4 | Scanner import pipeline, PostgreSQL, AI scoring and briefs. |
| 5 | Per-CVE templated labs: classification, parametrization, image caching. |
| 6 | Splunk integration via the Docker log driver; Blue Team phase. |
| 7 | Real terminal — requests proxied to the live container, flags earned not matched. |
| 8 | WAF replay loop: rules deployed and tested against the learner's own attack. |
| 9 | Graded reports and PDF export. |
| 10 | Twelve vulnerability classes, session persistence, streaming progress, dark UI. |
| 11 | Multi-user: network access, per-session containers, concurrent missions. |

### Notable bugs worth remembering

- `/start` was being called twice per mission — a nested `fetch` inside its own
  callback. Six AI brief generations per launch instead of two.
- `LogConfig(driver=, options=)` silently produced an empty config, so six days of
  container logs went nowhere. `mode: non-blocking` meant the failure was silent.
- Templates originally hard-coded the flag string, so reading `app.py` through the
  traversal falsely captured the flag.
- A CSS comment containing `</style>` terminated the stylesheet three lines in.
- `.env` values written as `KEY = "value"` are parsed with the spaces and quotes intact.
- `os.path.dirname(__file__)` returns `""` when the process is launched from that
  file's own directory, which silently broke the import subprocess.
- `API_BASE = 'http://localhost:8000'` meant every learner's browser called *its own*
  machine. One line — `window.location.origin` — made the platform multi-user.
