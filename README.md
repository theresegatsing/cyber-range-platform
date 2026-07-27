# Purple-Team Cyber Range Platform

## Project Goal
Convert daily vulnerability scanner findings into interactive attack-and-defense labs.

## Phase 1 (Weeks 1-2)
Building base Docker containers with vulnerable applications.

## Current Status
Project started: $(date +"2026-07-20")
EOF

## Tool choice 
- when initilaising the first vulnerable app, I used DVWA (Damn Vulnerable Web Application), which  is a deliberately insecure web application designed for learning and practicing web security in a safe, controlled environment.

## Installation Requirements (Who needs to install what?)

This platform is a **web-based application**. 
- **End-Users (Employees doing training)**: **NOTHING**. They only need a modern web browser (Chrome, Firefox, Edge) and the internal company URL.
- **Developers (Me)**: Docker Desktop (https://www.docker.com/products/docker-desktop/), Python, Node.js, Git.
- **Production Server (IT/DevOps)**: Docker Engine, Docker Compose, PostgreSQL, and Ollama (AI).

---

## How End-Users Access the Platform
1. The platform is deployed to a central company server.
2. Employees receive an internal link (e.g., `https://training.company.local`).
3. They log in with their company credentials.
4. They complete the training entirely in their browser.
5. **They do not download, clone, or install any code or tools on their personal machines.**

---


## Phase 1 Complete: SQL Injection Exploit Working

### Testing the Exploit Manually

The vulnerable app is running at `http://localhost:8080/vuln`.

To test the SQL injection manually:

1. **Normal request** (returns only user 1): http://localhost:8080/vuln?id=1
Output: `[(1, 'admin', 'secretpass')]`

2. **Exploit request** (returns ALL users): http://localhost:8080/vuln?id=1%20OR%201=1

Output: `[(1, 'admin', 'secretpass'), (2, 'john', 'doe123')]`

### Important Note About SQL Injection Payloads

Since the `id` column is an **integer**, you **cannot** use single quotes:
- ❌ `1' OR '1'='1` → causes an SQL syntax error (Internal Server Error)
- ✅ `1 OR 1=1` → works perfectly (no quotes needed)

### Automated Exploit Script

The script `scripts/exploit_sqli.py` automatically sends the exploit payload and confirms it works by looking for both `admin` and `john` in the response.

**Run it with:**
```bash
python scripts/exploit_sqli.py
```

### Downloading all dependencies
From the root directory, run the following command:

```bash 
pip install -r requirements.txt
```


### why backend fast api
to automatically start the container , end it and get the status

---

## Phase 2: FastAPI Backend (The "Brain")

### Why This Matters

The backend API is the **core controller** of the entire platform. It acts as the bridge between the user interface (frontend) and the Docker containers.

| What It Does | Why It's Important |
|--------------|---------------------|
| **Starts containers** | When a learner clicks "Start Mission," the API triggers Docker. |
| **Stops containers** | Prevents unused containers from wasting server resources. |
| **Checks container status** | Lets the frontend display "Running" or "Stopped" to the user. |
| **Future features** | Will handle user authentication, logging, and report generation. |

---

### How to Run the Backend Server

**Important:** Run this from the `backend/` folder.

```bash
cd C:\Users\gatsi\github\cyber-range-platform\backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## Phase 1 Summary: Vulnerable App + SQL Injection Exploit

### What We Built

We built a **custom vulnerable web application** using Python Flask that contains a deliberate SQL injection vulnerability. This serves as the "training target" for the Red Team phase.

### Why We Built It Ourselves

| Problem with Pre-built Images | Our Custom Solution |
|-------------------------------|----------------------|
| Required login, CSRF tokens, and sessions | **No authentication required** – just a direct URL. |
| Apache/PHP configuration nightmares | **Pure Python** – runs reliably in a container. |
| Unknown URL structures (404 errors) | **Single known endpoint** – `/vuln`. |
| Bloated UIs with 50+ lessons | **Minimal UI** – just returns raw database data. |
| Session handling was broken | **Stateless** – no sessions to break. |

### How to Get the Vulnerable App Running

**Step 1: Build the Docker image**
```bash
docker build -t custom-vuln-app ./containers
```
---

## Phase 2 Progress: FastAPI Backend (Container Control)

We built a FastAPI backend that acts as the "remote control" for the vulnerable container.

### Testing the API (From the Backend Directory)

While the FastAPI server was running (in the `backend/` directory), we successfully tested the container control using PowerShell:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/container/start" -Method POST
```

---

## Phase 3: Learner Interface (No More Auto-Exploit)

### The Problem We Fixed

Previously, the exploit was in the URL (e.g., `?id=1%20OR%201=1`). The learner just clicked a link and the attack happened automatically – **they learned nothing**.

### The Solution: Active Learning

Now, we have built a **web interface** (`http://localhost:8000/`) where the learner must:

1. Read the mission briefing.
2. Understand that the database stores user data.
3. **Manually type** their SQL injection payload into an input box.
4. Click "Exploit" to see the result.
5. Iterate until they successfully retrieve all users.

### How It Works

| Component | What It Does |
|-----------|--------------|
| **Frontend HTML** | Served by FastAPI at `/`. Contains the input form. |
| **`/exploit` endpoint** | Takes the learner's payload, sends it to the vulnerable app, and displays the result. |
| **Error handling** | Shows helpful messages if the app is down or the payload fails. |

### Why This Matters

- **Forces critical thinking** – the learner must craft the syntax themselves.
- **Immediate feedback** – they see the database response or an error message.
- **Teaches SQL injection mechanics** – they learn that `1 OR 1=1` works on integers, but `1' OR '1'='1` fails on integer columns.

### Testing the Learner Interface

1. Make sure the container is running:  
   `Invoke-RestMethod -Uri "http://localhost:8000/container/start" -Method POST`

2. Open your browser to: `http://localhost:8000/`

3. Enter a payload in the box and click "Exploit".

**Example successful payload:** `1 OR 1=1`

**Expected result:**
```bash
[(1, 'admin', 'secretpass'), (2, 'john', 'doe123')]
```

### start the docker before going to the frontend
Run this command:

```bash
docker start custom-vuln-app
```