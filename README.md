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
