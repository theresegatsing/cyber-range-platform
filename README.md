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

## Troubleshooting SQL Injection (Common Error)

If you see a MariaDB/MySQL syntax error when testing `1' OR 1=1 --`:

**Cause**: MySQL requires a space after `--` to treat the rest as a comment.

**Solutions**:
1. Add a trailing space: `1' OR 1=1 -- ` (type a space after the dashes).
2. Use the universal payload: `1' OR '1'='1` (doesn't require comments).
3. **Check DVWA Security Level**: Go to the left menu -> "DVWA Security" -> Set to **"Low"** -> Submit.

Once set to "Low" and using the correct syntax, the exploit will work immediately.