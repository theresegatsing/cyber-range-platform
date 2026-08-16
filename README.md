# Purple-Team Cyber Range Platform

## Project Goal
Convert daily vulnerability scanner findings into interactive attack-and-defense labs.

## steps to make it run
1) Run the docker in the backend:  
```bash 
docker build -t custom-vuln-app ./containers
```

2) Run this on the backend level directory: 
``` bash
 python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

```
3) Run frontend 
```bash
http://localhost:8000/

```
4) start a container inside containers directory
```bash

docker-compose up -d
```
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

---

## Installation Guide

### One-Command Setup

We provide automated setup scripts for both Windows (development) and Ubuntu (production).

#### For Ubuntu (Production Server)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cyber-range-platform.git
cd cyber-range-platform

# Make the script executable and run it
chmod +x scripts/install_ubuntu.sh
./scripts/install_ubuntu.sh
```

##### What the script does:

- Updates system packages.

- Installs Docker and Docker Compose.

- Installs Python 3 and pip.

- Installs Ollama.

- Pulls the Phi-3-mini AI model.

- Installs Python dependencies.

- Builds and runs the vulnerable container.

#### For Windows (Development)

```bash
# Open PowerShell as Administrator and run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Clone the repository
git clone https://github.com/YOUR_USERNAME/cyber-range-platform.git
cd cyber-range-platform

# Run the setup script
powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1
```

##### What the script does:

- Checks if Docker is installed.

- Checks if Python is installed.

- Installs Python dependencies.

- Checks if Ollama is installed.

- Builds and runs the vulnerable container.

## AI Features (Intelligent Summarization)

The AI reads the CVE description and generates **unique, professional mission briefs** for both Red Team and Blue Team phases.

### How It Works

| Step | What Happens |
|------|--------------|
| 1 | AI receives the CVE description (e.g., "OpenCTI is vulnerable to XSS..."). |
| 2 | AI **reads and understands** the vulnerability. |
| 3 | AI generates a **unique summary** in 1-2 sentences. |
| 4 | Output is professional, urgent, and clear. |

### Red Team Brief Example

**Input Description:**
> "OpenCTI is vulnerable to XSS in the rendering of email-message observable body data... could lead to CSRF and then large scale session theft."

**AI Output:**
> "For this mission, you will exploit a stored XSS vulnerability in OpenCTI that allows attackers to steal admin cookies through malicious email-message data. Your objective: execute the attack and capture the flag."

### Blue Team Brief Example

**Input Description:** Same as above.

**AI Output:**
> "Your mission is to investigate the logs from a stored XSS attack on OpenCTI. You must locate the attack traces in the logs and write a detection rule to prevent session theft."

### Why This Works

- **Unique**: Every brief is different based on the CVE description.
- **Professional**: No casual greetings or passive voice.
- **Actionable**: The learner knows exactly what to do.
- **Scalable**: Works with any CVE description.


## Splunk Integration Setup
Overview
The Cyber Range Platform forwards logs from every vulnerable container to Splunk using the Splunk HTTP Event Collector (HEC). This allows learners to search for their attack traces during the Blue Team phase.

1. Splunk Admin Setup (First Time)
These steps must be completed once by a Splunk administrator.

Step 1.1: Create the Splunk Index
Log in to Splunk Web UI (http://<splunk-ip>:8000).

Go to Settings → Indexes.

Click "New Index".

Fill in:

Index Name: cyber_range

Data Type: Events

Max Data Size: Set to your preference (e.g., 100 GB)

Click "Save".

Step 1.2: Enable HTTP Event Collector (HEC)
Go to Settings → Data Inputs → HTTP Event Collector.

Click "Global Settings" (top right).

Set Enabled to "Yes".

Under "Allowed Indexes", select cyber_range.

Click "Save".

Step 1.3: Create a HEC Token
In Settings → Data Inputs → HTTP Event Collector, click "New Token".

Fill in:

Name: cyber_range_token (or any descriptive name)

Default Index: Select cyber_range

Allowed Indexes: Add cyber_range

Click "Next".

Verify the settings and click "Submit".

Copy the token immediately – it will not be shown again.

#### Build and Run the Container
# Navigate to project root
cd C:\Users\gatsi\github\cyber-range-platform

# Build the Docker image
docker build -t custom-vuln-app ./containers

# Start the container with Splunk logging
cd containers
docker-compose up -d

# Verify it's running
docker ps


## Prerequisites

- **Docker Desktop** (or Docker Engine) must be installed and **running** before starting the backend.
- The backend uses Docker’s API to manage mission containers. If Docker is not running, you will see:

- Verify Docker is ready with:
```bash
docker version
```