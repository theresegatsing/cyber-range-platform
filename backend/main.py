from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
import docker
import requests
import os
from datetime import datetime
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from database import get_all_missions, get_active_missions, get_pending_vulnerabilities, get_top_interesting_vulnerabilities

# Load environment variables
load_dotenv()

app = FastAPI(title="Cyber Range Platform API", version="0.1.0")

# Connect to Docker
try:
    docker_client = docker.from_env()
    print("✅ Connected to Docker")
except Exception as e:
    print(f"❌ Failed to connect to Docker: {e}")
    docker_client = None

# Container configuration
CONTAINER_NAME = "custom-vuln-app"
IMAGE_NAME = "custom-vuln-app"
VULN_APP_URL = "http://localhost:8080/vuln"

# ============================================================
# ROOT ENDPOINT: MISSION DASHBOARD (FRONTEND)
# ============================================================
@app.get("/")
def serve_frontend():
    """Serve the main frontend HTML page (Mission Dashboard)."""
    frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    if os.path.exists(frontend_path):
        return FileResponse(frontend_path)
    else:
        return {"error": "Frontend not found. Please run the setup script."}

# ============================================================
# OLD SQL INJECTION LAB (MOVED TO /lab FOR TESTING)
# ============================================================
@app.get("/lab", response_class=HTMLResponse)
def sql_lab():
    """Serve the old SQL injection training lab (for testing only)."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cyber Range - SQL Injection Lab</title>
        <style>
            body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
            input[type=text] { width: 100%; padding: 10px; font-size: 16px; }
            button { padding: 10px 20px; font-size: 16px; background: #007bff; color: white; border: none; cursor: pointer; }
            pre { background: #f4f4f4; padding: 15px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>SQL Injection Training Lab</h1>
        <p><strong>Mission:</strong> The database stores user credentials. Your goal is to retrieve <strong>ALL</strong> users by exploiting a SQL injection vulnerability.</p>
        
        <h3>Instructions</h3>
        <ul>
            <li>Craft a SQL injection payload that returns <strong>ALL</strong> users.</li>
            <li>Type your payload into the box below and click "Exploit".</li>
        </ul>

        <form action="/exploit" method="get">
            <label for="payload">Enter your SQL injection payload:</label><br><br>
            <input type="text" id="payload" name="payload" placeholder="e.g., 1 OR 1=1" style="width: 100%; padding: 10px; font-size: 16px;">
            <br><br>
            <button type="submit">Exploit</button>
        </form>
        
        <hr>
        <p><strong>Hint:</strong> The column is an integer. Try <code>1 OR 1=1</code> or <code>1 OR '1'='1</code>.</p>
        <p><a href="/">← Back to Mission Dashboard</a></p>
    </body>
    </html>
    """

# ============================================================
# SQL EXPLOIT PROXY (For the Lab)
# ============================================================
@app.get("/exploit", response_class=HTMLResponse)
def exploit(request: Request):
    payload = request.query_params.get("payload", "")
    
    if not payload:
        return """
        <html><body>
            <h2>⚠️ No payload provided.</h2>
            <a href="/lab">Go back</a>
        </body></html>
        """
    
    try:
        response = requests.get(VULN_APP_URL, params={"id": payload})
        
        if response.status_code != 200:
            return f"""
            <html><body>
                <h2>❌ Error: Vulnerable app returned status {response.status_code}</h2>
                <p>Make sure the container is running. Use the API to start it.</p>
                <a href="/lab">Go back</a>
            </body></html>
            """
        
        return f"""
        <html>
        <head>
            <title>Exploit Result</title>
            <style>
                body {{ font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }}
                .payload {{ background: #f4f4f4; padding: 10px; border-radius: 5px; }}
                pre {{ background: #e8f4e8; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>📊 Exploit Result</h1>
            <p><strong>Your payload:</strong> <code class="payload">{payload}</code></p>
            <h3>📦 Database Response:</h3>
            <pre>{response.text}</pre>
            <hr>
            <h3>🧠 Analysis</h3>
            <ul>
                <li>If you see <strong>ALL</strong> users (admin and john), your exploit worked! 🎉</li>
                <li>If you see only user 1, the payload didn't work.</li>
                <li>If you see an error, your syntax is wrong – try again!</li>
            </ul>
            <a href="/lab">← Back to lab</a>
            <br>
            <a href="/">← Back to Mission Dashboard</a>
        </body>
        </html>
        """
    
    except requests.exceptions.ConnectionError:
        return f"""
        <html><body>
            <h2>❌ Connection Error</h2>
            <p>Could not reach the vulnerable app on port 8080.</p>
            <p>Make sure the container is running.</p>
            <a href="/lab">Go back</a>
        </body></html>
        """

# ============================================================
# CONTAINER CONTROL ENDPOINTS
# ============================================================
@app.get("/container/status")
def get_container_status():
    if docker_client is None:
        raise HTTPException(status_code=500, detail="Docker not available")
    
    try:
        container = docker_client.containers.get(CONTAINER_NAME)
        return {
            "name": container.name,
            "status": container.status,
            "is_running": container.status == "running"
        }
    except docker.errors.NotFound:
        return {
            "name": CONTAINER_NAME,
            "status": "not_found",
            "is_running": False
        }

@app.post("/container/start")
def start_container():
    if docker_client is None:
        raise HTTPException(status_code=500, detail="Docker not available")
    
    try:
        try:
            container = docker_client.containers.get(CONTAINER_NAME)
            if container.status == "running":
                return {"message": f"Container '{CONTAINER_NAME}' is already running"}
            else:
                container.start()
                return {"message": f"Container '{CONTAINER_NAME}' started successfully"}
        except docker.errors.NotFound:
            container = docker_client.containers.run(
                IMAGE_NAME,
                detach=True,
                ports={'80/tcp': 8080},
                name=CONTAINER_NAME
            )
            return {"message": f"Container '{CONTAINER_NAME}' created and started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/container/stop")
def stop_container():
    if docker_client is None:
        raise HTTPException(status_code=500, detail="Docker not available")
    
    try:
        container = docker_client.containers.get(CONTAINER_NAME)
        container.stop()
        return {"message": f"Container '{CONTAINER_NAME}' stopped"}
    except docker.errors.NotFound:
        return {"message": f"Container '{CONTAINER_NAME}' does not exist"}

# ============================================================
# AI ENDPOINTS
# ============================================================
from ai_helper import generate_blue_team_brief, generate_mission_brief, generate_hint, grade_report, score_cve_interestingness

@app.get("/ai/brief")
def get_mission_brief(cve_id: str, description: str, cvss_score: float):
    """Generate a mission brief for a CVE."""
    brief = generate_mission_brief(cve_id, description, cvss_score)
    return {"brief": brief}

@app.get("/ai/blue_brief")
def get_blue_team_brief(cve_id: str, description: str):
    """Generate a Blue Team mission brief for a CVE."""
    blue_brief = generate_blue_team_brief(cve_id, description)
    return {"brief": blue_brief}

@app.get("/ai/hint")
def get_hint(task_name: str, current_step: str, actions: str = ""):
    """Generate a hint for a stuck learner."""
    action_list = actions.split(",") if actions else []
    hint = generate_hint(task_name, current_step, action_list)
    return {"hint": hint}

@app.post("/ai/grade")
def grade_learner_report(report: str, findings: list):
    """Grade a learner's incident report."""
    result = grade_report(report, findings)
    return result

@app.get("/ai/score")
def score_cve(cve_id: str, description: str, cvss_score: float, kev_status: bool = False):
    """Score how interesting a CVE is for training."""
    score = score_cve_interestingness(cve_id, description, cvss_score, kev_status)
    return {"cve": cve_id, "interestingness_score": score}

# ============================================================
# RULE VALIDATION ENDPOINTS
# ============================================================
from rule_validator import validate_rule, test_attack

@app.post("/validate")
def validate_learner_rule(rule: str):
    """Validate a learner's detection rule."""
    result = validate_rule(rule)
    return result

@app.get("/test_attack")
def test_sql_injection():
    """Test if the SQL injection attack works."""
    result = test_attack()
    return result

# ============================================================
# MISSION MANAGEMENT ENDPOINTS
# ============================================================
from database import get_all_missions, get_active_missions, get_pending_vulnerabilities
from ai_helper import generate_mission_brief, generate_blue_team_brief
import docker
import time

@app.get("/missions")
def list_all_missions():
    """List all missions from the database."""
    try:
        missions = get_all_missions()
        return {"missions": [dict(m) for m in missions]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/missions/active")
def list_active_missions():
    """List only active missions."""
    try:
        missions = get_active_missions()
        return {"missions": [dict(m) for m in missions]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/vulnerabilities/pending")
def list_pending_vulnerabilities():
    """List all pending vulnerabilities."""
    try:
        pending = get_pending_vulnerabilities()
        return {"vulnerabilities": [dict(v) for v in pending]}
    except Exception as e:
        return {"error": str(e)}

@app.post("/missions/{vulnerability_id}/start")
def start_mission(vulnerability_id: int):
    """
    Start a mission by vulnerability ID.
    This:
    1. Generates Red Team and Blue Team briefs on-demand.
    2. Starts the vulnerable container.
    3. Returns the briefs and container info.
    """
    try:
        from database import get_platform_connection
        conn = get_platform_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Fetch the vulnerability
        cursor.execute("SELECT * FROM platform_vulnerabilities WHERE id = %s", (vulnerability_id,))
        vuln = cursor.fetchone()
        
        if not vuln:
            conn.close()
            return {"error": "Vulnerability not found"}
        
        # Generate briefs on-demand (ONLY NOW!)
        print(f"🤖 Generating AI briefs for {vuln['cve_id']}...")
        red_brief = generate_mission_brief(vuln['cve_id'], vuln['description'], vuln['cvss_score'])
        blue_brief = generate_blue_team_brief(vuln['cve_id'], vuln['description'])
        
        # Start the vulnerable container
        print(f"🐳 Starting container for {vuln['cve_id']}...")
        try:
            docker_client = docker.from_env()
            container_name = f"mission-{vulnerability_id}"
            
            # Check if container exists
            try:
                container = docker_client.containers.get(container_name)
                if container.status == "running":
                    print(f"Container {container_name} is already running")
                else:
                    container.start()
                    print(f"Container {container_name} started")
            except docker.errors.NotFound:
                # Create and run new container
                container = docker_client.containers.run(
                    "custom-vuln-app",
                    detach=True,
                    ports={'80/tcp': 8080},
                    name=container_name
                )
                print(f"Container {container_name} created and started")
            
            # Update mission status in database
            cursor.execute("""
                INSERT INTO missions (vulnerability_id, cve_id, red_team_brief, blue_team_brief, status, created_at)
                VALUES (%s, %s, %s, %s, 'active', %s)
            """, (vulnerability_id, vuln['cve_id'], red_brief, blue_brief, datetime.now()))
            
            # Update vulnerability status
            cursor.execute("""
                UPDATE platform_vulnerabilities 
                SET platform_status = 'active' 
                WHERE id = %s
            """, (vulnerability_id,))
            
            conn.commit()
            conn.close()
            
            return {
                "status": "success",
                "cve_id": vuln['cve_id'],
                "red_team_brief": red_brief,
                "blue_team_brief": blue_brief,
                "container_name": container_name,
                "container_port": 8080,
                "app_url": f"http://localhost:8080/vuln"
            }
            
        except Exception as e:
            conn.close()
            return {"error": f"Container error: {str(e)}"}
            
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# SCANNER IMPORT ENDPOINT (For Frontend Trigger)
# ============================================================
@app.post("/admin/import")
def run_scanner_import():
    """
    Trigger the scanner import process.
    This will fetch new vulnerabilities from the scanner database,
    score them with AI, and save them to the platform.
    """
    try:
        import subprocess
        import sys
        
        # Run scanner_import.py as a subprocess
        result = subprocess.run(
            [sys.executable, "scanner_import.py"],
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=1800  # 30 minute timeout
        )
        
        return {
            "status": "success" if result.returncode == 0 else "error",
            "output": result.stdout,
            "error": result.stderr if result.stderr else None
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Import timed out after 5 minutes"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/vulnerabilities/top")
def get_top_vulnerabilities(limit: int = 10):
    """Get the top N most interesting vulnerabilities."""
    try:
        from database import get_top_interesting_vulnerabilities
        top = get_top_interesting_vulnerabilities(limit)
        return {"vulnerabilities": [dict(v) for v in top]}
    except Exception as e:
        return {"error": str(e)}