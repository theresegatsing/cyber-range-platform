from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
import docker
import requests
import os
from datetime import datetime
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
import socket
import time

# Load environment variables
load_dotenv()

app = FastAPI(title="Cyber Range Platform API", version="0.1.0")

# ============================================================
# DOCKER CLIENT
# ============================================================
try:
    docker_client = docker.from_env()
    print("✅ Connected to Docker")
except Exception as e:
    print(f"❌ Failed to connect to Docker: {e}")
    docker_client = None

# ============================================================
# HELPER FUNCTIONS
# ============================================================
def find_free_port(start_port=8080, max_attempts=100):
    """Find a free port starting from the given port."""
    for port in range(start_port, start_port + max_attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        if result != 0:
            return port
    return None

# ============================================================
# SERVE FRONTEND
# ============================================================
@app.get("/")
def serve_frontend():
    frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    if os.path.exists(frontend_path):
        return FileResponse(frontend_path)
    else:
        return {"error": "Frontend not found."}

@app.get("/lab", response_class=HTMLResponse)
def sql_lab():
    """SQL injection lab (for testing)"""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>SQL Injection Lab</title></head>
    <body>
        <h1>SQL Injection Training Lab</h1>
        <p>Visit <a href="http://localhost:8080/" target="_blank">http://localhost:8080/</a></p>
    </body>
    </html>
    """

# ============================================================
# CONTAINER CONTROL
# ============================================================
@app.get("/container/status")
def get_container_status():
    if docker_client is None:
        raise HTTPException(status_code=500, detail="Docker not available")
    
    try:
        container = docker_client.containers.get("custom-vuln-app")
        return {
            "name": container.name,
            "status": container.status,
            "is_running": container.status == "running"
        }
    except docker.errors.NotFound:
        return {
            "name": "custom-vuln-app",
            "status": "not_found",
            "is_running": False
        }

@app.post("/container/start")
def start_container():
    if docker_client is None:
        raise HTTPException(status_code=500, detail="Docker not available")
    
    try:
        try:
            container = docker_client.containers.get("custom-vuln-app")
            if container.status == "running":
                return {"message": "Container is already running"}
            else:
                container.start()
                return {"message": "Container started successfully"}
        except docker.errors.NotFound:
            container = docker_client.containers.run(
                "custom-vuln-app",
                detach=True,
                ports={'80/tcp': 8080},
                name="custom-vuln-app"
            )
            return {"message": "Container created and started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/container/stop")
def stop_container():
    if docker_client is None:
        raise HTTPException(status_code=500, detail="Docker not available")
    
    try:
        container = docker_client.containers.get("custom-vuln-app")
        container.stop()
        return {"message": "Container stopped"}
    except docker.errors.NotFound:
        return {"message": "Container does not exist"}

# ============================================================
# AI ENDPOINTS
# ============================================================
from ai_helper import generate_mission_brief, generate_blue_team_brief, generate_hint, grade_report, score_cve_interestingness

@app.get("/ai/brief")
def get_mission_brief(cve_id: str, description: str, cvss_score: float, asset: str = "the application"):
    brief = generate_mission_brief(cve_id, description, cvss_score, asset)
    return {"brief": brief}

@app.get("/ai/blue_brief")
def get_blue_team_brief(cve_id: str, description: str):
    blue_brief = generate_blue_team_brief(cve_id, description)
    return {"brief": blue_brief}

@app.get("/ai/hint")
def get_hint(task_name: str, current_step: str, actions: str = ""):
    action_list = actions.split(",") if actions else []
    hint = generate_hint(task_name, current_step, action_list)
    return {"hint": hint}

@app.post("/ai/grade")
def grade_learner_report(report: str, findings: list):
    result = grade_report(report, findings)
    return result

@app.get("/ai/score")
def score_cve(cve_id: str, description: str, cvss_score: float, is_kev: bool = False):
    score = score_cve_interestingness(cve_id, description, cvss_score, is_kev)
    return {"cve": cve_id, "interestingness_score": score}

# ============================================================
# MISSION MANAGEMENT
# ============================================================
from database import get_all_missions, get_active_missions, get_pending_vulnerabilities, get_top_interesting_vulnerabilities, get_platform_connection

@app.get("/missions")
def list_all_missions():
    try:
        missions = get_all_missions()
        return {"missions": [dict(m) for m in missions]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/missions/active")
def list_active_missions():
    try:
        missions = get_active_missions()
        return {"missions": [dict(m) for m in missions]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/vulnerabilities/pending")
def list_pending_vulnerabilities():
    try:
        pending = get_pending_vulnerabilities()
        return {"vulnerabilities": [dict(v) for v in pending]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/vulnerabilities/top")
def get_top_vulnerabilities(limit: int = 10):
    try:
        top = get_top_interesting_vulnerabilities(limit)
        return {"vulnerabilities": [dict(v) for v in top]}
    except Exception as e:
        return {"error": str(e)}

@app.post("/missions/{vulnerability_id}/start")
def start_mission(vulnerability_id: int):
    try:
        conn = get_platform_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute("SELECT * FROM platform_vulnerabilities WHERE id = %s", (vulnerability_id,))
        vuln = cursor.fetchone()
        
        if not vuln:
            conn.close()
            return {"error": "Vulnerability not found"}
        
        print(f"🤖 Generating AI briefs for {vuln['cve_id']}...")
        red_brief = generate_mission_brief(
            vuln['cve_id'], 
            vuln['description'], 
            vuln['cvss_score'],
            vuln['asset']
        )
        blue_brief = generate_blue_team_brief(vuln['cve_id'], vuln['description'])
        
        free_port = find_free_port()
        if not free_port:
            conn.close()
            return {"error": "No free ports available"}
        
        print(f"🐳 Starting container on port {free_port}...")
        try:
            container_name = f"mission-{vulnerability_id}"
            
            try:
                existing = docker_client.containers.get(container_name)
                existing.stop()
                existing.remove()
                print(f"Removed existing container: {container_name}")
            except docker.errors.NotFound:
                pass
            
            container = docker_client.containers.run(
                "custom-vuln-app",
                detach=True,
                ports={'80/tcp': free_port},
                name=container_name
            )
            print(f"Container {container_name} started on port {free_port}")
            
            cursor.execute("""
                INSERT INTO missions (vulnerability_id, cve_id, red_team_brief, blue_team_brief, status, created_at)
                VALUES (%s, %s, %s, %s, 'active', %s)
            """, (vulnerability_id, vuln['cve_id'], red_brief, blue_brief, datetime.now()))
            
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
                "container_port": free_port,
                "app_url": f"http://localhost:{free_port}"
            }
            
        except Exception as e:
            conn.close()
            return {"error": f"Container error: {str(e)}"}
            
    except Exception as e:
        return {"error": str(e)}

# ============================================================
# ADMIN: RUN SCANNER IMPORT
# ============================================================
@app.post("/admin/import")
def run_scanner_import():
    try:
        import subprocess
        import sys
        
        print("📂 Running scanner_import.py from:", os.path.dirname(__file__))
        result = subprocess.run(
            [sys.executable, "scanner_import.py"],
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=3600
        )
        print(f"📤 Return code: {result.returncode}")
        if result.stdout:
            print(f"📤 Stdout: {result.stdout[:500]}...")
        if result.stderr:
            print(f"📤 Stderr: {result.stderr[:500]}...")
        
        return {
            "status": "success" if result.returncode == 0 else "error",
            "output": result.stdout,
            "error": result.stderr if result.stderr else None,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Import timed out after 60 minutes"}
    except Exception as e:
        print(f"❌ Import exception: {str(e)}")
        return {"status": "error", "message": str(e)}