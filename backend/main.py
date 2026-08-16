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
from database import get_archived_vulnerabilities
from ai_helper import generate_mission_brief, generate_blue_team_brief, generate_hint, grade_report, score_cve_interestingness, generate_command_suggestion
from docker.types import LogConfig
from container_builder import build_cve_image

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

def wait_for_container_ready(port: int, timeout: int = 15) -> bool:
    """Poll the target's HTTP endpoint until it responds or timeout is hit."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"http://localhost:{port}/", timeout=1)
            if r.status_code < 500:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)
    return False

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

@app.get("/ai/command_suggest")
def get_command_suggestion(goal: str, current_step: str, cve_description: str = ""):
    suggestion = generate_command_suggestion(goal, current_step, cve_description)
    return {"suggestion": suggestion}

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
def get_top_vulnerabilities(limit: int = 100):
    try:
        top = get_top_interesting_vulnerabilities(limit)
        return {"vulnerabilities": [dict(v) for v in top]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/vulnerabilities/archived")
def list_archived_vulnerabilities(min_score: int = 5):
    try:
        archived = get_archived_vulnerabilities(min_score)
        return {"vulnerabilities": [dict(v) for v in archived]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/missions/{vulnerability_id}/preview")
def preview_mission(vulnerability_id: int):
    """Generate briefs for the modal WITHOUT touching platform_status or spinning up a container."""
    try:
        conn = get_platform_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM platform_vulnerabilities WHERE id = %s", (vulnerability_id,))
        vuln = cursor.fetchone()
        conn.close()
        if not vuln:
            return {"error": "Vulnerability not found"}

        red_brief = generate_mission_brief(vuln['cve_id'], vuln['description'], vuln['cvss_score'], vuln['asset'])
        blue_brief = generate_blue_team_brief(vuln['cve_id'], vuln['description'])
        return {
            "cve_id": vuln['cve_id'],
            "red_team_brief": red_brief,
            "blue_team_brief": blue_brief
        }
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

            print(f"🏗️  Resolving vulnerable environment for {vuln['cve_id']}...")
            image_tag = build_cve_image(docker_client, vuln['cve_id'], vuln['description'])
            print(f"   Using image: {image_tag}")

            log_config = LogConfig(
                driver="splunk",
                options={
                    "splunk-token": "bb056fbe-a182-4ff6-8612-803df97d6d24",
                    "splunk-url": "https://172.16.25.2:8088",
                    "splunk-insecureskipverify": "true",
                    "splunk-sourcetype": "docker",
                    "splunk-index": "cyber_range",
                    "splunk-verify-connection": "false",
                    "mode": "non-blocking",
                    "max-buffer-size": "2m",
                    "tag": f"mission-{vulnerability_id}"
                }
            )

            host_config = docker_client.api.create_host_config(
                port_bindings={80: free_port},
                log_config=log_config
            )

            container_id = docker_client.api.create_container(
                image=image_tag,
                host_config=host_config,
                name=container_name,
                detach=True
            )

            docker_client.api.start(container=container_id)

            container = docker_client.containers.get(container_name)
            print(f"Container {container_name} started on port {free_port} with Splunk logging")

            print("⏳ Waiting for target to become ready...")
            target_ready = wait_for_container_ready(free_port)
            print(f"   Target ready: {target_ready}")

            if vuln['platform_status'] == 'pending':
                cursor.execute("""
                    UPDATE platform_vulnerabilities
                    SET platform_status = 'active'
                    WHERE id = %s
                """, (vulnerability_id,))
            # if archived, leave it archived

            cursor.execute("""
                INSERT INTO missions (vulnerability_id, cve_id, red_team_brief, blue_team_brief, status, created_at)
                VALUES (%s, %s, %s, %s, 'active', %s)
            """, (vulnerability_id, vuln['cve_id'], red_brief, blue_brief, datetime.now()))

            conn.commit()
            conn.close()

            return {
                "status": "success",
                "cve_id": vuln['cve_id'],
                "red_team_brief": red_brief,
                "blue_team_brief": blue_brief,
                "container_name": container_name,
                "container_port": free_port,
                "app_url": f"http://localhost:{free_port}",
                "target_ready": target_ready
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