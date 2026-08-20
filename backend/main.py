from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
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
import json, queue, threading
import re as _re
from pathlib import Path
from pydantic import BaseModel
from typing import Optional
from fastapi.responses import StreamingResponse as FileStream
import io
from fastapi.responses import HTMLResponse as HTML
from ai_helper import get_pattern_explainer




# Load environment variables
load_dotenv(Path(__file__).parent.parent / ".env")
print(f"🔑 Splunk token loaded: {len(os.getenv('SPLUNK_HEC_TOKEN', ''))} chars")

app = FastAPI(title="Cyber Range Platform API", version="0.1.0")

REQ_RE = _re.compile(r'"(GET|POST) ([^"]+?) HTTP/[\d.]+" (\d{3})')


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



_in_flight = set()   # guards against double-launch server-side
_in_flight_lock = threading.Lock()

def wait_for_container_ready(port: int, timeout: int = 20, emit=None) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"http://localhost:{port}/", timeout=1)
            if r.status_code < 500:
                return True
        except requests.exceptions.RequestException:
            pass
        if emit:
            emit("waiting", f"Waiting for target… {int(deadline - time.time())}s left")
        time.sleep(0.5)
    return False


def _run_mission_start(vulnerability_id: int, emit):
    conn = get_platform_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM platform_vulnerabilities WHERE id = %s", (vulnerability_id,))
    vuln = cursor.fetchone()
    if not vuln:
        conn.close()
        raise ValueError("Vulnerability not found")

    cached = BRIEF_CACHE.get(vulnerability_id)
    if cached:
        red_brief, blue_brief = cached["red"], cached["blue"]
    else:
        emit("briefs", f"Generating AI briefs for {vuln['cve_id']}…")
        red_brief = generate_mission_brief(vuln['cve_id'], vuln['description'],
                                           vuln['cvss_score'], vuln['asset'])
        blue_brief = generate_blue_team_brief(vuln['cve_id'], vuln['description'])
        BRIEF_CACHE[vulnerability_id] = {"red": red_brief, "blue": blue_brief}

    free_port = find_free_port()
    if not free_port:
        conn.close()
        raise RuntimeError("No free ports available")

    container_name = f"mission-{vulnerability_id}"
    try:
        existing = docker_client.containers.get(container_name)
        emit("cleanup", f"Removing previous container {container_name}…")
        existing.stop()
        existing.remove()
    except docker.errors.NotFound:
        pass

    emit("image", f"Resolving vulnerable environment for {vuln['cve_id']}…")
    image_tag, pattern, lab = build_cve_image(docker_client, vuln['cve_id'],
                                              vuln['description'], emit=emit)
    emit("image", f"Using image {image_tag} (pattern: {pattern})")

    log_config = {
        "Type": "splunk",
        "Config": {
            "splunk-token": os.getenv("SPLUNK_HEC_TOKEN", ""),
            "splunk-url": os.getenv("SPLUNK_HEC_URL", "https://172.16.25.2:8088"),
            "splunk-insecureskipverify": "true",
            "splunk-sourcetype": "docker",
            "splunk-index": "cyber_range",
            "splunk-verify-connection": "true",
            "splunk-format": "json",
            "tag": f"mission-{vulnerability_id}",
        }
    }
    
    emit("container", f"Starting container on port {free_port}…")

    def _create_and_start(with_logging: bool):
        if with_logging:
            hc = docker_client.api.create_host_config(
                port_bindings={80: free_port}, log_config=log_config)
        else:
            hc = docker_client.api.create_host_config(port_bindings={80: free_port})
        cid = docker_client.api.create_container(
            image=image_tag, host_config=hc, name=container_name, detach=True)
        docker_client.api.start(container=cid)
        return cid

    splunk_ok = True
    try:
        container_id = _create_and_start(True)
    except Exception as e:
        msg = str(e).lower()
        if "logging driver" in msg or "splunk" in msg or "8088" in msg:
            splunk_ok = False
            emit("container", "⚠️ Splunk unreachable — starting without log forwarding. "
                              "The Blue Team phase will have no data.")
            try:
                docker_client.containers.get(container_name).remove(force=True)
            except Exception:
                pass
            container_id = _create_and_start(False)
        else:
            raise

    target_ready = wait_for_container_ready(free_port, emit=emit)

    if vuln['platform_status'] == 'pending':
        cursor.execute("UPDATE platform_vulnerabilities SET platform_status='active' WHERE id=%s",
                       (vulnerability_id,))
    cursor.execute("""
        INSERT INTO missions (vulnerability_id, cve_id, red_team_brief, blue_team_brief, status, created_at)
        VALUES (%s, %s, %s, %s, 'active', %s)
    """, (vulnerability_id, vuln['cve_id'], red_brief, blue_brief, datetime.now()))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "cve_id": vuln['cve_id'],
        "description": vuln['description'],
        "red_team_brief": red_brief,
        "blue_team_brief": blue_brief,
        "container_name": container_name,
        "container_port": free_port,
        "app_url": f"http://localhost:{free_port}",
        "target_ready": target_ready,
        "pattern": pattern,
        "explainer": get_pattern_explainer(pattern),
        "lab": lab,
    }


@app.get("/missions/{vulnerability_id}/start_stream")
def start_mission_stream(vulnerability_id: int):
    q = queue.Queue()

    def emit(stage, message, **extra):
        q.put({"stage": stage, "message": message, **extra})

    def work():
        # claim this mission id atomically
        with _in_flight_lock:
            if vulnerability_id in _in_flight:
                q.put({"stage": "error", "message": "This mission is already starting."})
                q.put(None)
                return
            _in_flight.add(vulnerability_id)

        try:
            result = _run_mission_start(vulnerability_id, emit)
            q.put({"stage": "done", "message": "Environment ready", "result": result})
        except Exception as e:
            import traceback
            traceback.print_exc()
            q.put({"stage": "error", "message": str(e)})
        finally:
            with _in_flight_lock:
                _in_flight.discard(vulnerability_id)
            q.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        while True:
            try:
                item = q.get(timeout=1.0)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if item is None:
                break
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )
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
def get_hint(task_name: str, current_step: str, actions: str = "",
             cve_description: str = "", vulnerability_id: int = None):
    action_list = [a for a in actions.split(",") if a.strip()] if actions else []

    activity, lab = [], {}
    if vulnerability_id is not None:
        data = mission_activity(vulnerability_id)
        activity = [f"{r['method']} {r['path']} -> {r['status']}" for r in data.get("requests", [])]
        try:
            container = docker_client.containers.get(f"mission-{vulnerability_id}")
            img = docker_client.images.get(container.image.id)
            lab = json.loads((img.labels or {}).get("cyber_range_lab") or "{}")
        except Exception:
            lab = {}

    return {"hint": generate_hint(task_name, current_step, action_list,
                                  cve_description, activity, lab)}

class ReportSubmission(BaseModel):
    cve_id: str = ""
    pattern: str = ""
    payload: str = ""
    attack_description: str = ""
    detection_method: str = ""
    detection_rule: str = ""
    recommendations: str = ""
    duration_seconds: int = 0


@app.post("/ai/grade")
def grade_learner_report(sub: ReportSubmission):
    combined = (
        f"1. ATTACK DESCRIPTION\n{sub.attack_description}\n\n"
        f"2. DETECTION METHOD\n{sub.detection_method}\n\n"
        f"3. BLOCKING RULE\n{sub.detection_rule}\n\n"
        f"4. RECOMMENDATIONS\n{sub.recommendations}"
    )
    result = grade_report(combined, [], sub.cve_id, sub.pattern,
                          sub.payload, sub.detection_rule)
    REPORT_CACHE[sub.cve_id or "last"] = {"submission": sub.model_dump(), "grade": result}
    return result


REPORT_CACHE = {}


@app.post("/report/pdf")
def report_pdf(sub: ReportSubmission):
    """Generate a downloadable incident report PDF including AI feedback."""
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, Preformatted)

    cached = REPORT_CACHE.get(sub.cve_id or "last", {})
    grade = cached.get("grade") or grade_report(
        f"{sub.attack_description}\n{sub.detection_method}\n"
        f"{sub.detection_rule}\n{sub.recommendations}",
        [], sub.cve_id, sub.pattern, sub.payload, sub.detection_rule)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER,
                            leftMargin=0.9*inch, rightMargin=0.9*inch,
                            topMargin=0.9*inch, bottomMargin=0.9*inch,
                            title=f"Incident Report — {sub.cve_id}")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=17,
                        textColor=colors.HexColor("#0d9488"), spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12,
                        textColor=colors.HexColor("#1e293b"), spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=10, leading=15)
    mono = ParagraphStyle("mono", parent=ss["Code"], fontSize=9,
                          backColor=colors.HexColor("#f1f5f9"), leading=13)

    def esc(t):
        return (str(t or "Not provided")
                .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    story = [Paragraph("Incident Report", h1),
             Paragraph(f"{esc(sub.cve_id)} &mdash; "
                       f"{esc(sub.pattern).replace('_', ' ').title()}", body),
             Paragraph(datetime.now().strftime("Generated %d %B %Y at %H:%M"), body),
             Spacer(1, 14)]

    sec = grade.get("sections", {}) or {}
    rows = [["Section", "Score"],
            ["Attack description", f"{sec.get('attack', '—')} / 25"],
            ["Detection method", f"{sec.get('detection', '—')} / 25"],
            ["Blocking rule", f"{sec.get('rule', '—')} / 25"],
            ["Recommendations", f"{sec.get('recommendations', '—')} / 25"],
            ["Overall", f"{grade.get('score', 0)} / 100"]]
    t = Table(rows, colWidths=[3.6*inch, 1.4*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d9488")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f0fdfa")),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [t, Spacer(1, 6)]

    story += [Paragraph("Assessor feedback", h2),
              Paragraph(esc(grade.get("feedback")), body)]
    if grade.get("strengths"):
        story.append(Paragraph("<b>Strengths</b>", body))
        for s in grade["strengths"]:
            story.append(Paragraph("&bull; " + esc(s), body))
    if grade.get("improvements"):
        story.append(Paragraph("<b>Areas to improve</b>", body))
        for s in grade["improvements"]:
            story.append(Paragraph("&bull; " + esc(s), body))

    if sub.payload:
        story += [Paragraph("Verified exploit", h2),
                  Preformatted(f"GET {sub.payload}", mono)]

    story += [Paragraph("1. Attack description", h2), Paragraph(esc(sub.attack_description), body),
              Paragraph("2. Detection method", h2), Paragraph(esc(sub.detection_method), body),
              Paragraph("3. Blocking rule deployed", h2), Preformatted(str(sub.detection_rule or "None"), mono),
              Paragraph("4. Recommendations", h2), Paragraph(esc(sub.recommendations), body)]

    if sub.duration_seconds:
        story += [Spacer(1, 12),
                  Paragraph(f"Time on mission: {sub.duration_seconds // 60}m "
                            f"{sub.duration_seconds % 60}s", body)]

    doc.build(story)
    buf.seek(0)
    safe = _re.sub(r'[^A-Za-z0-9\-]', '-', sub.cve_id or "report")
    return FileStream(buf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="incident-report-{safe}.pdf"'
    })


@app.get("/ai/score")
def score_cve(cve_id: str, description: str, cvss_score: float, is_kev: bool = False):
    score = score_cve_interestingness(cve_id, description, cvss_score, is_kev)
    return {"cve": cve_id, "interestingness_score": score}

@app.get("/ai/command_suggest")
def get_command_suggestion(goal: str, current_step: str, cve_description: str = "",
                           vulnerability_id: int = None):
    lab = {}
    if vulnerability_id is not None:
        try:
            container = docker_client.containers.get(f"mission-{vulnerability_id}")
            img = docker_client.images.get(container.image.id)
            lab = json.loads((img.labels or {}).get("cyber_range_lab") or "{}")
        except Exception:
            lab = {}
    return {"suggestion": generate_command_suggestion(goal, current_step, cve_description, lab)}
    
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

BRIEF_CACHE = {}
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
        BRIEF_CACHE[vulnerability_id] = {"red": red_brief, "blue": blue_brief}
        return {
            "cve_id": vuln['cve_id'],
            "red_team_brief": red_brief,
            "blue_team_brief": blue_brief
        }
    except Exception as e:
        return {"error": str(e)}

@app.post("/missions/{vulnerability_id}/start")
def start_mission(vulnerability_id: int):
    build_log = []
    def log(msg):
        print(msg)
        build_log.append(msg)

    try:
        conn = get_platform_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cursor.execute("SELECT * FROM platform_vulnerabilities WHERE id = %s", (vulnerability_id,))
        vuln = cursor.fetchone()

        if not vuln:
            conn.close()
            return {"error": "Vulnerability not found"}

        log(f"🤖 Generating AI briefs for {vuln['cve_id']}...")
        red_brief = generate_mission_brief(vuln['cve_id'], vuln['description'], vuln['cvss_score'], vuln['asset'])
        blue_brief = generate_blue_team_brief(vuln['cve_id'], vuln['description'])

        free_port = find_free_port()
        if not free_port:
            conn.close()
            return {"error": "No free ports available"}

        log(f"🐳 Starting container on port {free_port}...")
        try:
            container_name = f"mission-{vulnerability_id}"

            try:
                existing = docker_client.containers.get(container_name)
                existing.stop()
                existing.remove()
                log(f"Removed existing container: {container_name}")
            except docker.errors.NotFound:
                pass

            log(f"🏗️  Resolving vulnerable environment for {vuln['cve_id']}...")

            result = build_cve_image(docker_client, vuln['cve_id'], vuln['description'])
            if isinstance(result, tuple) and len(result) == 2:
                image_tag, pattern = result
            else:
                image_tag, pattern = result, "unknown"
            log(f"   Using image: {image_tag} (pattern: {pattern})")

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
            log(f"Container {container_name} started on port {free_port} with Splunk logging")

            log("⏳ Waiting for target to become ready...")
            target_ready = wait_for_container_ready(free_port)
            log(f"   Target ready: {target_ready}")

            if vuln['platform_status'] == 'pending':
                cursor.execute("""
                    UPDATE platform_vulnerabilities SET platform_status = 'active' WHERE id = %s
                """, (vulnerability_id,))

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
                "target_ready": target_ready,
                "pattern": pattern,          # <-- new: frontend needs this for terminal commands
                "build_log": build_log
            }

        except Exception as e:
            conn.close()
            return {"error": f"Container error: {str(e)}", "build_log": build_log}

    except Exception as e:
        return {"error": str(e)}

@app.get("/missions/{vulnerability_id}/proxy")
def proxy_target(vulnerability_id: int, path: str = "/"):
    """Relay a request to this mission's container so the terminal can hit it for real."""
    try:
        container = docker_client.containers.get(f"mission-{vulnerability_id}")
        port = container.attrs["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"]
    except Exception as e:
        return {"error": f"Target container not reachable: {e}"}

    if not path.startswith("/"):
        path = "/" + path
    try:
        r = requests.get(f"http://localhost:{port}{path}", timeout=8)
        st = _state(vulnerability_id)
        st["requests"].append({"method": "GET", "path": path, "status": r.status_code})
        st["requests"] = st["requests"][-100:]
        return {"status": r.status_code, "body": r.text[:6000]}
    except Exception as e:
        return {"error": str(e)}


@app.post("/admin/purge_images")
def purge_cve_images(include_containers: bool = True):
    """Remove all generated CVE lab images (and optionally their containers)."""
    removed_containers, removed_images, errors = [], [], []

    if include_containers:
        for c in docker_client.containers.list(all=True):
            if c.name.startswith("mission-"):
                try:
                    c.remove(force=True)
                    removed_containers.append(c.name)
                except Exception as e:
                    errors.append(f"{c.name}: {e}")

    for img in docker_client.images.list():
        tags = img.tags or []
        if any(t.startswith("cve-vuln-") for t in tags):
            try:
                docker_client.images.remove(img.id, force=True)
                removed_images.extend(tags)
            except Exception as e:
                errors.append(f"{tags}: {e}")

    BRIEF_CACHE.clear()
    return {
        "removed_containers": removed_containers,
        "removed_images": removed_images,
        "errors": errors,
    }


@app.on_event("startup")
def cleanup_stale_missions():
    """Remove leftover mission containers from a previous backend run."""
    if docker_client is None:
        return
    removed = []
    for c in docker_client.containers.list(all=True):
        if c.name.startswith("mission-"):
            try:
                c.remove(force=True)
                removed.append(c.name)
            except Exception as e:
                print(f"⚠️  Could not remove {c.name}: {e}")
    if removed:
        print(f"🧹 Cleaned up {len(removed)} stale mission container(s): {', '.join(removed)}")


@app.get("/missions/{vulnerability_id}/activity")
def mission_activity(vulnerability_id: int, limit: int = 40):
    return {"requests": _state(vulnerability_id)["requests"][-limit:]}


from fastapi import Response
from urllib.parse import urlencode
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_WEB = os.getenv("SPLUNK_WEB_URL", "http://172.16.25.2:8000")

_HOP_BY_HOP = {
    "content-encoding", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "upgrade", "x-frame-options", "content-security-policy",
}


@app.api_route("/splunk-proxy/{path:path}",
               methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def splunk_proxy(path: str, request: Request):
    """Reverse-proxy Splunk Web so it can be embedded same-origin in an iframe."""
    url = f"{SPLUNK_WEB}/{path}"
    if request.url.query:
        url += "?" + request.url.query

    fwd = {k: v for k, v in request.headers.items()
           if k.lower() not in ("host", "content-length", "accept-encoding")}
    body = await request.body()

    try:
        r = requests.request(
            request.method, url,
            headers=fwd,
            data=body if body else None,
            cookies=request.cookies,
            allow_redirects=False,
            verify=False,
            timeout=30,
        )
    except Exception as e:
        return Response(content=f"Splunk unreachable at {SPLUNK_WEB}: {e}",
                        status_code=502, media_type="text/plain")

    out = {k: v for k, v in r.headers.items() if k.lower() not in _HOP_BY_HOP}

    # rewrite redirects and Set-Cookie paths back through the proxy
    if "location" in {k.lower() for k in out}:
        for k in list(out):
            if k.lower() == "location":
                loc = out.pop(k)
                if loc.startswith(SPLUNK_WEB):
                    loc = loc[len(SPLUNK_WEB):]
                if loc.startswith("/"):
                    loc = "/splunk-proxy" + loc
                out["location"] = loc

    content = r.content
    ctype = r.headers.get("content-type", "")
    if any(t in ctype for t in ("text/html", "javascript", "text/css", "application/json")):
        text = content.decode("utf-8", errors="replace")
        text = text.replace('"/en-US/', '"/splunk-proxy/en-US/')
        text = text.replace("'/en-US/", "'/splunk-proxy/en-US/")
        text = text.replace('"/static/', '"/splunk-proxy/static/')
        text = text.replace("'/static/", "'/splunk-proxy/static/")
        text = text.replace('"/api/', '"/splunk-proxy/api/')
        text = text.replace('"/servicesNS/', '"/splunk-proxy/servicesNS/')
        content = text.encode("utf-8")

    resp = Response(content=content, status_code=r.status_code,
                    headers=out, media_type=ctype or None)
    for c in r.cookies:
        resp.set_cookie(c.name, c.value, path="/splunk-proxy")
    return resp

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




class RuleTest(BaseModel):
    rule: str
    payload: str


def _recreate_with_rule(vulnerability_id: int, rule: str):
    """Recreate the mission container with WAF_RULE set, on the same port."""
    name = f"mission-{vulnerability_id}"
    old = docker_client.containers.get(name)
    image_tag = old.image.tags[0] if old.image.tags else old.image.id
    port = old.attrs["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"]

    old.remove(force=True)

    log_config = {
        "Type": "splunk",
        "Config": {
            "splunk-token": os.getenv("SPLUNK_HEC_TOKEN", ""),
            "splunk-url": os.getenv("SPLUNK_HEC_URL", "https://172.16.25.2:8088"),
            "splunk-insecureskipverify": "true",
            "splunk-sourcetype": "docker",
            "splunk-index": "cyber_range",
            "splunk-verify-connection": "true",
            "splunk-format": "json",
            "tag": f"mission-{vulnerability_id}",
        },
    }
    host_config = docker_client.api.create_host_config(
        port_bindings={80: int(port)}, log_config=log_config)

    cid = docker_client.api.create_container(
        image=image_tag, name=name, detach=True,
        environment={"WAF_RULE": rule},
        host_config=host_config)
    docker_client.api.start(container=cid)
    return int(port)


@app.post("/missions/{vulnerability_id}/test_rule")
def test_rule(vulnerability_id: int, sub: RuleTest):
    """Redeploy the target with the learner's rule, then replay the winning payload."""
    rule = sub.rule.strip()
    if not rule:
        return {"error": "No rule submitted."}

    try:
        _re.compile(rule)
    except _re.error as e:
        return {"blocked": False, "verdict": "invalid",
                "message": f"That isn't a valid pattern: {e}"}

    if not sub.payload:
        return {"error": "No recorded attack to replay — capture the flag first."}

    try:
        port = _recreate_with_rule(vulnerability_id, rule)
    except Exception as e:
        return {"error": f"Could not redeploy target: {e}"}

    if not wait_for_container_ready(port, timeout=20):
        return {"error": "Target did not come back up after redeploy."}

    # 1. replay the attack
    try:
        atk = requests.get(f"http://localhost:{port}{sub.payload}", timeout=8)
        atk_body, atk_status = atk.text, atk.status_code
    except Exception as e:
        return {"error": f"Replay failed: {e}"}

    still_works = "FLAG-FOUND" in atk_body and atk_status == 200

    # 2. make sure normal traffic still passes (no over-blocking)
    try:
        ok = requests.get(f"http://localhost:{port}/", timeout=8)
        legit_ok = ok.status_code == 200
    except Exception:
        legit_ok = False

    if still_works:
        verdict, message = "bypassed", (
            "Your rule did not stop the attack — the exact same request still "
            "returns the flag. Look at the payload again and find the "
            "characteristic your pattern is missing.")
    elif not legit_ok:
        verdict, message = "overblocking", (
            "The attack was stopped, but normal traffic is blocked too. A rule "
            "that breaks the application isn't deployable — make it more specific.")
    else:
        verdict, message = "effective", (
            "The attack is blocked and legitimate requests still work. "
            "That's a deployable rule.")

    return {
        "blocked": not still_works,
        "verdict": verdict,
        "message": message,
        "replayed": sub.payload,
        "attack_status": atk_status,
        "legit_ok": legit_ok,
    }



MISSION_STATE = {}   # vuln_id -> {"requests": [...], "flag_path": str|None}


def _state(vid: int):
    return MISSION_STATE.setdefault(vid, {"requests": [], "flag_path": None})


def _target_port(vid: int):
    c = docker_client.containers.get(f"mission-{vid}")
    return c.attrs["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"]


@app.get("/missions/{vulnerability_id}/browse", response_class=HTML)
def browse_target(vulnerability_id: int, request: Request, path: str = "/"):
    """Serve the target through the backend so Target-tab traffic is observable."""
    params = dict(request.query_params)
    params.pop("path", None)
    real_path = params.pop("__path", path) or "/"
    if not real_path.startswith("/"):
        real_path = "/" + real_path
    qs = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
    full = real_path + ("?" + qs if qs else "")

    try:
        port = _target_port(vulnerability_id)
        r = requests.get(f"http://localhost:{port}{full}", timeout=8)
        body, status = r.text, r.status_code
    except Exception as e:
        return HTML(f"<pre>Target unreachable: {e}</pre>", status_code=502)

    st = _state(vulnerability_id)
    st["requests"].append({"method": "GET", "path": full, "status": status})
    st["requests"] = st["requests"][-100:]

    if "FLAG-FOUND" in body and not st["flag_path"]:
        st["flag_path"] = full
        print(f"🚩 Flag captured via Target tab: {full}")

    base = f"/missions/{vulnerability_id}/browse"
    # keep navigation inside the proxy
    body = _re.sub(r'action=(["\'])(/[^"\']*)\1',
                   lambda m: f'action="{base}"><input type="hidden" name="__path" value="{m.group(2)}"',
                   body)
    body = _re.sub(r'href=(["\'])(/[^"\']*)\1',
                   lambda m: f'href="{base}?path={m.group(2)}"', body)
    return HTML(body, status_code=status)


@app.get("/missions/{vulnerability_id}/flag_status")
def flag_status(vulnerability_id: int):
    return {"flag_path": _state(vulnerability_id)["flag_path"]}