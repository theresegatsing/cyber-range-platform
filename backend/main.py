from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
import docker
import requests

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

# ----------------------------------------------------------
# PHASE 3: The Learner Interface (HTML Form)
# ----------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
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
            .status { color: green; font-weight: bold; }
            .error { color: red; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🔐 SQL Injection Training Lab</h1>
        <p><strong>Mission:</strong> The database stores user credentials. Your goal is to retrieve <strong>ALL</strong> users by exploiting a SQL injection vulnerability.</p>
        
        <h3>📝 Instructions</h3>
        <ul>
            <li>Open the vulnerable app: <a href="http://localhost:8080/vuln?id=1" target="_blank">http://localhost:8080/vuln?id=1</a></li>
            <li>This returns only user <strong>1</strong> (admin).</li>
            <li>Now, craft a SQL injection payload that returns <strong>ALL</strong> users.</li>
            <li>Type your payload into the box below and click "Exploit".</li>
        </ul>

        <form action="/exploit" method="get">
            <label for="payload">🧪 Enter your SQL injection payload:</label><br><br>
            <input type="text" id="payload" name="payload" placeholder="e.g., 1 OR 1=1" style="width: 100%; padding: 10px; font-size: 16px;">
            <br><br>
            <button type="submit">🚀 Exploit</button>
        </form>
        
        <hr>
        <p><strong>💡 Hint:</strong> The column is an integer. Try <code>1 OR 1=1</code> or <code>1 OR '1'='1</code>.</p>
    </body>
    </html>
    """

# ----------------------------------------------------------
# PHASE 3: The Exploit Proxy (Learner submits payload here)
# ----------------------------------------------------------
@app.get("/exploit", response_class=HTMLResponse)
def exploit(request: Request):
    payload = request.query_params.get("payload", "")
    
    if not payload:
        return """
        <html><body>
            <h2>⚠️ No payload provided.</h2>
            <a href="/">Go back</a>
        </body></html>
        """
    
    # Send the payload to the vulnerable app
    try:
        response = requests.get(VULN_APP_URL, params={"id": payload})
        
        # Check if the vulnerable app is running
        if response.status_code != 200:
            return f"""
            <html><body>
                <h2>❌ Error: Vulnerable app returned status {response.status_code}</h2>
                <p>Make sure the container is running. Use the API to start it.</p>
                <a href="/">Go back</a>
            </body></html>
            """
        
        # Display the result
        return f"""
        <html>
        <head>
            <title>Exploit Result</title>
            <style>
                body {{ font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }}
                .success {{ color: green; font-weight: bold; }}
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
            <a href="/">← Back to training</a>
        </body>
        </html>
        """
    
    except requests.exceptions.ConnectionError:
        return f"""
        <html><body>
            <h2>❌ Connection Error</h2>
            <p>Could not reach the vulnerable app on port 8080.</p>
            <p>Make sure the container is running using the API.</p>
            <a href="/">Go back</a>
        </body></html>
        """

# ----------------------------------------------------------
# PHASE 2: Container Control Endpoints (Already Built)
# ----------------------------------------------------------
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