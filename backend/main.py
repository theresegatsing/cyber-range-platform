from fastapi import FastAPI, HTTPException
import docker

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

# Health check endpoint
@app.get("/")
def root():
    return {"message": "Cyber Range Platform API is running!"}

# Check if the container is running
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

# Start the container
@app.post("/container/start")
def start_container():
    if docker_client is None:
        raise HTTPException(status_code=500, detail="Docker not available")
    
    try:
        # Check if container exists
        try:
            container = docker_client.containers.get(CONTAINER_NAME)
            if container.status == "running":
                return {"message": f"Container '{CONTAINER_NAME}' is already running"}
            else:
                container.start()
                return {"message": f"Container '{CONTAINER_NAME}' started successfully"}
        except docker.errors.NotFound:
            # Container doesn't exist, create it
            container = docker_client.containers.run(
                IMAGE_NAME,
                detach=True,
                ports={'80/tcp': 8080},
                name=CONTAINER_NAME
            )
            return {"message": f"Container '{CONTAINER_NAME}' created and started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Stop the container
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