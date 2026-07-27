# Cyber Range Platform - Windows Development Setup
# Run with: powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Cyber Range Platform Setup (Windows)" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# --------------------------------------------------
# 1. Check if Docker is installed
# --------------------------------------------------
Write-Host ""
Write-Host "[1/5] Checking Docker..." -ForegroundColor Yellow
try {
    docker --version
    Write-Host "✅ Docker is installed" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not installed." -ForegroundColor Red
    Write-Host "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop" -ForegroundColor Red
    exit 1
}

# --------------------------------------------------
# 2. Check if Python is installed
# --------------------------------------------------
Write-Host ""
Write-Host "[2/5] Checking Python..." -ForegroundColor Yellow
try {
    python --version
    Write-Host "✅ Python is installed" -ForegroundColor Green
} catch {
    Write-Host "❌ Python is not installed." -ForegroundColor Red
    Write-Host "Please install Python from: https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "Make sure to check 'Add Python to PATH' during installation."
    exit 1
}

# --------------------------------------------------
# 3. Install Python dependencies
# --------------------------------------------------
Write-Host ""
Write-Host "[3/5] Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt
Write-Host "✅ Python dependencies installed" -ForegroundColor Green

# --------------------------------------------------
# 4. Check if Ollama is installed
# --------------------------------------------------
Write-Host ""
Write-Host "[4/5] Checking Ollama..." -ForegroundColor Yellow
try {
    ollama --version
    Write-Host "✅ Ollama is installed" -ForegroundColor Green
} catch {
    Write-Host "❌ Ollama is not installed." -ForegroundColor Red
    Write-Host "Please install Ollama from: https://ollama.com/download/windows" -ForegroundColor Red
    Write-Host "After installing, run: ollama pull phi3:mini" -ForegroundColor Yellow
    exit 1
}

# --------------------------------------------------
# 5. Build and run the Docker container
# --------------------------------------------------
Write-Host ""
Write-Host "[5/5] Building and running the vulnerable container..." -ForegroundColor Yellow
docker build -t custom-vuln-app ./containers
docker rm -f custom-vuln-app 2>$null
docker run -d -p 8080:80 --name custom-vuln-app custom-vuln-app
Write-Host "✅ Container running on http://localhost:8080" -ForegroundColor Green

# --------------------------------------------------
# 6. Done
# --------------------------------------------------
Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  ✅ Setup Complete!" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Start the FastAPI backend:" -ForegroundColor White
Write-Host "     cd backend" -ForegroundColor White
Write-Host "     python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000" -ForegroundColor White
Write-Host ""
Write-Host "  2. Open the learner interface:" -ForegroundColor White
Write-Host "     http://localhost:8000/" -ForegroundColor White
Write-Host ""