#!/bin/bash

# Cyber Range Platform - Ubuntu Installation Script
# Run with: chmod +x scripts/install_ubuntu.sh && ./scripts/install_ubuntu.sh

set -e  # Stop on any error

echo "======================================"
echo "  Cyber Range Platform Installer (Ubuntu)"
echo "======================================"

# --------------------------------------------------
# 1. Update system packages
# --------------------------------------------------
echo ""
echo "[1/6] Updating system packages..."
sudo apt update && sudo apt upgrade -y

# --------------------------------------------------
# 2. Install Docker
# --------------------------------------------------
echo ""
echo "[2/6] Installing Docker..."
sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
echo "✅ Docker installed"

# --------------------------------------------------
# 3. Install Python and pip
# --------------------------------------------------
echo ""
echo "[3/6] Installing Python 3 and pip..."
sudo apt install -y python3 python3-pip python3-venv
echo "✅ Python installed"

# --------------------------------------------------
# 4. Install Ollama
# --------------------------------------------------
echo ""
echo "[4/6] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh
echo "✅ Ollama installed"

# --------------------------------------------------
# 5. Pull the Phi-3-mini model
# --------------------------------------------------
echo ""
echo "[5/6] Pulling Phi-3-mini AI model..."
ollama pull phi3:mini
echo "✅ AI model downloaded"

# --------------------------------------------------
# 6. Install Python dependencies
# --------------------------------------------------
echo ""
echo "[6/6] Installing Python dependencies..."
pip3 install -r requirements.txt
echo "✅ Python dependencies installed"

# --------------------------------------------------
# 7. Start Docker container (vulnerable app)
# --------------------------------------------------
echo ""
echo "Building and starting the vulnerable container..."
docker build -t custom-vuln-app ./containers
docker run -d -p 8080:80 --name custom-vuln-app custom-vuln-app

# --------------------------------------------------
# 8. Done
# --------------------------------------------------
echo ""
echo "======================================"
echo "  ✅ Installation Complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "  1. Start the FastAPI backend:"
echo "     cd backend && python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "  2. Test the AI:"
echo "     ollama run phi3:mini 'Explain SQL injection in one sentence'"
echo ""
echo "  3. Open the learner interface:"
echo "     http://localhost:8000/"
echo ""