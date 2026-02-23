# OpenClaw Pi Dashboard - Installation Script

#!/bin/bash

set -e

INSTALL_DIR="$HOME/OpenClaw-Pi-Dashboard"
SERVICE_NAME="openclaw-pi-dashboard"
REPO_URL="https://github.com/Ryan-W31/OpenClaw-Pi-Dashboard.git"

echo "🚀 Installing OpenClaw Pi Dashboard..."

# Clone repository
echo "📦 Cloning repository..."
if [ -d "$INSTALL_DIR" ]; then
    echo "Directory exists, pulling latest changes..."
    cd "$INSTALL_DIR"
    git pull
else
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Copy config if it doesn't exist
if [ ! -f "config.json" ]; then
    echo "⚙️  Creating default configuration..."
    cp config.json.example config.json
    echo "⚠️  IMPORTANT: Edit config.json to set your password!"
fi

# Install systemd service
echo "🔧 Installing systemd service..."
cat > /tmp/$SERVICE_NAME.service << 'EOF'
[Unit]
Description=OpenClaw Pi Dashboard
After=network.target

[Service]
Type=simple
User=%USER%
WorkingDirectory=%WORK_DIR%
Environment="PATH=%WORK_DIR%/venv/bin"
Environment="DASHBOARD_CONFIG=%WORK_DIR%/config.json"
ExecStart=%WORK_DIR%/venv/bin/python %WORK_DIR%/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Replace variables in service file
sed -i "s|%USER%|$USER|g" /tmp/$SERVICE_NAME.service
sed -i "s|%WORK_DIR%|$INSTALL_DIR|g" /tmp/$SERVICE_NAME.service

sudo mv /tmp/$SERVICE_NAME.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit your config: nano $INSTALL_DIR/config.json"
echo "   - Set a strong password"
echo "   - Configure allowed hosts or use localhost + SSH tunnel"
echo ""
echo "2. Start the service:"
echo "   sudo systemctl start $SERVICE_NAME"
echo ""
echo "3. Check status:"
echo "   sudo systemctl status $SERVICE_NAME"
echo ""
echo "4. Access the dashboard (with SSH tunnel):"
echo "   ssh -L 5000:localhost:5000 $(whoami)@$(hostname -I | awk '{print $1}')"
echo "   Then open: http://localhost:5000"
