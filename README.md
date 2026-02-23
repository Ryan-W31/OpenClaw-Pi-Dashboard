# OpenClaw Pi Dashboard

A secure, real-time Raspberry Pi monitoring dashboard built with Flask and Server-Sent Events.

![Dashboard Preview](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/python-3.9+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- 📊 **Real-time Metrics**: CPU, memory, temperature, uptime, disk, and network monitoring
- 🔄 **Live Updates**: Server-Sent Events (SSE) for instant data refresh
- 🤖 **Assistant Status**: Configurable "Sak is Awake" style indicator
- 🔒 **Security First**: Optional HTTP Basic Auth, host-based access control, no shell execution
- ⚙️ **Highly Configurable**: JSON-based configuration for branding, metrics, and security
- 📱 **Responsive Design**: Mobile-friendly dark UI with Tailwind CSS
- 🚀 **Lightweight**: Minimal dependencies, runs smoothly on Raspberry Pi Zero 2W and up

## Quick Start

### Prerequisites

- Raspberry Pi (any model) or Linux system
- Python 3.9 or higher
- pip

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/Ryan-W31/OpenClaw-Pi-Dashboard.git
cd OpenClaw-Pi-Dashboard
```

2. **Create a virtual environment** (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Configure the dashboard**:
```bash
cp config.json.example config.json
# Edit config.json to customize settings
```

5. **Run the dashboard**:
```bash
python app.py
```

6. **Access the dashboard**:
Open your browser to `http://your-pi-ip:5000`

## Configuration

Edit `config.json` to customize your dashboard:

```json
{
  "assistant": {
    "name": "Sak",
    "status_indicator": true,
    "awake_message": "{name} is Awake",
    "sleeping_message": "{name} is Sleeping"
  },
  "branding": {
    "title": "OpenClaw Pi Dashboard",
    "theme_color": "#3b82f6"
  },
  "metrics": {
    "enabled": ["cpu", "memory", "temperature", "uptime", "disk", "network"],
    "update_interval": 2,
    "temperature_unit": "celsius"
  },
  "security": {
    "auth_enabled": false,
    "username": "admin",
    "password": "changeme",
    "allowed_hosts": ["127.0.0.1", "localhost", "192.168.*", "10.*"]
  }
}
```

### Configuration Options

#### Assistant Status
- `name`: Your assistant's name (e.g., "Sak", "Alexa", "Google")
- `status_indicator`: Show/hide the status badge
- `awake_message`: Template for awake status (`{name}` is replaced)
- `sleeping_message`: Template for sleeping status

#### Metrics
- `enabled`: List of metrics to display
  - `cpu`: CPU usage and frequency
  - `memory`: RAM usage
  - `temperature`: CPU temperature
  - `uptime`: System uptime
  - `disk`: Disk usage
  - `network`: Network I/O statistics
- `update_interval`: Seconds between updates (default: 2)
- `temperature_unit`: `celsius` or `fahrenheit`

#### Security
- `auth_enabled`: Enable HTTP Basic Authentication
- `username` / `password`: Credentials for basic auth
- `allowed_hosts`: IP patterns allowed to access the dashboard
  - Supports wildcards like `192.168.*` for entire subnets

## Running as a Service

Create a systemd service for auto-start:

```bash
sudo nano /etc/systemd/system/pi-dashboard.service
```

Add the following:

```ini
[Unit]
Description=OpenClaw Pi Dashboard
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/OpenClaw-Pi-Dashboard
Environment=PATH=/home/pi/OpenClaw-Pi-Dashboard/venv/bin
ExecStart=/home/pi/OpenClaw-Pi-Dashboard/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pi-dashboard
sudo systemctl start pi-dashboard
```

## Security Considerations

- **No shell execution**: The dashboard never executes shell commands from web requests
- **Read-only**: All stats are gathered via safe system APIs (psutil, /sys filesystem)
- **Host filtering**: Restrict access to LAN IPs by default
- **Optional authentication**: Enable basic auth for additional protection
- **No external dependencies**: All data is gathered locally

## API Endpoints

- `GET /` - Main dashboard page
- `GET /api/stats` - Current system stats (JSON)
- `GET /api/config` - Safe configuration (JSON, no passwords)
- `GET /stream` - Server-Sent Events for real-time updates
- `GET /health` - Health check endpoint

## Development

### Running Tests

```bash
pip install -e ".[dev]"
pytest
```

### Code Formatting

```bash
black app.py
```

## Troubleshooting

### Temperature not showing
Ensure your user has access to thermal zones:
```bash
sudo usermod -aG video $USER  # For some Pi models
```

Or check permissions:
```bash
cat /sys/class/thermal/thermal_zone0/temp
```

### Permission denied errors
Make sure the user running the dashboard can read:
- `/sys/class/thermal/thermal_zone0/temp`
- `/proc/*` (psutil requirement)

### Port already in use
Change the port in `config.json` or kill the existing process:
```bash
sudo lsof -ti:5000 | xargs kill -9
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit using conventional commits (`feat:`, `fix:`, `docs:`, etc.)
4. Push to the branch
5. Open a Pull Request

---

Built with ❤️ for the OpenClaw community
