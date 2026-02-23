"""
OpenClaw Pi Dashboard - Main Application
A secure, real-time Raspberry Pi monitoring dashboard
"""

import os
import json
import time
import logging
from datetime import datetime
from functools import wraps

import psutil
from flask import Flask, render_template, jsonify, Response, request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Load configuration
CONFIG_PATH = os.environ.get('DASHBOARD_CONFIG', 'config.json')

DEFAULT_CONFIG = {
    "assistant": {
        "name": "Sak",
        "status_indicator": True,
        "awake_message": "{name} is Awake",
        "sleeping_message": "{name} is Sleeping",
        "show_status_badge": True
    },
    "branding": {
        "title": "OpenClaw Pi Dashboard",
        "favicon": "/static/favicon.ico",
        "theme_color": "#3b82f6"
    },
    "metrics": {
        "enabled": ["cpu", "memory", "temperature", "uptime", "disk", "network"],
        "update_interval": 2,
        "temperature_unit": "celsius"
    },
    "security": {
        "auth_enabled": False,
        "username": "admin",
        "password": "changeme",
        "allowed_hosts": ["127.0.0.1", "localhost", "192.168.*", "10.*"],
        "rate_limit": 100
    },
    "server": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": False
    }
}


def load_config():
    """Load configuration from file or use defaults."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                user_config = json.load(f)
                # Merge with defaults
                config = DEFAULT_CONFIG.copy()
                for key, value in user_config.items():
                    if isinstance(value, dict) and key in config:
                        config[key].update(value)
                    else:
                        config[key] = value
                logger.info(f"Loaded configuration from {CONFIG_PATH}")
                return config
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading config: {e}. Using defaults.")
            return DEFAULT_CONFIG
    return DEFAULT_CONFIG


# Global config
config = load_config()


def check_auth(username, password):
    """Verify credentials against config."""
    if not config['security']['auth_enabled']:
        return True
    return (username == config['security']['username'] and 
            password == config['security']['password'])


def authenticate():
    """Send 401 response with WWW-Authenticate header."""
    return Response(
        'Authentication required',
        401,
        {'WWW-Authenticate': 'Basic realm="Pi Dashboard"'}
    )


def requires_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not config['security']['auth_enabled']:
            return f(*args, **kwargs)
        
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def is_allowed_host():
    """Check if request is from an allowed host."""
    remote_addr = request.remote_addr or '127.0.0.1'
    allowed_hosts = config['security']['allowed_hosts']
    
    for pattern in allowed_hosts:
        if pattern.endswith('*'):
            if remote_addr.startswith(pattern[:-1]):
                return True
        elif remote_addr == pattern:
            return True
    return False


def get_temperature():
    """Get CPU temperature safely from /sys filesystem."""
    try:
        # Try Raspberry Pi temperature sensor
        temp_paths = [
            '/sys/class/thermal/thermal_zone0/temp',
            '/sys/class/hwmon/hwmon0/temp1_input',
        ]
        
        for path in temp_paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    temp_raw = f.read().strip()
                    # Convert millidegrees to degrees
                    temp_c = int(temp_raw) / 1000.0
                    if config['metrics']['temperature_unit'] == 'fahrenheit':
                        return round((temp_c * 9/5) + 32, 1)
                    return round(temp_c, 1)
        
        return None
    except Exception as e:
        logger.warning(f"Could not read temperature: {e}")
        return None


def get_system_stats():
    """Gather system statistics safely."""
    stats = {}
    enabled = config['metrics']['enabled']
    
    if 'cpu' in enabled:
        stats['cpu'] = {
            'percent': psutil.cpu_percent(interval=0.1),
            'count': psutil.cpu_count(),
            'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
        }
    
    if 'memory' in enabled:
        mem = psutil.virtual_memory()
        stats['memory'] = {
            'total': mem.total,
            'available': mem.available,
            'percent': mem.percent,
            'used': mem.used,
            'free': mem.free
        }
    
    if 'temperature' in enabled:
        temp = get_temperature()
        if temp is not None:
            stats['temperature'] = {
                'value': temp,
                'unit': config['metrics']['temperature_unit']
            }
    
    if 'uptime' in enabled:
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        stats['uptime'] = {
            'seconds': int(uptime_seconds),
            'boot_time': datetime.fromtimestamp(boot_time).isoformat()
        }
    
    if 'disk' in enabled:
        disk = psutil.disk_usage('/')
        stats['disk'] = {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent
        }
    
    if 'network' in enabled:
        net_io = psutil.net_io_counters()
        stats['network'] = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
    
    # Assistant status
    if config['assistant']['status_indicator']:
        stats['assistant'] = {
            'name': config['assistant']['name'],
            'awake': True,  # Dashboard is running, so assistant is awake
            'message': config['assistant']['awake_message'].format(
                name=config['assistant']['name']
            )
        }
    
    stats['timestamp'] = datetime.now().isoformat()
    return stats


def format_bytes(bytes_val):
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


def format_duration(seconds):
    """Format seconds to human readable duration."""
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{int(days)}d")
    if hours > 0:
        parts.append(f"{int(hours)}h")
    if minutes > 0:
        parts.append(f"{int(minutes)}m")
    if seconds > 0 or not parts:
        parts.append(f"{int(seconds)}s")
    
    return " ".join(parts)


@app.before_request
def check_host():
    """Verify request comes from allowed host."""
    if not is_allowed_host():
        logger.warning(f"Blocked request from {request.remote_addr}")
        return Response('Forbidden', 403)


@app.route('/')
@requires_auth
def index():
    """Render main dashboard page."""
    return render_template('index.html', config=config)


@app.route('/api/stats')
@requires_auth
def api_stats():
    """Get current system stats as JSON."""
    return jsonify(get_system_stats())


@app.route('/api/config')
@requires_auth
def api_config():
    """Get safe configuration (no passwords)."""
    safe_config = {
        'assistant': config['assistant'],
        'branding': config['branding'],
        'metrics': config['metrics']
    }
    return jsonify(safe_config)


@app.route('/stream')
@requires_auth
def stream():
    """Server-Sent Events endpoint for real-time updates."""
    def event_stream():
        interval = config['metrics']['update_interval']
        while True:
            try:
                stats = get_system_stats()
                yield f"data: {json.dumps(stats)}\n\n"
                time.sleep(interval)
            except Exception as e:
                logger.error(f"SSE error: {e}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(interval)
    
    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})


if __name__ == '__main__':
    server_config = config['server']
    logger.info(f"Starting Pi Dashboard on {server_config['host']}:{server_config['port']}")
    app.run(
        host=server_config['host'],
        port=server_config['port'],
        debug=server_config['debug'],
        threaded=True
    )
