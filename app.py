"""
OpenClaw Pi Dashboard - Main Application
A secure, real-time Raspberry Pi monitoring dashboard
"""

import os
import json
import time
import logging
import subprocess
import shutil
import pwd
import fnmatch
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

# Configuration
CONFIG_PATH = os.environ.get('DASHBOARD_CONFIG', 'config.json')

DEFAULT_CONFIG = {
    "assistant": {
        "name": "Sak",
        "status_indicator": True,
        "awake_message": "{name} is Awake",
        "sleeping_message": "{name} is Sleeping"
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
        "allowed_hosts": ["127.0.0.1", "localhost", "192.168.*", "10.*"]
    },
    "gateway": {
        "service_name": "openclaw-gateway",
        "shell_user": None,  # None = auto-detect from current user
        "restart_timeout": 30
    },
    "server": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": False
    }
}


def load_config():
    """Load configuration from file merged with defaults."""
    config = DEFAULT_CONFIG.copy()
    
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                user_config = json.load(f)
            
            # Deep merge
            for key, value in user_config.items():
                if isinstance(value, dict) and key in config:
                    config[key].update(value)
                else:
                    config[key] = value
            
            logger.info(f"Loaded configuration from {CONFIG_PATH}")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading config: {e}. Using defaults.")
    
    return config


config = load_config()


# Auth helpers
def get_gateway_user():
    """Get the user for running gateway commands."""
    return config['gateway'].get('shell_user') or pwd.getpwuid(os.getuid()).pw_name


def get_gateway_env():
    """Get environment dict for gateway commands."""
    user = get_gateway_user()
    uid = pwd.getpwnam(user).pw_uid
    env = os.environ.copy()
    env['XDG_RUNTIME_DIR'] = f"/run/user/{uid}"
    env['DBUS_SESSION_BUS_ADDRESS'] = f"unix:path=/run/user/{uid}/bus"
    return env


def check_auth(username, password, admin_only=False):
    """Verify credentials against config."""
    if not config['security']['auth_enabled'] and not admin_only:
        return True
    
    return (username == config['security']['username'] and 
            password == config['security']['password'])


def authenticate():
    """Send 401 response."""
    return Response('Authentication required', 401, 
                   {'WWW-Authenticate': 'Basic realm="Pi Dashboard"'})


def requires_auth(admin=False):
    """Decorator factory for authentication."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not config['security']['auth_enabled'] and not admin:
                return f(*args, **kwargs)
            
            auth = request.authorization
            if not auth or not check_auth(auth.username, auth.password, admin_only=admin):
                return authenticate()
            return f(*args, **kwargs)
        return wrapped
    return decorator


def is_allowed_host():
    """Check if request is from an allowed host."""
    remote_addr = request.remote_addr or '127.0.0.1'
    return any(fnmatch.fnmatch(remote_addr, pattern) 
               for pattern in config['security']['allowed_hosts'])


# System stats helpers
def get_temperature():
    """Get CPU temperature from /sys filesystem."""
    temp_paths = [
        '/sys/class/thermal/thermal_zone0/temp',
        '/sys/class/hwmon/hwmon0/temp1_input',
    ]
    
    for path in temp_paths:
        try:
            with open(path, 'r') as f:
                temp_c = int(f.read().strip()) / 1000.0
                if config['metrics']['temperature_unit'] == 'fahrenheit':
                    return round((temp_c * 9/5) + 32, 1)
                return round(temp_c, 1)
        except (IOError, ValueError):
            continue
    
    return None


def get_system_stats():
    """Gather system statistics."""
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
            stats['temperature'] = {'value': temp, 'unit': config['metrics']['temperature_unit']}
    
    if 'uptime' in enabled:
        boot_time = psutil.boot_time()
        stats['uptime'] = {
            'seconds': int(time.time() - boot_time),
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
        net = psutil.net_io_counters()
        stats['network'] = {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
            'packets_sent': net.packets_sent,
            'packets_recv': net.packets_recv
        }
    
    if config['assistant']['status_indicator']:
        name = config['assistant']['name']
        stats['assistant'] = {
            'name': name,
            'awake': True,
            'message': config['assistant']['awake_message'].format(name=name)
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
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    
    parts = []
    if days: parts.append(f"{int(days)}d")
    if hours: parts.append(f"{int(hours)}h")
    if minutes: parts.append(f"{int(minutes)}m")
    if seconds or not parts: parts.append(f"{int(seconds)}s")
    
    return " ".join(parts)


# Routes
@app.before_request
def check_host():
    """Verify request comes from allowed host."""
    if not is_allowed_host():
        logger.warning(f"Blocked request from {request.remote_addr}")
        return Response('Forbidden', 403)


@app.route('/')
def index():
    """Render main dashboard page."""
    is_admin = check_auth(
        request.authorization.username if request.authorization else '',
        request.authorization.password if request.authorization else '',
        admin_only=True
    ) if config['security']['auth_enabled'] else False
    
    return render_template('index.html', config=config, is_admin=is_admin)


@app.route('/api/stats')
def api_stats():
    """Get current system stats as JSON."""
    return jsonify(get_system_stats())


@app.route('/api/config')
@requires_auth()
def api_config():
    """Get safe configuration (no passwords)."""
    return jsonify({
        'assistant': config['assistant'],
        'branding': config['branding'],
        'metrics': config['metrics']
    })


@app.route('/stream')
def stream():
    """Server-Sent Events endpoint for real-time updates."""
    interval = config['metrics']['update_interval']
    
    def event_stream():
        while True:
            try:
                yield f"data: {json.dumps(get_system_stats())}\n\n"
            except Exception as e:
                logger.error(f"SSE error: {e}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            time.sleep(interval)
    
    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})


@app.route('/api/restart-gateway', methods=['POST'])
@requires_auth(admin=True)
def restart_gateway():
    """Restart the OpenClaw gateway."""
    try:
        user = get_gateway_user()
        service = config['gateway']['service_name']
        env = get_gateway_env()
        
        # Pass DBUS_SESSION_BUS_ADDRESS as part of command since sudo sanitizes env
        result = subprocess.run(
            ['/usr/bin/sudo', '-u', user, 
             f'DBUS_SESSION_BUS_ADDRESS={env["DBUS_SESSION_BUS_ADDRESS"]}',
             '/usr/bin/systemctl', '--user', 'restart', service],
            capture_output=True,
            text=True,
            timeout=config['gateway']['restart_timeout']
        )
        
        if result.returncode == 0:
            logger.info(f"Gateway {service} restart initiated by admin")
            return jsonify({'success': True, 'message': f'{service} restart initiated'})
        
        logger.error(f"Gateway restart failed: {result.stderr}")
        return jsonify({'success': False, 'error': result.stderr}), 500
        
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Restart timed out'}), 500
    except Exception as e:
        logger.error(f"Error restarting gateway: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/gateway-status', methods=['GET'])
def gateway_status():
    """Get OpenClaw gateway status."""
    try:
        service = config['gateway']['service_name']
        env = get_gateway_env()
        systemctl = shutil.which('systemctl') or '/usr/bin/systemctl'
        
        result = subprocess.run(
            [systemctl, '--user', 'is-active', f'{service}.service'],
            capture_output=True,
            text=True,
            timeout=5,
            env=env
        )
        is_active = result.returncode == 0
        
        uptime_info = None
        if is_active:
            uptime_result = subprocess.run(
                [systemctl, '--user', 'show', f'{service}.service', '--property=ActiveEnterTimestamp'],
                capture_output=True,
                text=True,
                timeout=5,
                env=env
            )
            if uptime_result.returncode == 0:
                uptime_info = uptime_result.stdout.strip()
        
        return jsonify({
            'active': is_active,
            'status': 'active' if is_active else 'inactive',
            'uptime_info': uptime_info
        })
        
    except Exception as e:
        logger.error(f"Error checking gateway status: {e}")
        return jsonify({'active': False, 'status': 'unknown', 'error': str(e)}), 500


if __name__ == '__main__':
    server = config['server']
    logger.info(f"Starting Pi Dashboard on {server['host']}:{server['port']}")
    app.run(
        host=server['host'],
        port=server['port'],
        debug=server['debug'],
        threaded=True
    )
