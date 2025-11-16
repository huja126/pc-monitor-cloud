"""
PC Monitor Multi-User Cloud Server - FIXED DATA HANDLING
Properly stores and returns PC data for dashboard
"""

from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for, flash
from flask_cors import CORS
import sqlite3
import json
from datetime import datetime, timedelta
import threading
import time
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import hashlib
import secrets
import re

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(32)
CORS(app)

# Configuration
DB_PATH = os.path.join(os.getcwd(), 'pc_monitor.db')
CHECK_INTERVAL = 30
browser_alerts = []

print(f"Database path: {DB_PATH}")
print(f"Current working directory: {os.getcwd()}")

# User authentication helpers
def hash_password(password):
    """Hash password using PBKDF2 with salt"""
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    return f"{salt}${password_hash}"

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    try:
        salt, stored_password_hash = stored_hash.split('$')
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
        return password_hash == stored_password_hash
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

def get_current_user():
    """Get current logged-in user from session"""
    return session.get('user_id')

# Database connection helper
def get_db():
    """Get database connection"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        raise

# Database initialization
def init_db():
    """Initialize database with proper tables"""
    print("Starting database initialization...")
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1
    )''')
    
    # PCs table - SIMPLIFIED for testing
    c.execute('''CREATE TABLE IF NOT EXISTS pcs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pc_id TEXT UNIQUE NOT NULL,
        pc_name TEXT NOT NULL,
        platform TEXT,
        last_seen TIMESTAMP,
        status TEXT DEFAULT 'offline',
        continuous_online_minutes REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Status history table
    c.execute('''CREATE TABLE IF NOT EXISTS status_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pc_id TEXT,
        status TEXT,
        uptime_seconds REAL,
        cpu_percent REAL,
        memory_percent REAL,
        disk_percent REAL,
        running_apps TEXT,
        processes TEXT,
        system_info TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (pc_id) REFERENCES pcs (pc_id)
    )''')
    
    conn.commit()
    conn.close()
    print("Database initialization complete!")

def create_default_admin():
    """Create default admin user if none exists"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users')
        count = c.fetchone()[0]
        
        if count == 0:
            password_hash = hash_password('admin123')
            c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                      ('admin', 'admin@example.com', password_hash))
            conn.commit()
            print("✓ Created default admin user: admin / admin123")
        conn.close()
    except Exception as e:
        print(f"Error creating admin user: {e}")

# Initialize database on startup
try:
    init_db()
    create_default_admin()
    print("Database initialization complete!")
except Exception as e:
    print(f"Database initialization failed: {e}")

print("\n" + "="*60)
print("PC Monitor Server - FIXED DATA HANDLING")
print("="*60)

# API Routes

@app.route('/')
def index():
    """Main dashboard"""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('index.html')

@app.route('/login')
def login_page():
    """Login page"""
    if 'user_id' in session:
        return redirect('/')
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    """User login API"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        print(f"Login attempt: {username}")
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id, password_hash FROM users WHERE username = ? AND is_active = 1', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and verify_password(password, user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = username
            return jsonify({'success': True, 'message': 'Login successful'})
            
        return jsonify({'error': 'Invalid username or password'}), 401
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """User logout API"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/user')
def get_current_user_info():
    """Get current user info"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    return jsonify({
        'user_id': session['user_id'],
        'username': session.get('username', 'Unknown')
    })

@app.route('/api/pcs')
def api_get_pcs():
    """Get PCs for dashboard - FIXED VERSION"""
    print("📱 Dashboard requesting PCs data...")
    
    conn = get_db()
    c = conn.cursor()
    
    # Get all PCs (no user filtering for now)
    c.execute('''
        SELECT p.*, 
               sh.cpu_percent, sh.memory_percent, sh.disk_percent,
               sh.uptime_seconds, sh.running_apps, sh.processes, sh.system_info
        FROM pcs p
        LEFT JOIN status_history sh ON p.pc_id = sh.pc_id 
        AND sh.timestamp = (SELECT MAX(timestamp) FROM status_history WHERE pc_id = p.pc_id)
        ORDER BY p.last_seen DESC
    ''')
    
    pcs = []
    for row in c.fetchall():
        print(f"📊 Processing PC: {row['pc_name']}, Status: {row['status']}")
        
        # Parse running apps
        running_apps = []
        if row['running_apps']:
            try:
                running_apps = json.loads(row['running_apps'])
            except:
                running_apps = []
        
        # Parse processes
        processes = []
        if row['processes']:
            try:
                processes = json.loads(row['processes'])
            except:
                processes = []
        
        # Parse system info
        system_info = {}
        if row['system_info']:
            try:
                system_info = json.loads(row['system_info'])
            except:
                system_info = {}
        
        # Build PC data in EXACT format dashboard expects
        pc_data = {
            'pc_id': row['pc_id'],
            'pc_name': row['pc_name'],
            'platform': row['platform'],
            'last_seen': row['last_seen'],
            'status': row['status'],
            'continuous_online_minutes': row['continuous_online_minutes'],
            'latest_info': {
                'cpu': {
                    'percent': row['cpu_percent'] or 0,
                    'count': system_info.get('cpu', {}).get('count', 0) if system_info else 0
                },
                'memory': {
                    'percent': row['memory_percent'] or 0,
                    'total_gb': system_info.get('memory', {}).get('total_gb', 0) if system_info else 0
                },
                'disk': {
                    'percent': row['disk_percent'] or 0,
                    'total_gb': system_info.get('disk', {}).get('total_gb', 0) if system_info else 0
                },
                'uptime_seconds': row['uptime_seconds'] or 0,
                'system': system_info.get('system', {}),
                'running_apps': running_apps,
                'processes': processes
            }
        }
        
        pcs.append(pc_data)
        print(f"✅ Prepared PC data: {pc_data['pc_name']} - CPU: {pc_data['latest_info']['cpu']['percent']}%")
    
    conn.close()
    
    print(f"📤 Sending {len(pcs)} PCs to dashboard")
    return jsonify(pcs)  # Return direct array as dashboard expects

@app.route('/api/pc/register', methods=['POST'])
def api_register_pc():
    """Register a new PC - FIXED VERSION"""
    data = request.get_json()
    pc_id = data.get('pc_id')
    pc_name = data.get('pc_name')
    platform = data.get('platform')
    
    print(f"🖥️ Registering PC: {pc_name} (ID: {pc_id})")
    
    if not pc_id or not pc_name:
        return jsonify({'error': 'PC ID and name required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Insert or update PC
        c.execute('''INSERT OR REPLACE INTO pcs 
                     (pc_id, pc_name, platform, last_seen, status) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (pc_id, pc_name, platform, datetime.now(), 'online'))
        
        conn.commit()
        print(f"✅ PC registered: {pc_name}")
        conn.close()
        return jsonify({'success': True, 'message': 'PC registered successfully'})
        
    except Exception as e:
        print(f"❌ PC registration error: {e}")
        conn.close()
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/pc/update', methods=['POST'])
def api_update_pc():
    """Update PC status - FIXED VERSION"""
    data = request.get_json()
    pc_id = data.get('pc_id')
    
    print(f"📊 Updating PC status: {pc_id}")
    
    if not pc_id:
        return jsonify({'error': 'PC ID required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Update PC status and last seen
        c.execute('''UPDATE pcs 
                     SET last_seen = ?, status = 'online', continuous_online_minutes = ?
                     WHERE pc_id = ?''',
                  (datetime.now(), data.get('continuous_online_minutes', 0), pc_id))
        
        # Store status history with ALL data
        running_apps = json.dumps(data.get('running_apps', []))
        processes = json.dumps(data.get('processes', []))
        system_info = data.get('system_info', '{}')
        
        c.execute('''INSERT INTO status_history 
                     (pc_id, status, uptime_seconds, cpu_percent, memory_percent, 
                      disk_percent, running_apps, processes, system_info) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (pc_id, 'online',
                   data.get('uptime_seconds', 0),
                   data.get('cpu', {}).get('percent', 0),
                   data.get('memory', {}).get('percent', 0),
                   data.get('disk', {}).get('percent', 0),
                   running_apps,
                   processes,
                   system_info))
        
        conn.commit()
        print(f"✅ PC updated: {pc_id} - "
              f"CPU: {data.get('cpu', {}).get('percent', 0)}%, "
              f"Memory: {data.get('memory', {}).get('percent', 0)}%")
        conn.close()
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"❌ PC update error: {e}")
        conn.close()
        return jsonify({'error': 'Update failed'}), 500

# Simple endpoints for dashboard compatibility
@app.route('/api/alerts')
def api_get_alerts():
    """Get alerts - placeholder"""
    return jsonify([])

@app.route('/api/alert_history')
def api_get_alert_history():
    """Get alert history - placeholder"""
    return jsonify([])

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """Settings endpoint - placeholder"""
    if request.method == 'GET':
        return jsonify({})
    else:
        return jsonify({'success': True})

@app.route('/api/scheduled-alerts')
def api_scheduled_alerts():
    """Scheduled alerts - placeholder"""
    return jsonify([])

if __name__ == '__main__':
    print(f"\n🚀 Server starting: http://localhost:5000")
    print("Default Login: admin / admin123")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True, threaded=True)
