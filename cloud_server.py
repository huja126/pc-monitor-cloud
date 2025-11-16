"""
PC Monitor Multi-User Cloud Server - Debug Version
Fixes password verification issue
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
app.secret_key = secrets.token_hex(32)  # Secure session key
CORS(app)

# Configuration - Use current directory for cloud deployment
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
        result = password_hash == stored_password_hash
        print(f"Password verification result: {result}")
        print(f"Expected hash: {password_hash}")
        print(f"Stored hash: {stored_password_hash}")
        return result
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
        print(f"Database connection opened: {DB_PATH}")
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        raise

# Database initialization with multi-user support
def init_db():
    """Initialize database with multi-user support"""
    print("Starting database initialization...")
    conn = sqlite3.connect(DB_PATH)
    print("Database connection established")
    c = conn.cursor()
    
    # Users table for authentication
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1
    )''')
    
    # User sessions table
    c.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_token TEXT UNIQUE,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # PCs table with user association
    c.execute('''CREATE TABLE IF NOT EXISTS pcs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        pc_id TEXT UNIQUE,
        pc_name TEXT NOT NULL,
        platform TEXT,
        last_seen TIMESTAMP,
        last_online TIMESTAMP,
        status TEXT DEFAULT 'offline',
        continuous_online_minutes REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Status history table with user association
    c.execute('''CREATE TABLE IF NOT EXISTS status_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        pc_id TEXT,
        status TEXT,
        uptime_seconds REAL,
        cpu_percent REAL,
        memory_percent REAL,
        disk_percent REAL,
        running_apps TEXT,
        system_info TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (pc_id) REFERENCES pcs (pc_id)
    )''')
    
    # Scheduled alerts table with user association
    c.execute('''CREATE TABLE IF NOT EXISTS scheduled_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        pc_id TEXT,
        alert_name TEXT NOT NULL,
        check_time TEXT NOT NULL,
        day_of_week TEXT DEFAULT 'daily',
        alert_type TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        notification_type TEXT DEFAULT 'browser',
        notification_config TEXT,
        last_checked DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (pc_id) REFERENCES pcs (pc_id)
    )''')
    
    # Alert history table with user association
    c.execute('''CREATE TABLE IF NOT EXISTS alert_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        alert_id INTEGER,
        pc_id TEXT,
        message TEXT,
        notification_sent INTEGER DEFAULT 0,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Settings table for notification configurations
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        key TEXT NOT NULL,
        value TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()

def create_default_admin():
    """Create default admin user if none exists"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users')
        count = c.fetchone()[0]
        print(f"Current user count: {count}")
        
        if count == 0:
            # Create default admin user with proper password
            password_hash = hash_password('admin123')
            print(f"Created password hash: {password_hash}")
            c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                      ('admin', 'admin@example.com', password_hash))
            conn.commit()
            print("✓ Created default admin user: admin / admin123")
        else:
            print(f"Admin user already exists (count: {count})")
        conn.close()
    except Exception as e:
        print(f"Error creating admin user: {e}")

# Initialize database on startup
try:
    print("Starting application initialization...")
    init_db()
    create_default_admin()
    print("Database initialization complete!")
except Exception as e:
    print(f"Database initialization failed: {e}")
    print("Application will continue but login may not work!")

print("\n" + "="*60)
print("PC Monitor Multi-User Server Starting")
print("="*60)
print(f"Database initialized: {DB_PATH}")
print(f"Default Login: admin / admin123")
print(f"Max Users: 5")
print("="*60 + "\n")

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
    """User login API with debug"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        print(f"Login attempt - Username: {username}, Password length: {len(password) if password else 0}")
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id, password_hash FROM users WHERE username = ? AND is_active = 1', (username,))
        user = c.fetchone()
        conn.close()
        
        print(f"User query result: {user}")
        
        if user:
            user_id, stored_hash = user
            print(f"Found user: ID={user_id}, Hash={stored_hash[:20]}...")
            if verify_password(password, stored_hash):
                print("✓ Password verification successful")
                session['user_id'] = user_id
                session['username'] = username
                return jsonify({'success': True, 'message': 'Login successful'})
            else:
                print("✗ Password verification failed")
        else:
            print("✗ User not found")
            
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
    """Get PCs for current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM pcs WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
    pcs = []
    for row in c.fetchall():
        pcs.append({
            'id': row[2],  # pc_id
            'name': row[3],  # pc_name
            'platform': row[4],  # platform
            'last_seen': row[5],  # last_seen
            'status': row[7],  # status
            'continuous_online_minutes': row[8]  # continuous_online_minutes
        })
    conn.close()
    
    return jsonify({'pcs': pcs})

@app.route('/api/pc/register', methods=['POST'])
def api_register_pc():
    """Register a new PC"""
    data = request.get_json()
    pc_id = data.get('pc_id')
    pc_name = data.get('pc_name')
    platform = data.get('platform')
    
    if not pc_id or not pc_name:
        return jsonify({'error': 'PC ID and name required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Insert or update PC
    c.execute('''INSERT OR REPLACE INTO pcs 
                 (user_id, pc_id, pc_name, platform, last_seen, status) 
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (1, pc_id, pc_name, platform, datetime.now(), 'online'))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'PC registered successfully'})

@app.route('/api/pc/update', methods=['POST'])
def api_update_pc():
    """Update PC status"""
    data = request.get_json()
    pc_id = data.get('pc_id')
    
    if not pc_id:
        return jsonify({'error': 'PC ID required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Update PC status
    c.execute('''UPDATE pcs 
                 SET last_seen = ?, status = ?, continuous_online_minutes = ? 
                 WHERE pc_id = ?''',
              (datetime.now(), 'online', data.get('continuous_online_minutes', 0), pc_id))
    
    # Store status history
    running_apps = json.dumps(data.get('running_apps', []))
    c.execute('''INSERT INTO status_history 
                 (user_id, pc_id, status, uptime_seconds, cpu_percent, memory_percent, 
                  disk_percent, running_apps, system_info) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (1, pc_id, 'online',
               data.get('uptime_seconds'),
               data.get('cpu', {}).get('percent'),
               data.get('memory', {}).get('percent'),
               data.get('disk', {}).get('percent'),
               running_apps,
               json.dumps(data)))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/alerts')
def api_get_alerts():
    """Get alerts for current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM scheduled_alerts WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
    alerts = []
    for row in c.fetchall():
        alerts.append({
            'id': row[0],
            'pc_id': row[2],
            'alert_name': row[3],
            'check_time': row[4],
            'day_of_week': row[5],
            'alert_type': row[6],
            'enabled': row[7],
            'notification_type': row[8]
        })
    conn.close()
    
    return jsonify({'alerts': alerts})

@app.route('/api/alert_history')
def api_get_alert_history():
    """Get alert history for current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM alert_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50', (session['user_id'],))
    history = []
    for row in c.fetchall():
        history.append({
            'id': row[0],
            'alert_id': row[2],
            'pc_id': row[3],
            'message': row[4],
            'timestamp': row[6]
        })
    conn.close()
    
    return jsonify({'history': history})

# Flask development server (for local testing)
if __name__ == '__main__':
    print(f"\nServer URL: http://localhost:5000")
    print(f"Default Login: admin / admin123")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False, threaded=True)
