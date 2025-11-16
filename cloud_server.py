"""
PC Monitor Cloud Server - FIXED TELEGRAM INTEGRATION
With detailed debugging and setup guide
"""

from flask import Flask, request, jsonify, render_template, session, redirect
from flask_cors import CORS
import sqlite3
import json
from datetime import datetime, timedelta
import threading
import time
import os
import hashlib
import secrets
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(32)
CORS(app)

# Configuration
DB_PATH = os.path.join(os.getcwd(), 'pc_monitor.db')
HEARTBEAT_TIMEOUT = 120  # 2 minutes

print(f"Database path: {DB_PATH}")

# User authentication helpers
def hash_password(password):
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    return f"{salt}${password_hash}"

def verify_password(password, stored_hash):
    try:
        salt, stored_password_hash = stored_hash.split('$')
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
        return password_hash == stored_password_hash
    except:
        return False

def get_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        raise

# Database initialization
def init_db():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1
    )''')
    
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
    
    c.execute('''CREATE TABLE IF NOT EXISTS scheduled_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        pc_id TEXT,
        pc_name TEXT,
        alert_name TEXT NOT NULL,
        check_time TEXT NOT NULL,
        day_of_week TEXT DEFAULT 'daily',
        alert_type TEXT NOT NULL,
        condition_value INTEGER,
        enabled INTEGER DEFAULT 1,
        notification_type TEXT DEFAULT 'browser',
        notification_config TEXT,
        last_triggered TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS alert_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        alert_id INTEGER,
        pc_id TEXT,
        pc_name TEXT,
        alert_name TEXT,
        message TEXT NOT NULL,
        alert_type TEXT,
        notification_sent INTEGER DEFAULT 0,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (alert_id) REFERENCES scheduled_alerts (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        key TEXT NOT NULL,
        value TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()
    print("Database initialization complete!")

def create_default_admin():
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

# IMPROVED TELEGRAM FUNCTIONS WITH DEBUGGING
def get_telegram_bot_info(bot_token):
    """Get bot information to verify token"""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/getMe"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('ok'):
                bot_info = data['result']
                print(f"✅ Bot verified: @{bot_info['username']} ({bot_info['first_name']})")
                return True
            else:
                print(f"❌ Bot token invalid: {data.get('description')}")
                return False
        else:
            print(f"❌ Telegram API error: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error verifying bot token: {e}")
        return False

def get_telegram_updates(bot_token):
    """Get recent updates to find chat ID"""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('ok') and data['result']:
                print("📱 Recent Telegram updates found:")
                for update in data['result']:
                    if 'message' in update:
                        chat = update['message']['chat']
                        print(f"   💬 Chat ID: {chat['id']} - {chat.get('first_name', 'Unknown')} (@{chat.get('username', 'No username')})")
                return True
            else:
                print("ℹ️ No recent messages found. Send a message to your bot first.")
                return False
        else:
            print(f"❌ Error getting updates: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error getting Telegram updates: {e}")
        return False

def send_telegram_alert(user_id, chat_id, message):
    """Send Telegram alert via bot - WITH COMPLETE DEBUGGING"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Get Telegram bot token from database
        c.execute('SELECT value FROM settings WHERE user_id = ? AND key = ?', 
                 (user_id, 'telegram_token'))
        token_result = c.fetchone()
        conn.close()
        
        if not token_result or not token_result['value']:
            print("❌ Telegram bot token not configured in database")
            return False
            
        bot_token = token_result['value'].strip()
        
        if not bot_token:
            print("❌ Telegram bot token is empty")
            return False
            
        if not chat_id:
            print("❌ Chat ID is required")
            return False
        
        # Verify bot token first
        print(f"🔍 Verifying bot token: {bot_token[:10]}...")
        if not get_telegram_bot_info(bot_token):
            print("❌ Bot token verification failed")
            return False
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        # Format message with emojis and formatting
        formatted_message = f"🚨 *PC Monitor Alert* 🚨\n\n{message}\n\n_Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        payload = {
            'chat_id': chat_id,
            'text': formatted_message,
            'parse_mode': 'Markdown'
        }
        
        print(f"📤 Sending Telegram message to chat {chat_id}...")
        response = requests.post(url, json=payload, timeout=10)
        
        print(f"📡 Telegram API response: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print(f"✅ Telegram message sent successfully to {chat_id}")
                return True
            else:
                print(f"❌ Telegram API error: {result.get('description')}")
                return False
        else:
            print(f"❌ Telegram HTTP error: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("❌ Telegram request timeout")
        return False
    except requests.exceptions.ConnectionError:
        print("❌ Telegram connection error - check internet connection")
        return False
    except Exception as e:
        print(f"❌ Telegram error: {str(e)}")
        return False

def send_email_alert(user_id, recipient_email, subject, message):
    """Send email alert using SMTP configuration"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Get email settings from database
        c.execute('''SELECT key, value FROM settings 
                     WHERE user_id = ? AND key IN ('email_smtp', 'email_port', 'email_sender', 'email_password')''', 
                  (user_id,))
        settings = {row['key']: row['value'] for row in c.fetchall()}
        conn.close()
        
        # Check if all required settings are present
        required_settings = ['email_smtp', 'email_port', 'email_sender', 'email_password']
        missing_settings = [s for s in required_settings if not settings.get(s)]
        
        if missing_settings:
            print(f"❌ Email not configured. Missing: {missing_settings}")
            return False
        
        smtp_server = settings['email_smtp']
        port = int(settings['email_port'])
        sender_email = settings['email_sender']
        password = settings['email_password']
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        
        # Create HTML email body
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background: #f6f9fc; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h1 style="color: #667eea; margin: 0;">🖥️ PC Monitor Alert</h1>
                        <p style="color: #666; margin: 10px 0 0 0;">Automated System Notification</p>
                    </div>
                    
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h2 style="color: #333; margin: 0 0 10px 0;">{subject}</h2>
                        <p style="color: #666; margin: 0; line-height: 1.6;">{message}</p>
                    </div>
                    
                    <div style="border-top: 2px solid #e0e0e0; padding-top: 20px; text-align: center;">
                        <p style="color: #999; font-size: 12px; margin: 0;">
                            This is an automated alert from your PC Monitor system.<br>
                            Sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        </p>
                    </div>
                </div>
            </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        # Send email
        print(f"📧 Attempting to send email via {smtp_server}:{port}...")
        server = smtplib.SMTP(smtp_server, port)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Email sent successfully to {recipient_email}")
        return True
        
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False

def send_alert_notification(user_id, alert_data, message):
    """Send notification based on alert configuration"""
    notification_type = alert_data.get('notification_type', 'browser')
    notification_config = alert_data.get('notification_config', {})
    
    success = False
    
    if notification_type == 'telegram':
        chat_id = notification_config.get('chat_id')
        if chat_id:
            print(f"🔔 Sending Telegram alert to chat {chat_id}")
            success = send_telegram_alert(user_id, chat_id, message)
        else:
            print("❌ Telegram chat ID not configured for alert")
            
    elif notification_type == 'email':
        recipient_email = notification_config.get('recipient_email')
        if recipient_email:
            subject = f"PC Monitor Alert: {alert_data['alert_name']}"
            print(f"🔔 Sending Email alert to {recipient_email}")
            success = send_email_alert(user_id, recipient_email, subject, message)
        else:
            print("❌ Email recipient not configured for alert")
            
    else:  # browser
        print(f"🔔 Browser notification: {message}")
        success = True
    
    return success

def cleanup_old_pcs():
    """Remove old duplicate PCs that have been offline for a long time"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        c.execute('''
            SELECT p1.pc_id, p1.pc_name, p1.last_seen 
            FROM pcs p1
            WHERE p1.status = 'offline' 
            AND p1.last_seen < datetime('now', '-1 day')
            AND EXISTS (
                SELECT 1 FROM pcs p2 
                WHERE p2.pc_name = p1.pc_name 
                AND p2.pc_id != p1.pc_id
                AND p2.status = 'online'
            )
        ''')
        
        old_pcs = c.fetchall()
        
        if old_pcs:
            print(f"🧹 Cleaning up {len(old_pcs)} old duplicate PCs...")
            for pc in old_pcs:
                print(f"🗑️ Removing old PC: {pc['pc_name']} (ID: {pc['pc_id']})")
                c.execute('DELETE FROM pcs WHERE pc_id = ?', (pc['pc_id'],))
                c.execute('DELETE FROM status_history WHERE pc_id = ?', (pc['pc_id'],))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error cleaning up old PCs: {e}")

def check_offline_pcs():
    """Automatically mark PCs as offline if they haven't reported in HEARTBEAT_TIMEOUT seconds"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        cutoff_time = datetime.utcnow() - timedelta(seconds=HEARTBEAT_TIMEOUT)
        
        c.execute('''SELECT pc_id, pc_name, last_seen FROM pcs 
                     WHERE status = 'online' AND last_seen < ?''', 
                  (cutoff_time,))
        
        offline_pcs = c.fetchall()
        
        if offline_pcs:
            print(f"🔄 Checking for offline PCs...")
            for pc in offline_pcs:
                pc_id = pc['pc_id']
                pc_name = pc['pc_name']
                last_seen = pc['last_seen']
                
                c.execute('''UPDATE pcs SET status = 'offline' WHERE pc_id = ?''', (pc_id,))
                c.execute('''INSERT INTO status_history 
                             (pc_id, status, timestamp) 
                             VALUES (?, ?, ?)''',
                          (pc_id, 'offline', datetime.utcnow()))
                
                print(f"🔴 Marked PC as offline: {pc_name} (last seen: {last_seen})")
        
        conn.commit()
        conn.close()
        cleanup_old_pcs()
        
    except Exception as e:
        print(f"Error in offline check: {e}")

def check_scheduled_alerts():
    """Check and trigger scheduled alerts"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        current_time = datetime.utcnow()
        current_hour_min = current_time.strftime('%H:%M')
        current_day = current_time.strftime('%A').lower()
        
        print(f"⏰ Checking scheduled alerts at {current_hour_min} ({current_day})...")
        
        c.execute('''
            SELECT sa.*, p.status as pc_status, p.last_seen, p.continuous_online_minutes
            FROM scheduled_alerts sa
            LEFT JOIN pcs p ON sa.pc_id = p.pc_id
            WHERE sa.enabled = 1
        ''')
        
        alerts = c.fetchall()
        triggered_count = 0
        
        for alert in alerts:
            try:
                should_trigger = False
                alert_message = ""
                
                if alert['check_time'] == current_hour_min:
                    if alert['day_of_week'] == 'daily' or alert['day_of_week'] == current_day:
                        
                        pc_status = alert['pc_status'] or 'offline'
                        pc_name = alert['pc_name']
                        
                        if alert['alert_type'] == 'still_offline' and pc_status == 'offline':
                            should_trigger = True
                            alert_message = f"🔴 PC '{pc_name}' is still offline at scheduled check time {alert['check_time']}"
                            
                        elif alert['alert_type'] == 'still_online' and pc_status == 'online':
                            condition_value = alert['condition_value']
                            online_minutes = alert['continuous_online_minutes'] or 0
                            
                            if not condition_value or online_minutes >= condition_value:
                                should_trigger = True
                                if condition_value:
                                    alert_message = f"🟢 PC '{pc_name}' has been online for {online_minutes:.0f} minutes (exceeds {condition_value} min threshold)"
                                else:
                                    alert_message = f"🟢 PC '{pc_name}' is still online at scheduled check time {alert['check_time']}"
                        
                        if should_trigger:
                            c.execute('''
                                INSERT INTO alert_history 
                                (user_id, alert_id, pc_id, pc_name, alert_name, message, alert_type)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''', (alert['user_id'], alert['id'], alert['pc_id'], 
                                  alert['pc_name'], alert['alert_name'], alert_message, alert['alert_type']))
                            
                            c.execute('''
                                UPDATE scheduled_alerts 
                                SET last_triggered = ? 
                                WHERE id = ?
                            ''', (datetime.utcnow(), alert['id']))
                            
                            notification_config = json.loads(alert['notification_config'] or '{}')
                            alert_data = {
                                'notification_type': alert['notification_type'],
                                'notification_config': notification_config,
                                'alert_name': alert['alert_name']
                            }
                            
                            notification_sent = send_alert_notification(
                                alert['user_id'], 
                                alert_data, 
                                alert_message
                            )
                            
                            if notification_sent:
                                c.execute('''
                                    UPDATE alert_history 
                                    SET notification_sent = 1 
                                    WHERE id = (SELECT MAX(id) FROM alert_history WHERE alert_id = ?)
                                ''', (alert['id'],))
                            
                            print(f"🚨 Alert triggered: {alert_message}")
                            triggered_count += 1
                            
            except Exception as e:
                print(f"Error processing alert {alert['id']}: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        if triggered_count > 0:
            print(f"✅ {triggered_count} alerts triggered with notifications")
        else:
            print("✅ No alerts to trigger")
            
    except Exception as e:
        print(f"Error checking scheduled alerts: {e}")

# Background threads
def start_offline_monitor():
    def monitor_loop():
        while True:
            try:
                check_offline_pcs()
                time.sleep(60)
            except Exception as e:
                print(f"Offline monitor error: {e}")
                time.sleep(60)
    
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    print("✅ Offline monitor started")

def start_alert_monitor():
    def alert_loop():
        while True:
            try:
                check_scheduled_alerts()
                time.sleep(60)
            except Exception as e:
                print(f"Alert monitor error: {e}")
                time.sleep(60)
    
    alert_thread = threading.Thread(target=alert_loop, daemon=True)
    alert_thread.start()
    print("✅ Alert monitor started")

# Initialize
try:
    init_db()
    create_default_admin()
    start_offline_monitor()
    start_alert_monitor()
    print("Server initialization complete!")
except Exception as e:
    print(f"Initialization failed: {e}")

print("\n" + "="*60)
print("PC Monitor Server - FIXED TELEGRAM INTEGRATION")
print("="*60)

# API Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('index.html')

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect('/')
    return render_template('login.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email and password required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if user limit reached (5 users max)
        c.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
        user_count = c.fetchone()[0]
        
        if user_count >= 5:
            conn.close()
            return jsonify({'error': 'Maximum user limit (5) reached'}), 400
        
        # Create user
        password_hash = hash_password(password)
        
        try:
            c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                      (username, email, password_hash))
            conn.commit()
            conn.close()
            
            print(f"✅ New user registered: {username}")
            return jsonify({'success': True, 'message': 'Registration successful'})
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Username or email already exists'}), 400
            
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
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
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/user')
def get_current_user_info():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    return jsonify({
        'user_id': session['user_id'],
        'username': session.get('username', 'Unknown')
    })

@app.route('/api/pcs')
def api_get_pcs():
    """Get PCs with REAL-TIME status checking"""
    print("📱 Dashboard requesting PCs data...")
    
    # Run offline check immediately when dashboard loads
    check_offline_pcs()
    
    conn = get_db()
    c = conn.cursor()
    
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
        # Calculate if PC should be considered offline
        if row['last_seen']:
            try:
                if isinstance(row['last_seen'], str):
                    last_seen = datetime.fromisoformat(row['last_seen'].replace('Z', '+00:00'))
                else:
                    last_seen = row['last_seen']
                
                time_since_last_seen = (datetime.utcnow() - last_seen).total_seconds()
            except Exception as e:
                print(f"Error parsing last_seen for {row['pc_name']}: {e}")
                time_since_last_seen = HEARTBEAT_TIMEOUT + 1
        else:
            time_since_last_seen = HEARTBEAT_TIMEOUT + 1
        
        # Override status if PC hasn't reported recently
        actual_status = row['status']
        if actual_status == 'online' and time_since_last_seen > HEARTBEAT_TIMEOUT:
            actual_status = 'offline'
            print(f"🔴 Real-time offline: {row['pc_name']} (last seen {time_since_last_seen:.0f}s ago)")
        
        # Parse data
        running_apps = []
        if row['running_apps']:
            try:
                running_apps = json.loads(row['running_apps'])
            except:
                running_apps = []
        
        processes = []
        if row['processes']:
            try:
                processes = json.loads(row['processes'])
            except:
                processes = []
        
        system_info = {}
        if row['system_info']:
            try:
                system_info = json.loads(row['system_info'])
            except:
                system_info = {}
        
        # Build PC data
        pc_data = {
            'pc_id': row['pc_id'],
            'pc_name': row['pc_name'],
            'platform': row['platform'],
            'last_seen': row['last_seen'].isoformat() if hasattr(row['last_seen'], 'isoformat') else str(row['last_seen']),
            'status': actual_status,
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
    
    conn.close()
    
    print(f"📤 Sending {len(pcs)} PCs to dashboard")
    return jsonify(pcs)

@app.route('/api/pc/register', methods=['POST'])
def api_register_pc():
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
        current_time = datetime.utcnow()
        
        c.execute('''INSERT OR REPLACE INTO pcs 
                     (pc_id, pc_name, platform, last_seen, status) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (pc_id, pc_name, platform, current_time, 'online'))
        
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
    data = request.get_json()
    pc_id = data.get('pc_id')
    
    print(f"📊 Updating PC: {pc_id}")
    
    if not pc_id:
        return jsonify({'error': 'PC ID required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        current_time = datetime.utcnow()
        
        c.execute('''UPDATE pcs 
                     SET last_seen = ?, status = 'online', continuous_online_minutes = ?
                     WHERE pc_id = ?''',
                  (current_time, data.get('continuous_online_minutes', 0), pc_id))
        
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
        print(f"✅ PC updated: {pc_id} - CPU: {data.get('cpu', {}).get('percent', 0)}%")
        conn.close()
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"❌ PC update error: {e}")
        conn.close()
        return jsonify({'error': 'Update failed'}), 500

# COMPLETE ALERTS API ENDPOINTS
@app.route('/api/scheduled-alerts', methods=['GET', 'POST'])
def api_scheduled_alerts():
    """Get all scheduled alerts or create new one"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if request.method == 'GET':
        # Get all scheduled alerts for current user
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT sa.*, p.pc_name, p.status as pc_status 
            FROM scheduled_alerts sa
            LEFT JOIN pcs p ON sa.pc_id = p.pc_id
            WHERE sa.user_id = ?
            ORDER BY sa.created_at DESC
        ''', (session['user_id'],))
        
        alerts = []
        for row in c.fetchall():
            alerts.append({
                'id': row['id'],
                'pc_id': row['pc_id'],
                'pc_name': row['pc_name'],
                'alert_name': row['alert_name'],
                'check_time': row['check_time'],
                'day_of_week': row['day_of_week'],
                'alert_type': row['alert_type'],
                'condition_value': row['condition_value'],
                'enabled': bool(row['enabled']),
                'notification_type': row['notification_type'],
                'last_triggered': row['last_triggered'],
                'created_at': row['created_at']
            })
        
        conn.close()
        return jsonify(alerts)
    
    else:  # POST - Create new alert
        data = request.get_json()
        
        required_fields = ['pc_id', 'alert_name', 'check_time', 'day_of_week', 'alert_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        try:
            # Get PC name for the alert
            c.execute('SELECT pc_name FROM pcs WHERE pc_id = ?', (data['pc_id'],))
            pc_result = c.fetchone()
            pc_name = pc_result['pc_name'] if pc_result else 'Unknown PC'
            
            # Insert new alert
            c.execute('''
                INSERT INTO scheduled_alerts 
                (user_id, pc_id, pc_name, alert_name, check_time, day_of_week, 
                 alert_type, condition_value, notification_type, notification_config)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session['user_id'], data['pc_id'], pc_name, data['alert_name'],
                data['check_time'], data['day_of_week'], data['alert_type'],
                data.get('condition_value'), data.get('notification_type', 'browser'),
                json.dumps(data.get('notification_config', {}))
            ))
            
            alert_id = c.lastrowid
            conn.commit()
            conn.close()
            
            print(f"✅ Scheduled alert created: {data['alert_name']} for PC {pc_name}")
            return jsonify({'success': True, 'alert_id': alert_id})
            
        except Exception as e:
            print(f"❌ Error creating scheduled alert: {e}")
            conn.close()
            return jsonify({'error': 'Failed to create alert'}), 500

@app.route('/api/scheduled-alerts/<int:alert_id>', methods=['PUT', 'DELETE'])
def api_scheduled_alert(alert_id):
    """Update or delete a specific scheduled alert"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    # Verify alert belongs to current user
    c.execute('SELECT id FROM scheduled_alerts WHERE id = ? AND user_id = ?', 
              (alert_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Alert not found'}), 404
    
    if request.method == 'PUT':
        data = request.get_json()
        
        try:
            if 'enabled' in data:
                c.execute('UPDATE scheduled_alerts SET enabled = ? WHERE id = ?',
                         (1 if data['enabled'] else 0, alert_id))
            
            conn.commit()
            conn.close()
            return jsonify({'success': True})
            
        except Exception as e:
            print(f"❌ Error updating alert: {e}")
            conn.close()
            return jsonify({'error': 'Failed to update alert'}), 500
    
    else:  # DELETE
        try:
            c.execute('DELETE FROM scheduled_alerts WHERE id = ?', (alert_id,))
            conn.commit()
            conn.close()
            
            print(f"✅ Scheduled alert deleted: {alert_id}")
            return jsonify({'success': True})
            
        except Exception as e:
            print(f"❌ Error deleting alert: {e}")
            conn.close()
            return jsonify({'error': 'Failed to delete alert'}), 500

@app.route('/api/alert-history')
def api_alert_history():
    """Get alert history for current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''
        SELECT ah.*, sa.alert_name as scheduled_alert_name
        FROM alert_history ah
        LEFT JOIN scheduled_alerts sa ON ah.alert_id = sa.id
        WHERE ah.user_id = ?
        ORDER BY ah.timestamp DESC
        LIMIT 100
    ''', (session['user_id'],))
    
    history = []
    for row in c.fetchall():
        history.append({
            'id': row['id'],
            'alert_id': row['alert_id'],
            'pc_id': row['pc_id'],
            'pc_name': row['pc_name'],
            'alert_name': row['alert_name'] or row['scheduled_alert_name'],
            'message': row['message'],
            'alert_type': row['alert_type'],
            'timestamp': row['timestamp'],
            'notification_sent': bool(row['notification_sent'])
        })
    
    conn.close()
    return jsonify(history)

@app.route('/api/recent-alerts')
def api_recent_alerts():
    """Get recent alerts for browser notifications"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    # Get alerts from last 5 minutes that haven't been sent as browser notifications
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    
    c.execute('''
        SELECT message, timestamp 
        FROM alert_history 
        WHERE user_id = ? AND timestamp > ? AND notification_sent = 0
        ORDER BY timestamp DESC
    ''', (session['user_id'], five_minutes_ago))
    
    recent_alerts = []
    for row in c.fetchall():
        recent_alerts.append({
            'message': row['message'],
            'timestamp': row['timestamp']
        })
    
    # Mark as sent
    if recent_alerts:
        c.execute('''
            UPDATE alert_history 
            SET notification_sent = 1 
            WHERE user_id = ? AND timestamp > ?
        ''', (session['user_id'], five_minutes_ago))
        conn.commit()
    
    conn.close()
    return jsonify(recent_alerts)

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """Get or save user settings"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if request.method == 'GET':
        conn = get_db()
        c = conn.cursor()
        
        c.execute('SELECT key, value FROM settings WHERE user_id = ?', (session['user_id'],))
        settings = {row['key']: row['value'] for row in c.fetchall()}
        
        conn.close()
        return jsonify(settings)
    
    else:  # POST
        data = request.get_json()
        conn = get_db()
        c = conn.cursor()
        
        try:
            for key, value in data.items():
                c.execute('''
                    INSERT OR REPLACE INTO settings (user_id, key, value)
                    VALUES (?, ?, ?)
                ''', (session['user_id'], key, value))
            
            conn.commit()
            conn.close()
            return jsonify({'success': True})
            
        except Exception as e:
            print(f"❌ Error saving settings: {e}")
            conn.close()
            return jsonify({'error': 'Failed to save settings'}), 500

@app.route('/api/telegram/setup', methods=['GET'])
def api_telegram_setup():
    """Get Telegram setup instructions and verify current bot"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT value FROM settings WHERE user_id = ? AND key = ?', 
             (session['user_id'], 'telegram_token'))
    token_result = c.fetchone()
    conn.close()
    
    bot_token = token_result['value'] if token_result else None
    bot_status = None
    updates_info = None
    
    if bot_token:
        bot_status = get_telegram_bot_info(bot_token)
        if bot_status:
            updates_info = get_telegram_updates(bot_token)
    
    return jsonify({
        'has_token': bool(bot_token),
        'bot_status': bot_status,
        'updates_available': updates_info,
        'instructions': {
            'step1': 'Create a bot with @BotFather on Telegram',
            'step2': 'Get the bot token (format: 123456789:ABCdefGHIjklMnOpQRsTuvwxyz)',
            'step3': 'Save the bot token in Settings',
            'step4': 'Send a message to your bot',
            'step5': 'Use /api/telegram/updates to get your Chat ID',
            'step6': 'Use the Chat ID in your alert configurations'
        }
    })

@app.route('/api/telegram/updates', methods=['GET'])
def api_telegram_updates():
    """Get recent Telegram updates to find Chat ID"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT value FROM settings WHERE user_id = ? AND key = ?', 
             (session['user_id'], 'telegram_token'))
    token_result = c.fetchone()
    conn.close()
    
    if not token_result or not token_result['value']:
        return jsonify({'error': 'Telegram bot token not configured'}), 400
    
    bot_token = token_result['value']
    
    try:
        url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('ok'):
                chats = []
                for update in data['result']:
                    if 'message' in update:
                        chat = update['message']['chat']
                        chats.append({
                            'chat_id': chat['id'],
                            'first_name': chat.get('first_name', 'Unknown'),
                            'username': chat.get('username', 'No username'),
                            'type': chat.get('type', 'unknown')
                        })
                return jsonify({'success': True, 'chats': chats})
            else:
                return jsonify({'error': 'No messages found. Send a message to your bot first.'}), 400
        else:
            return jsonify({'error': f'Telegram API error: {response.status_code}'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error getting updates: {str(e)}'}), 500

@app.route('/api/test-telegram', methods=['POST'])
def api_test_telegram():
    """Test Telegram configuration with detailed feedback"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    chat_id = data.get('chat_id')
    
    if not chat_id:
        return jsonify({'error': 'Chat ID required'}), 400
    
    message = "🎉 This is a TEST message from your PC Monitor system! If you receive this, your Telegram configuration is working perfectly!"
    
    success = send_telegram_alert(session['user_id'], chat_id, message)
    
    if success:
        return jsonify({'success': True, 'message': 'Test Telegram message sent successfully!'})
    else:
        return jsonify({'error': 'Failed to send test message. Check your bot token and chat ID.'}), 500

@app.route('/api/test-email', methods=['POST'])
def api_test_email():
    """Test email configuration"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    recipient_email = data.get('email')
    
    if not recipient_email:
        return jsonify({'error': 'Recipient email required'}), 400
    
    subject = "PC Monitor - Test Email"
    message = "This is a test email from your PC Monitor system. If you're receiving this, your email configuration is working correctly!"
    
    success = send_email_alert(session['user_id'], recipient_email, subject, message)
    
    if success:
        return jsonify({'success': True, 'message': 'Test email sent successfully!'})
    else:
        return jsonify({'error': 'Failed to send test email. Check your settings.'}), 500

if __name__ == '__main__':
    print(f"\n🚀 Server starting: http://localhost:5000")
    print("✅ Telegram integration: FIXED WITH DEBUGGING")
    print("🔧 New endpoints:")
    print("   GET /api/telegram/setup - Setup instructions & bot verification")
    print("   GET /api/telegram/updates - Get Chat ID from recent messages")
    print("   POST /api/test-telegram - Test Telegram configuration")
    print("Default Login: admin / admin123")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True, threaded=True)
