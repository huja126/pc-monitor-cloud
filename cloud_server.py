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
    
    # ... (keep all your existing table creation code the same) ...
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

# ... (keep all your existing functions: cleanup_old_pcs, check_offline_pcs, check_scheduled_alerts, etc.) ...

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

# API Routes (keep all your existing routes, but add these new ones)

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

# ... (keep all your other existing API routes exactly as they were) ...

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
    # ... (keep your existing register code) ...

@app.route('/api/login', methods=['POST'])
def api_login():
    # ... (keep your existing login code) ...

@app.route('/api/logout', methods=['POST'])
def api_logout():
    # ... (keep your existing logout code) ...

# ... (keep all your other existing routes) ...

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
