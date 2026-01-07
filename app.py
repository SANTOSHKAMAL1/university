import re
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask, json, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson import ObjectId
from datetime import datetime, timedelta
import pytz
from config import Config
from flask_mail import Mail, Message
import random
from apscheduler.schedulers.background import BackgroundScheduler
import pandas as pd
from io import StringIO, BytesIO
import logging
import requests
from werkzeug.middleware.proxy_fix import ProxyFix

# Google OAuth imports
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Apply ProxyFix for HTTPS handling
from werkzeug.middleware.proxy_fix import ProxyFix

# Initialize Flask app FIRST
app = Flask(__name__)
app.config.from_object(Config)

# THEN apply ProxyFix
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_proto=1,
    x_host=1
)


app = Flask(__name__)


# Upload folder settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'csv', 'xls'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize MongoDB
mongo = PyMongo(app)
db = mongo.db

# Mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'info.loginpanel@gmail.com'
app.config['MAIL_PASSWORD'] = 'wedbfepklgtwtugf'
mail = Mail(app)

# INDIAN TIMEZONE
IST = pytz.timezone('Asia/Kolkata')

# Google OAuth Scopes
DRIVE_SCOPES = [
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive'
]
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# ===================== HELPER FUNCTIONS =====================
def get_indian_time():
    """Get current time in Indian Standard Time (IST)"""
    return datetime.now(IST)

def convert_to_ist(dt):
    """Convert datetime to IST if it's naive"""
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(IST)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_drive_service():
    """Get authenticated Google Drive service with proper error handling"""
    if 'drive_creds' not in session:
        logger.warning("No drive credentials in session")
        return None
    
    try:
        creds_data = session['drive_creds']
        
        # Validate credentials data
        required_fields = ['token', 'refresh_token', 'token_uri', 'client_id', 'client_secret']
        for field in required_fields:
            if field not in creds_data:
                logger.error(f"Missing required field in credentials: {field}")
                return None
        
        creds = Credentials(
            token=creds_data['token'],
            refresh_token=creds_data['refresh_token'],
            token_uri=creds_data['token_uri'],
            client_id=creds_data['client_id'],
            client_secret=creds_data['client_secret'],
            scopes=creds_data.get('scopes', DRIVE_SCOPES)
        )
        
        # Build and return service
        service = build('drive', 'v3', credentials=creds)
        logger.info("✅ Drive service created successfully")
        return service
        
    except Exception as e:
        logger.error(f"❌ Error getting drive service: {e}", exc_info=True)
        # Clear invalid credentials
        session.pop('drive_creds', None)
        return None

def make_file_public(service, file_id):
    """Make a file public (anyone with link can view)"""
    try:
        permission = {
            'type': 'anyone',
            'role': 'reader'
        }
        service.permissions().create(
            fileId=file_id,
            body=permission
        ).execute()
        logger.info(f"✅ File {file_id} made public")
        return True
    except Exception as e:
        logger.error(f"❌ Error making file public: {e}")
        return False

def make_file_private(service, file_id):
    """Make a file private (remove public access)"""
    try:
        # Get all permissions
        permissions = service.permissions().list(fileId=file_id).execute()
        
        # Find and delete 'anyone' permission
        for perm in permissions.get('permissions', []):
            if perm.get('type') == 'anyone':
                service.permissions().delete(
                    fileId=file_id,
                    permissionId=perm['id']
                ).execute()
                logger.info(f"✅ File {file_id} made private")
                return True
        
        logger.info(f"⚠️ File {file_id} is already private")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error making file private: {e}")
        return False

def delete_drive_file(service, file_id):
    """Delete a file from Google Drive"""
    try:
        service.files().delete(fileId=file_id).execute()
        logger.info(f"✅ File {file_id} deleted from Drive")
        return True
    except Exception as e:
        logger.error(f"❌ Error deleting Drive file: {e}")
        return False

def get_drive_stats():
    """Get Drive statistics for user dashboard"""
    try:
        service = get_drive_service()
        if not service:
            logger.warning("Drive service unavailable for stats")
            return {'total_files': 0, 'recent_uploads': []}
        
        # Get recent files
        seven_days_ago = (get_indian_time() - timedelta(days=7)).isoformat()
        recent = service.files().list(
            q=f"createdTime >= '{seven_days_ago}' and trashed=false",
            pageSize=10,
            orderBy="createdTime desc",
            fields="files(id, name, mimeType, createdTime, parents, webViewLink)"
        ).execute()
        
        recent_files = recent.get('files', [])
        
        # Enrich with folder names
        for file in recent_files:
            if file.get('parents'):
                try:
                    folder = service.files().get(
                        fileId=file['parents'][0],
                        fields='name'
                    ).execute()
                    file['folder_name'] = folder.get('name', 'Root')
                except Exception as e:
                    logger.warning(f"Could not get folder name: {e}")
                    file['folder_name'] = 'Root'
            else:
                file['folder_name'] = 'Root'
        
        # Get total file count
        all_files = service.files().list(
            q="trashed=false",
            pageSize=1000,
            fields="files(id)"
        ).execute()
        
        stats = {
            'total_files': len(all_files.get('files', [])),
            'recent_uploads': recent_files
        }
        
        logger.info(f"✅ Drive stats retrieved: {stats['total_files']} files")
        return stats
        
    except Exception as e:
        logger.error(f"❌ Error getting drive stats: {e}", exc_info=True)
        return {'total_files': 0, 'recent_uploads': []}

def get_user_navbar(email):
    """Get user's custom navbar items"""
    try:
        nav = db.user_navbars.find_one({"user_email": email})
        return nav.get('items', []) if nav else []
    except Exception as e:
        logger.error(f"Error getting user navbar: {e}")
        return []

# ===================== CONTEXT PROCESSORS =====================
@app.context_processor
def inject_notifications():
    """Inject notifications into all templates if user is logged in"""
    try:
        if 'email' in session and session.get('role') == 'user':
            notifications = get_user_notifications()
            return dict(notifications=notifications)
    except Exception as e:
        logger.error(f"Error injecting notifications: {e}")
    return dict(notifications=[])

@app.context_processor
def inject_user_navbar():
    """Inject user navbar into all templates"""
    try:
        if 'email' in session and session.get('role') == 'user':
            navbar = get_user_navbar(session['email'])
            return dict(user_navbar=navbar)
    except Exception as e:
        logger.error(f"Error injecting navbar: {e}")
    return dict(user_navbar=[])

def get_user_notifications():
    """Get user notifications (reminders, subscriptions, recent activities)"""
    try:
        if 'email' not in session:
            return []
        
        user = db.users.find_one({'email': session['email']})
        if not user:
            return []
        
        notifications = []
        
        # Get upcoming reminders
        upcoming_reminders = list(db.event_reminders.find({
            'user_id': user['_id'],
            'sent': False
        }).sort('reminder_datetime', 1).limit(5))
        
        for reminder in upcoming_reminders:
            event = db.events.find_one({'_id': reminder['event_id']})
            if event:
                notifications.append({
                    'type': 'reminder',
                    'icon': 'bell',
                    'title': f"Reminder: {event['event_name']}",
                    'message': f"Set for {reminder['reminder_datetime'].strftime('%d %b at %I:%M %p')} IST",
                    'time': reminder.get('created_at', get_indian_time()),
                    'link': url_for('jainevents')
                })
        
        # Get event subscriptions
        subscriptions = list(db.event_subscriptions.find({
            'user_id': user['_id']
        }).sort('subscribed_at', -1).limit(3))
        
        for sub in subscriptions:
            event = db.events.find_one({'_id': sub['event_id']})
            if event:
                notifications.append({
                    'type': 'subscription',
                    'icon': 'envelope',
                    'title': f"Subscribed to {event['event_name']}",
                    'message': f"Event on {event['event_date']}",
                    'time': sub.get('subscribed_at', get_indian_time()),
                    'link': url_for('jainevents')
                })
        
        # Get recent file uploads
        recent_uploads = list(db.user_files.find({
            'user_email': session['email']
        }).sort('uploaded_at', -1).limit(3))
        
        for upload in recent_uploads:
            notifications.append({
                'type': 'file',
                'icon': 'file',
                'title': f"File uploaded: {upload['file_name']}",
                'message': f"Source: {upload.get('source', 'Local')}",
                'time': upload.get('uploaded_at', get_indian_time()),
                'link': url_for('user_dashboard', tab='files')
            })
        
        # Get office of academics notifications
        office_files = list(db.public_files.find().sort('uploaded_at', -1).limit(3))
        for file in office_files:
            notifications.append({
                'type': 'office',
                'icon': 'building',
                'title': f"New Public File: {file['name']}",
                'message': f"Uploaded by Office of Academics",
                'time': file.get('uploaded_at', get_indian_time()),
                'link': url_for('user_dashboard', tab='office')
            })
        
        # Sort by time
        notifications.sort(key=lambda x: x['time'], reverse=True)
        return notifications[:10]
        
    except Exception as e:
        logger.error(f"Error getting notifications: {e}")
        return []

def validate_excel_data(df):
    """Validate Excel data before insertion"""
    errors = []
    required_columns = ['event_name', 'description', 'school', 'department', 'event_type', 'venue', 'event_date']
    
    missing_cols = [col for col in required_columns if col not in df.columns]
    if missing_cols:
        return False, [f"Missing required columns: {', '.join(missing_cols)}"], None
    
    cleaned_records = []
    
    for idx, row in df.iterrows():
        record_errors = []
        
        if pd.isna(row.get('event_name')) or str(row['event_name']).strip() == '':
            record_errors.append(f"Row {idx+2}: event_name is required")
            continue
        
        if pd.isna(row.get('description')) or str(row['description']).strip() == '':
            record_errors.append(f"Row {idx+2}: description is required")
            continue
        
        try:
            event_date = pd.to_datetime(row['event_date']).strftime('%Y-%m-%d')
        except Exception as e:
            record_errors.append(f"Row {idx+2}: Invalid event_date format (use YYYY-MM-DD)")
            continue
        
        end_date = None
        if not pd.isna(row.get('end_date')):
            try:
                end_date = pd.to_datetime(row['end_date']).strftime('%Y-%m-%d')
            except:
                record_errors.append(f"Row {idx+2}: Invalid end_date format (use YYYY-MM-DD)")
                continue
        
        if record_errors:
            errors.extend(record_errors)
            continue
        
        clean_record = {
            'event_name': str(row['event_name']).strip(),
            'description': str(row['description']).strip(),
            'school': str(row['school']).strip(),
            'department': str(row['department']).strip(),
            'event_type': str(row['event_type']).strip(),
            'venue': str(row['venue']).strip(),
            'event_date': event_date,
            'end_date': end_date,
            'event_time': str(row.get('event_time', 'All Day')).strip() if not pd.isna(row.get('event_time')) else 'All Day',
            'event_action': str(row.get('event_action', '')).strip() or None,
            'image': None,
            'pdf': None,
            'created_at': get_indian_time()
        }
        
        cleaned_records.append(clean_record)
    
    if errors:
        return False, errors, None
    
    return True, [], cleaned_records

# ===================== SCHEDULED TASKS =====================
def send_event_reminders():
    """Send event reminders based on user preferences - FIXED TIMEZONE HANDLING"""
    try:
        now = get_indian_time()
        
        reminders = list(db.event_reminders.find({
            'sent': False,
            'reminder_datetime': {'$lte': now}
        }))
        
        logger.info(f"[REMINDER CHECK] Current IST time: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"[REMINDER CHECK] Found {len(reminders)} pending reminders")
        
        for reminder in reminders:
            try:
                reminder_dt = reminder.get('reminder_datetime')
                
                # Ensure datetime is timezone aware
                if reminder_dt.tzinfo is None:
                    reminder_dt = IST.localize(reminder_dt)
                else:
                    reminder_dt = reminder_dt.astimezone(IST)
                
                logger.info(f"[REMINDER] Checking reminder for {reminder_dt.strftime('%Y-%m-%d %H:%M:%S')} IST")
                
                event = db.events.find_one({'_id': reminder['event_id']})
                if not event:
                    logger.warning(f"[REMINDER] Event not found: {reminder['event_id']}")
                    continue
                
                user = db.users.find_one({'_id': reminder['user_id']})
                if not user:
                    logger.warning(f"[REMINDER] User not found: {reminder['user_id']}")
                    continue
                
                msg = Message(
                    subject=f"🔔 Event Reminder: {event['event_name']}",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[user['email']]
                )
                
                msg.html = f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9fafb; border-radius: 10px;">
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
                        <h1 style="color: white; margin: 0; font-size: 28px;">⏰ Event Reminder</h1>
                    </div>
                    
                    <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                        <h2 style="color: #1f2937; margin-top: 0; font-size: 24px;">{event['event_name']}</h2>
                        
                        <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <p style="margin: 10px 0; color: #374151;"><strong>📅 Date:</strong> {event['event_date']}</p>
                            <p style="margin: 10px 0; color: #374151;"><strong>⏰ Time:</strong> {event.get('event_time', 'All Day')}</p>
                            <p style="margin: 10px 0; color: #374151;"><strong>📍 Venue:</strong> {event['venue']}</p>
                            <p style="margin: 10px 0; color: #374151;"><strong>🏢 Department:</strong> {event.get('department', 'N/A')}</p>
                            <p style="margin: 10px 0; color: #374151;"><strong>🏫 School:</strong> {event.get('school', 'N/A')}</p>
                        </div>
                        
                        <div style="margin: 20px 0; padding: 15px; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 4px;">
                            <p style="margin: 0; color: #1e40af;"><strong>📝 Description:</strong></p>
                            <p style="margin: 10px 0 0 0; color: #1e40af;">{event.get('description', 'No description provided')}</p>
                        </div>
                        
                        <p style="color: #6b7280; font-size: 14px; margin-top: 20px;">
                            This is your scheduled reminder. The event is coming up soon!
                        </p>
                        
                        <div style="text-align: center; margin-top: 30px;">
                            <p style="color: #9ca3af; font-size: 12px; margin: 5px 0;">Reminder sent at: {now.strftime('%Y-%m-%d %I:%M %p')} IST</p>
                        </div>
                    </div>
                    
                    <div style="text-align: center; margin-top: 20px; padding: 20px;">
                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                        <p style="color: #6b7280; font-size: 12px; margin: 5px 0;">
                            Jain University Portal - Office of Academics
                        </p>
                        <p style="color: #9ca3af; font-size: 11px; margin: 5px 0;">
                            This is an automated reminder. Please do not reply to this email.
                        </p>
                    </div>
                </div>
                """
                
                mail.send(msg)
                
                db.event_reminders.update_one(
                    {'_id': reminder['_id']},
                    {'$set': {
                        'sent': True,
                        'sent_at': now
                    }}
                )
                
                logger.info(f"✅ [REMINDER SENT] To: {user['email']} | Event: {event['event_name']} | Time: {now.strftime('%Y-%m-%d %H:%M:%S')} IST")
                
            except Exception as e:
                logger.error(f"❌ [REMINDER ERROR] {str(e)}", exc_info=True)
                continue
                
    except Exception as e:
        logger.error(f"❌ [REMINDER SYSTEM ERROR] {str(e)}", exc_info=True)

def send_daily_event_emails():
    """Send daily digest of upcoming events to subscribers"""
    try:
        today_ist = get_indian_time().strftime("%Y-%m-%d")
        upcoming_ist = (get_indian_time() + timedelta(days=7)).strftime("%Y-%m-%d")
        
        subscribers = list(db.subscribers.find())
        events = list(db.events.find({
            "event_date": {"$gte": today_ist, "$lte": upcoming_ist}
        }))
        
        logger.info(f"[DAILY EMAIL] Sending to {len(subscribers)} subscribers about {len(events)} events")
        
        for sub in subscribers:
            try:
                msg = Message(
                    "📅 Upcoming University Events - Weekly Digest", 
                    sender=app.config['MAIL_USERNAME'], 
                    recipients=[sub['email']]
                )
                
                body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #04043a;">Hello,</h2>
                    <p>Here are the upcoming events for this week:</p>
                    <hr>
                """
                
                for e in events:
                    if not sub.get('school') or e.get('school') == sub.get('school'):
                        body += f"""
                        <div style="margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                            <h3 style="color: #04043a; margin-top: 0;">{e['event_name']}</h3>
                            <p><strong>📅 Date:</strong> {e['event_date']}</p>
                            <p><strong>📍 Venue:</strong> {e['venue']}</p>
                            <p><strong>🏫 School:</strong> {e.get('school', 'N/A')}</p>
                            <p><strong>📝 Description:</strong> {e.get('description', 'N/A')}</p>
                        </div>
                        """
                
                body += """
                    <hr>
                    <p style="color: #666; font-size: 12px;">
                        Jain University Portal - Office of Academics<br>
                        This is an automated email. Please do not reply.
                    </p>
                </body>
                </html>
                """
                
                msg.html = body
                mail.send(msg)
                logger.info(f"✅ Daily digest sent to {sub['email']}")
            except Exception as e:
                logger.error(f"❌ Error sending daily email to {sub['email']}: {e}")
    except Exception as e:
        logger.error(f"❌ Error in send_daily_event_emails: {e}")

def send_newsletter_email(title, content, image_filename, recipients):
    """Send newsletter email to recipients"""
    try:
        msg = Message(subject=title, sender=app.config['MAIL_USERNAME'], recipients=recipients)
        msg.html = content

        if image_filename:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            if os.path.exists(image_path):
                with app.open_resource(image_path) as img:
                    msg.attach(image_filename, "image/jpeg", img.read())

        mail.send(msg)
    except Exception as e:
        logger.error(f"Error sending newsletter email: {e}")
        raise

# ===================== AUTHENTICATION ROUTES =====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'step' not in session:
        session['step'] = 1
    
    if request.method == 'POST':
        if session['step'] == 1:
            email = request.form.get('email')
            if not email.endswith('@jainuniversity.ac.in'):
                flash('Only @jainuniversity.ac.in emails allowed', 'error')
                return redirect(url_for('register'))
            if db.users.find_one({'email': email}):
                flash('Email already registered', 'error')
                return redirect(url_for('register'))
            
            otp = str(random.randint(100000, 999999))
            session['email'] = email
            session['otp'] = otp
            
            try:
                msg = Message('Your OTP for Registration', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your OTP is: {otp}\nPlease use this to complete your registration.'
                mail.send(msg)
                
                session['step'] = 2
                flash('OTP sent to your email. Please check and enter it.', 'info')
            except Exception as e:
                logger.error(f"Error sending OTP: {e}")
                flash('Error sending OTP. Please try again.', 'error')
            
            return redirect(url_for('register'))
        
        elif session['step'] == 2:
            entered_otp = request.form.get('otp')
            if entered_otp == session.get('otp'):
                session['otp_verified'] = True
                session['step'] = 3
                flash('OTP verified. Now set your password.', 'success')
                return redirect(url_for('register'))
            else:
                flash('Invalid OTP. Please try again.', 'error')
                return redirect(url_for('register'))
        
        elif session['step'] == 3:
            password = request.form.get('password')
            hashed_pw = generate_password_hash(password)
            db.users.insert_one({'email': session['email'], 'password': hashed_pw, 'role': 'user'})
            
            session.pop('email', None)
            session.pop('otp', None)
            session.pop('step', None)
            session.pop('otp_verified', None)
            
            flash('✅ Registration complete! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    otp_sent = session.get('step', 1) >= 2
    otp_verified = session.get('step', 1) == 3
    return render_template('register.html', otp_sent=otp_sent, otp_verified=otp_verified)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if not email.endswith('@jainuniversity.ac.in'):
            flash('Only @jainuniversity.ac.in emails allowed', 'error')
            return redirect(url_for('admin'))
        
        if db.users.find_one({'email': email}):
            flash('Email already registered', 'error')
            return redirect(url_for('admin'))
        
        hashed_pw = generate_password_hash(password)
        db.users.insert_one({'email': email, 'password': hashed_pw, 'role': 'admin'})
        flash('✅ Admin registered successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('admin_register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = db.users.find_one({'email': email})
        if not user or not check_password_hash(user['password'], password):
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))
        
        session['email'] = user['email']
        session['role'] = user['role']
        
        if user['role'] == 'admin':
            flash(f'Welcome back, Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash(f'Welcome back, {email}!', 'success')
            return redirect(url_for('user_dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# ===================== DASHBOARD ROUTES =====================
@app.route('/user')
@app.route('/user_dashboard')
def user_dashboard():
    """User dashboard with tabs and notifications - COMPLETELY FIXED"""
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in to access the dashboard', 'error')
        return redirect(url_for('login'))
    
    try:
        # Get user
        user = db.users.find_one({'email': session['email']})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('login'))
        
        # Get notifications
        notifications = get_user_notifications()
        
        # Get today's date in IST
        today = get_indian_time().replace(hour=0, minute=0, second=0, microsecond=0)
        next_week = today + timedelta(days=7)
        today_str = today.strftime('%Y-%m-%d')
        next_week_str = next_week.strftime('%Y-%m-%d')
        
        # Get today's events
        today_events = list(db.events.find({
            "$or": [
                {"event_date": today_str},
                {
                    "$and": [
                        {"event_date": {"$lte": today_str}},
                        {"end_date": {"$gte": today_str}}
                    ]
                }
            ]
        }).sort('event_date', 1))
        
        # Get upcoming events
        tomorrow_str = (today + timedelta(days=1)).strftime('%Y-%m-%d')
        upcoming_events = list(db.events.find({
            "event_date": {
                "$gte": tomorrow_str,
                "$lte": next_week_str
            }
        }).sort('event_date', 1))
        
        # Get user's reminders
        user_reminders = list(db.event_reminders.find({
            'user_id': user['_id']
        }).sort('reminder_datetime', 1))
        
        # Enrich reminders with event data
        for reminder in user_reminders:
            event = db.events.find_one({'_id': reminder['event_id']})
            if event:
                reminder['event'] = event
        
        # Get drive connection status
        drive_connected = 'drive_creds' in session
        
        # Get user's LOCAL files (uploaded via form)
        local_files = list(db.user_files.find({
            'user_email': session['email'],
            'source': 'local'
        }).sort('uploaded_at', -1))
        
        # Get user's DRIVE files (uploaded to Drive)
        drive_files = list(db.user_files.find({
            'user_email': session['email'],
            'source': 'drive'
        }).sort('uploaded_at', -1))
        
        # Combine all user files
        user_files = local_files + drive_files
        
        # Get public files from MongoDB
        public_files_db = list(db.public_files.find().sort('uploaded_at', -1))
        
        # Get Drive public files
        drive_public_files = []
        if drive_connected:
            try:
                service = get_drive_service()
                if service:
                    results = service.files().list(
                        q="trashed=false and visibility='anyoneWithLink'",
                        pageSize=100,
                        fields="files(id, name, mimeType, webViewLink, modifiedTime, owners)",
                        orderBy="modifiedTime desc"
                    ).execute()
                    
                    for file in results.get('files', []):
                        owner_email = file.get('owners', [{}])[0].get('emailAddress', '')
                        drive_public_files.append({
                            'file_id': file['id'],
                            'name': file['name'],
                            'web_link': file.get('webViewLink'),
                            'uploader_email': owner_email,
                            'uploaded_at': file.get('modifiedTime'),
                            'is_owner': owner_email == session['email']
                        })
            except Exception as e:
                logger.error(f"Error fetching drive public files: {e}")
        
        # Combine public files from both sources
        public_files = []
        
        # Add MongoDB public files
        for file in public_files_db:
            public_files.append({
                'file_id': str(file['_id']),
                'name': file['name'],
                'web_link': file.get('web_link'),
                'uploader_email': file.get('uploader_email'),
                'uploaded_at': file.get('uploaded_at'),
                'is_owner': file.get('uploader_email') == session['email'],
                'source': 'mongodb'
            })
        
        # Add Drive public files
        public_files.extend(drive_public_files)
        
        # Get user navbar
        user_navbar = get_user_navbar(session['email'])
        
        # Gmail connection status
        gmail_connected = 'gmail_creds' in session
        
        return render_template(
            'user_dashboard.html',
            today_events=today_events,
            upcoming_events=upcoming_events,
            user_reminders=user_reminders,
            drive_connected=drive_connected,
            gmail_connected=gmail_connected,
            public_files=public_files,
            user_navbar=user_navbar,
            user_files=user_files,
            local_files=local_files,
            drive_files=drive_files,
            notifications=notifications,
            drive_public_files=drive_public_files,
            now=get_indian_time()
        )
    except Exception as e:
        logger.error(f"❌ Error in user_dashboard: {str(e)}", exc_info=True)
        flash('Error loading dashboard. Please try again.', 'error')
        
        return render_template(
            'user_dashboard.html',
            today_events=[],
            upcoming_events=[],
            user_reminders=[],
            drive_connected=False,
            gmail_connected=False,
            public_files=[],
            user_navbar=[],
            user_files=[],
            local_files=[],
            drive_files=[],
            notifications=[],
            drive_public_files=[],
            now=get_indian_time()
        )
@app.route('/upload_file', methods=['POST'])
def upload_file():
    """Upload file to local MongoDB storage"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized', 'success': False}), 401
    
    try:
        file = request.files.get('file')
        file_name = request.form.get('file_name', '')
        description = request.form.get('description', '')
        
        if not file:
            return jsonify({'error': 'No file provided', 'success': False}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed. Allowed types: pdf, docx, txt, png, jpg, jpeg, gif, xlsx, csv, xls', 'success': False}), 400
        
        # Save file
        filename = secure_filename(file.filename)
        
        # Create unique filename to avoid conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name_part, ext_part = os.path.splitext(filename)
        unique_filename = f"{name_part}_{timestamp}{ext_part}"
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # Store metadata in MongoDB
        file_doc = {
            'user_email': session['email'],
            'file_name': file_name or filename,
            'original_filename': filename,
            'stored_filename': unique_filename,
            'description': description,
            'file_path': filepath,
            'file_size': os.path.getsize(filepath),
            'file_type': ext_part.lstrip('.').lower(),
            'source': 'local',
            'is_public': False,
            'uploaded_at': get_indian_time()
        }
        
        result = db.user_files.insert_one(file_doc)
        
        logger.info(f"✅ File uploaded: {file_name or filename} by {session['email']}")
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'file_id': str(result.inserted_id),
            'file_name': file_doc['file_name']
        })
        
    except Exception as e:
        logger.error(f"❌ Error uploading file: {e}", exc_info=True)
        return jsonify({'error': str(e), 'success': False}), 400

@app.route('/set_reminder', methods=['POST'])
def set_reminder():
    """Set a reminder for an event - FIXED IST TIMEZONE"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized', 'success': False}), 401
    
    try:
        data = request.get_json()
        event_id = data.get('event_id')
        reminder_date = data.get('reminder_date')
        reminder_time = data.get('reminder_time')
        
        # Validation
        if not all([event_id, reminder_date, reminder_time]):
            return jsonify({'error': 'Missing required fields', 'success': False}), 400
        
        # Get event
        try:
            event = db.events.find_one({'_id': ObjectId(event_id)})
        except:
            return jsonify({'error': 'Invalid event ID', 'success': False}), 400
            
        if not event:
            return jsonify({'error': 'Event not found', 'success': False}), 404
        
        # Get user
        user = db.users.find_one({'email': session['email']})
        if not user:
            return jsonify({'error': 'User not found', 'success': False}), 404
        
        # Parse datetime and EXPLICITLY localize to IST
        try:
            # Combine date and time
            reminder_datetime_str = f"{reminder_date} {reminder_time}"
            # Parse as naive datetime first
            reminder_datetime_naive = datetime.strptime(reminder_datetime_str, '%Y-%m-%d %H:%M')
            
            # EXPLICITLY localize to IST - this is the key fix
            reminder_datetime = IST.localize(reminder_datetime_naive)
            
            logger.info(f"✅ Parsed reminder datetime: {reminder_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        except Exception as e:
            logger.error(f"❌ Error parsing datetime: {e}")
            return jsonify({'error': f'Invalid date/time format: {str(e)}', 'success': False}), 400
        
        # Validate time is in future using IST
        now = get_indian_time()
        logger.info(f"Current IST: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        logger.info(f"Reminder IST: {reminder_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        
        if reminder_datetime <= now:
            return jsonify({
                'error': 'Reminder time must be in the future. Please select a time ahead of now.',
                'success': False
            }), 400
        
        # Create or update reminder with timezone-aware datetime
        existing = db.event_reminders.find_one({
            'user_id': user['_id'],
            'event_id': event['_id']
        })
        
        if existing:
            db.event_reminders.update_one(
                {'_id': existing['_id']},
                {'$set': {
                    'reminder_datetime': reminder_datetime,  # Store as timezone-aware
                    'sent': False,
                    'updated_at': now
                }}
            )
            message = 'Reminder updated successfully'
        else:
            db.event_reminders.insert_one({
                'user_id': user['_id'],
                'event_id': event['_id'],
                'reminder_datetime': reminder_datetime,  # Store as timezone-aware
                'sent': False,
                'created_at': now
            })
            message = 'Reminder set successfully'
        
        logger.info(f"✅ Reminder set for {event['event_name']} at {reminder_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')} IST")
        
        # Send confirmation email
        try:
            msg = Message(
                subject=f"✅ Reminder Set: {event['event_name']}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[user['email']]
            )
            
            msg.html = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #04043a;">Reminder Confirmation</h2>
                <p>Your reminder has been set for:</p>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #04043a; margin-top: 0;">{event['event_name']}</h3>
                    <p><strong>📅 Event Date:</strong> {event['event_date']}</p>
                    <p><strong>⏰ Event Time:</strong> {event.get('event_time', 'All Day')}</p>
                    <p><strong>📍 Venue:</strong> {event['venue']}</p>
                    <p><strong>🔔 Reminder Time:</strong> {reminder_datetime.strftime('%d %B %Y at %I:%M %p')} IST</p>
                </div>
                <p>You will receive a reminder email at the scheduled time.</p>
                <hr>
                <small>Jain University Portal - Office of Academics</small>
            </div>
            """
            
            mail.send(msg)
            logger.info(f"✅ Confirmation email sent to {user['email']}")
        except Exception as email_error:
            logger.error(f"❌ Error sending confirmation email: {email_error}")
        
        return jsonify({
            'success': True,
            'message': f"{message}! A confirmation email has been sent."
        })
        
    except Exception as e:
        logger.error(f"❌ Error setting reminder: {e}", exc_info=True)
        return jsonify({'error': f'Server error: {str(e)}', 'success': False}), 500
# ===================== USER PUBLIC FILES MANAGEMENT ROUTES =====================

@app.route('/user/make-private/<file_id>', methods=['POST'])
def user_make_file_private(file_id):
    """Allow users to make their own public files private"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Find the file record
        file_record = db.public_files.find_one({'_id': ObjectId(file_id)})
        
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        # Check if the user owns this file
        if file_record.get('uploader_email') != session['email']:
            return jsonify({'error': 'You can only make your own files private'}), 403
        
        drive_file_id = file_record.get('file_id')
        file_name = file_record.get('name', 'Unknown')
        
        if not drive_file_id:
            return jsonify({'error': 'No Drive file ID found'}), 400
        
        # Check if Drive is connected
        if 'drive_creds' not in session:
            return jsonify({'error': 'Google Drive not connected'}), 400
        
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Could not connect to Google Drive'}), 400
        
        # Remove public permissions
        removed_count = 0
        try:
            permissions = service.permissions().list(fileId=drive_file_id).execute()
            
            for permission in permissions.get('permissions', []):
                if permission.get('type') == 'anyone':
                    service.permissions().delete(
                        fileId=drive_file_id,
                        permissionId=permission['id']
                    ).execute()
                    removed_count += 1
            
            if removed_count == 0:
                logger.warning(f"⚠️ No public permissions found for file: {file_name}")
                return jsonify({
                    'success': False,
                    'message': 'File was not public or permissions already removed'
                })
            
            # Remove from public_files collection
            db.public_files.delete_one({'_id': ObjectId(file_id)})
            
            # Update user_files to reflect it's no longer public
            db.user_files.update_many(
                {
                    'user_email': session['email'],
                    'drive_file_id': drive_file_id
                },
                {'$set': {'is_public': False}}
            )
            
            logger.info(f"✅ User {session['email']} made file private: {file_name}")
            
            return jsonify({
                'success': True,
                'message': f'File "{file_name}" is now private'
            })
            
        except Exception as drive_error:
            logger.error(f"❌ Error removing permissions: {drive_error}", exc_info=True)
            return jsonify({'error': f'Drive API error: {str(drive_error)}'}), 400
        
    except Exception as e:
        logger.error(f"❌ Error making file private: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400


@app.route('/user/delete-public-file/<file_id>', methods=['DELETE'])
def user_delete_public_file(file_id):
    """Allow users to delete their own public files"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Find the file record
        file_record = db.public_files.find_one({'_id': ObjectId(file_id)})
        
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        # Check if the user owns this file
        if file_record.get('uploader_email') != session['email']:
            return jsonify({'error': 'You can only delete your own files'}), 403
        
        drive_file_id = file_record.get('file_id')
        file_name = file_record.get('name', 'Unknown')
        
        # Try to delete from Google Drive if we have the file_id and Drive is connected
        drive_deleted = False
        if drive_file_id and 'drive_creds' in session:
            try:
                service = get_drive_service()
                if service:
                    # Remove public permissions first
                    try:
                        permissions = service.permissions().list(fileId=drive_file_id).execute()
                        for permission in permissions.get('permissions', []):
                            if permission.get('type') == 'anyone':
                                service.permissions().delete(
                                    fileId=drive_file_id,
                                    permissionId=permission['id']
                                ).execute()
                    except:
                        pass
                    
                    # Delete the file from Drive
                    service.files().delete(fileId=drive_file_id).execute()
                    drive_deleted = True
                    logger.info(f"✅ Deleted file from Drive: {file_name} (ID: {drive_file_id})")
            except Exception as drive_error:
                logger.warning(f"⚠️ Could not delete from Drive: {drive_error}")
                # Continue even if Drive deletion fails
        
        # Delete from public_files database
        db.public_files.delete_one({'_id': ObjectId(file_id)})
        
        # Also delete from user_files
        db.user_files.delete_one({
            'user_email': session['email'],
            'drive_file_id': drive_file_id
        })
        
        logger.info(f"✅ User {session['email']} deleted public file: {file_name}")
        
        message = f'File "{file_name}" deleted successfully'
        if drive_deleted:
            message += ' (including from Google Drive)'
        else:
            message += ' (from database only)'
        
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        logger.error(f"❌ Error deleting public file: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400


# ===================== MISSING ROUTES - ADD THESE =====================

@app.route('/usernewsletters')
def usernewsletters():
    """User newsletters page"""
    try:
        newsletters = list(db.newsletters.find().sort('uploaded_at', -1))
        return render_template('user_newsletters.html', records=newsletters)
    except Exception as e:
        logger.error(f"Error in usernewsletters: {e}")
        return render_template('user_newsletters.html', records=[])


@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')


@app.route('/monthlyengagement')
def monthlyengagement():
    """Monthly engagement reports page"""
    events = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    return render_template('monthly.html', monthly_records=events)


@app.route('/ugc')
def ugc():
    """UGC notices page"""
    return render_template('ugc.html')


@app.route('/drive_files')
def drive_files():
    """Drive files management page"""
    if 'drive_creds' not in session:
        flash('Please connect your Google Drive first.', 'error')
        return redirect(url_for('connect_drive'))

    try:
        notifications = get_user_notifications()
        
        service = get_drive_service()
        
        if not service:
            flash('Error connecting to Drive. Please reconnect.', 'error')
            return redirect(url_for('connect_drive'))
        
        results = service.files().list(
            q="trashed=false and mimeType='application/vnd.google-apps.folder'",
            pageSize=100,
            fields="files(id, name, mimeType, createdTime, webViewLink, iconLink)",
            orderBy="name"
        ).execute()

        folders = results.get('files', [])

        user_folders = db.user_navbars.find_one({'user_email': session['email']})
        saved_folder_ids = [item['ref_id'] for item in user_folders['items']] if user_folders and 'items' in user_folders else []

        for folder in folders:
            if 'webViewLink' not in folder:
                folder['webViewLink'] = f"https://drive.google.com/drive/folders/{folder['id']}"

        logger.info(f"✅ Retrieved {len(folders)} Drive folders")

        return render_template('drive_files.html',
                             folders=folders,
                             saved_folder_ids=saved_folder_ids,
                             total_folders=len(folders),
                             notifications=notifications)

    except Exception as e:
        logger.error(f"❌ Error fetching Drive folders: {str(e)}", exc_info=True)
        flash('Error connecting to Google Drive', 'error')
        return redirect(url_for('user_dashboard'))


@app.route('/connect_drive')
def connect_drive():
    """Connect Google Drive"""
    if 'role' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))

    try:
        # Clear any existing credentials
        session.pop('drive_creds', None)
        session.pop('drive_state', None)

        # Determine redirect URI
        if request.url_root.startswith('https://'):
            redirect_uri = 'https://office-academic.juooa.cloud/drive/callback'
        else:
            redirect_uri = 'http://localhost:5000/drive/callback'
        
        logger.info(f"🔍 Drive OAuth redirect URI: {redirect_uri}")

        # Create flow
        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=DRIVE_SCOPES,
            redirect_uri=redirect_uri
        )

        # Generate authorization URL
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )

        # Store state in session
        session['drive_state'] = state
        logger.info(f"✅ Starting Drive OAuth - State: {state[:10]}...")

        return redirect(auth_url)

    except Exception as e:
        logger.error(f"❌ Drive connection error: {e}", exc_info=True)
        flash('Error initiating Google Drive connection. Please try again.', 'error')
        return redirect(url_for('user_dashboard'))


@app.route('/drive/callback')
def drive_callback():
    """Google Drive OAuth callback"""
    try:
        logger.info(f"📥 Drive callback received")
        
        # Verify state
        if session.get('drive_state') != request.args.get('state'):
            logger.error("❌ State mismatch in Drive callback")
            flash('Authorization failed: State mismatch', 'error')
            return redirect(url_for('user_dashboard'))

        # Determine redirect URI
        if request.url_root.startswith('https://'):
            redirect_uri = 'https://office-academic.juooa.cloud/drive/callback'
        else:
            redirect_uri = 'http://localhost:5000/drive/callback'
        
        logger.info(f"🔍 Drive callback redirect URI: {redirect_uri}")

        # Create flow and fetch token
        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=DRIVE_SCOPES,
            redirect_uri=redirect_uri,
            state=session['drive_state']
        )

        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        # Store credentials in session
        session['drive_creds'] = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': DRIVE_SCOPES
        }

        # Clear state
        session.pop('drive_state', None)

        logger.info(f"✅ Google Drive connected successfully for {session.get('email')}")
        flash('✅ Google Drive connected successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    except Exception as e:
        logger.error(f"❌ Drive callback error: {e}", exc_info=True)
        flash('Error connecting to Google Drive. Please try again.', 'error')
        return redirect(url_for('user_dashboard'))


@app.route('/remove_folder_from_navbar/<folder_id>', methods=['POST'])
def remove_folder_from_navbar(folder_id):
    """Remove folder from user's navbar"""
    if 'email' not in session:
        flash('Please log in', 'error')
        return redirect(url_for('login'))
    
    try:
        db.user_navbars.update_one(
            {'user_email': session['email']},
            {'$pull': {'items': {'ref_id': folder_id}}}
        )
        flash('Folder removed from sidebar', 'success')
    except Exception as e:
        logger.error(f"Error removing folder: {e}")
        flash('Error removing folder', 'error')
    
    return redirect(request.referrer or url_for('user_dashboard'))
# ===================== FILE MANAGEMENT ROUTES =====================
@app.route('/edit_file/<file_id>', methods=['POST'])
def edit_file(file_id):
    """Edit file metadata"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        new_name = data.get('file_name', '')
        new_description = data.get('description', '')
        
        if not new_name:
            return jsonify({'error': 'File name is required'}), 400
        
        # Update file metadata
        result = db.user_files.update_one(
            {
                '_id': ObjectId(file_id),
                'user_email': session['email']
            },
            {
                '$set': {
                    'file_name': new_name,
                    'description': new_description,
                    'updated_at': get_indian_time()
                }
            }
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True, 'message': 'File updated successfully'})
        else:
            return jsonify({'error': 'File not found or unauthorized'}), 404
        
    except Exception as e:
        logger.error(f"Error editing file: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/delete_file/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete file"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Find file
        file_doc = db.user_files.find_one({
            '_id': ObjectId(file_id),
            'user_email': session['email']
        })
        
        if not file_doc:
            return jsonify({'error': 'File not found'}), 404
        
        # Delete physical file if local
        if file_doc.get('source') == 'local' and 'file_path' in file_doc and os.path.exists(file_doc['file_path']):
            os.remove(file_doc['file_path'])
        
        # Delete from Drive if it's a Drive file
        elif file_doc.get('source') == 'drive' and 'drive_file_id' in file_doc:
            service = get_drive_service()
            if service:
                delete_drive_file(service, file_doc['drive_file_id'])
        
        # Delete from database
        db.user_files.delete_one({'_id': ObjectId(file_id)})
        
        logger.info(f"✅ File deleted: {file_doc.get('file_name')} by {session['email']}")
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/download_file/<file_id>')
def download_file(file_id):
    """Download file"""
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in to download files', 'error')
        return redirect(url_for('login'))
    
    try:
        file_doc = db.user_files.find_one({
            '_id': ObjectId(file_id),
            'user_email': session['email']
        })
        
        if not file_doc:
            flash('File not found', 'error')
            return redirect(url_for('user_dashboard', tab='files'))
        
        if file_doc.get('source') != 'local':
            flash('This file is not locally stored', 'error')
            return redirect(url_for('user_dashboard', tab='files'))
        
        directory = os.path.dirname(file_doc['file_path'])
        filename = os.path.basename(file_doc['file_path'])
        
        return send_from_directory(directory, filename, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        flash('Error downloading file', 'error')
        return redirect(url_for('user_dashboard', tab='files'))
# Add these routes to your app.py file

# ===================== PUBLIC FILE API ROUTES =====================
@app.route('/api/public_files', methods=['GET'])
def get_public_files():
    """Get all public files"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized', 'success': False}), 401
    
    try:
        # Get files from MongoDB public_files collection
        public_files = list(db.public_files.find().sort('uploaded_at', -1))
        
        # Get Drive public files if connected
        drive_public_files = []
        if 'drive_creds' in session:
            try:
                service = get_drive_service()
                if service:
                    results = service.files().list(
                        q="trashed=false and visibility='anyoneWithLink'",
                        pageSize=100,
                        fields="files(id, name, mimeType, size, webViewLink, modifiedTime, owners)",
                        orderBy="modifiedTime desc"
                    ).execute()
                    
                    for file in results.get('files', []):
                        owner_email = file.get('owners', [{}])[0].get('emailAddress', '')
                        drive_public_files.append({
                            'id': file['id'],
                            'name': file['name'],
                            'web_link': file.get('webViewLink'),
                            'mime_type': file.get('mimeType'),
                            'uploader_email': owner_email,
                            'uploaded_at': file.get('modifiedTime'),
                            'source': 'drive'
                        })
            except Exception as e:
                logger.error(f"Error fetching Drive public files: {e}")
        
        # Combine both sources
        all_files = []
        
        # Add MongoDB files
        for file in public_files:
            all_files.append({
                'id': str(file['_id']),
                'name': file['name'],
                'web_link': file.get('web_link'),
                'uploader_email': file.get('uploader_email'),
                'uploaded_at': file['uploaded_at'].isoformat() if file.get('uploaded_at') else None,
                'source': 'mongodb'
            })
        
        # Add Drive files
        all_files.extend(drive_public_files)
        
        return jsonify({
            'success': True,
            'files': all_files
        })
        
    except Exception as e:
        logger.error(f"Error getting public files: {e}", exc_info=True)
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/make_file_private/<file_id>', methods=['POST'])
def api_make_file_private(file_id):
    """Make a Drive file private - API endpoint"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized', 'success': False}), 401
    
    try:
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Drive not connected', 'success': False}), 400
        
        # Check if user owns this file
        try:
            file_info = service.files().get(
                fileId=file_id,
                fields='id, name, owners'
            ).execute()
            
            owner_email = file_info.get('owners', [{}])[0].get('emailAddress')
            if owner_email != session['email']:
                return jsonify({'error': 'You do not own this file', 'success': False}), 403
        except Exception as e:
            logger.error(f"Error checking file ownership: {e}")
            return jsonify({'error': 'File not found or access denied', 'success': False}), 404
        
        # Make file private
        success = make_file_private(service, file_id)
        
        if success:
            # Remove from public_files collection
            db.public_files.delete_one({'file_id': file_id})
            
            # Update in user_files if exists
            db.user_files.update_one(
                {'drive_file_id': file_id, 'user_email': session['email']},
                {'$set': {'is_public': False, 'updated_at': get_indian_time()}}
            )
            
            logger.info(f"✅ File {file_id} made private by {session['email']}")
            return jsonify({'success': True, 'message': 'File made private successfully'})
        else:
            return jsonify({'error': 'Failed to make file private', 'success': False}), 400
        
    except Exception as e:
        logger.error(f"Error making file private: {e}", exc_info=True)
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/delete_public_file/<file_id>', methods=['DELETE'])
def api_delete_public_file(file_id):
    """Delete a public file - API endpoint"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized', 'success': False}), 401
    
    try:
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Drive not connected', 'success': False}), 400
        
        # Check if user owns this file
        try:
            file_info = service.files().get(
                fileId=file_id,
                fields='id, name, owners'
            ).execute()
            
            owner_email = file_info.get('owners', [{}])[0].get('emailAddress')
            if owner_email != session['email']:
                return jsonify({'error': 'You do not own this file', 'success': False}), 403
        except Exception as e:
            logger.error(f"Error checking file ownership: {e}")
            return jsonify({'error': 'File not found or access denied', 'success': False}), 404
        
        # Delete from Drive
        success = delete_drive_file(service, file_id)
        
        if success:
            # Remove from public_files collection
            db.public_files.delete_one({'file_id': file_id})
            
            # Remove from user_files
            db.user_files.delete_one({'drive_file_id': file_id, 'user_email': session['email']})
            
            logger.info(f"✅ Public file {file_id} deleted by {session['email']}")
            return jsonify({'success': True, 'message': 'Public file deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete file from Drive', 'success': False}), 400
        
    except Exception as e:
        logger.error(f"Error deleting public file: {e}", exc_info=True)
        return jsonify({'error': str(e), 'success': False}), 500
# ===================== PUBLIC FILE MANAGEMENT =====================
@app.route('/manage_public_files')
def manage_public_files():
    """Manage public files (make private, delete)"""
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
    
    try:
        # Get notifications
        notifications = get_user_notifications()
        
        # Get user's Drive files that are public
        public_files = []
        drive_connected = 'drive_creds' in session
        
        if drive_connected:
            try:
                service = get_drive_service()
                if service:
                    # Query for files with public permissions
                    results = service.files().list(
                        q="trashed=false and visibility='anyoneWithLink'",
                        pageSize=100,
                        fields="files(id, name, mimeType, size, webViewLink, modifiedTime, owners)",
                        orderBy="modifiedTime desc"
                    ).execute()
                    
                    files = results.get('files', [])
                    
                    for file in files:
                        # Check if user owns the file
                        if file.get('owners', [{}])[0].get('emailAddress') == session['email']:
                            public_files.append({
                                'file_id': file['id'],
                                'name': file['name'],
                                'web_link': file.get('webViewLink'),
                                'mime_type': file.get('mimeType'),
                                'size': file.get('size'),
                                'modified_time': file.get('modifiedTime'),
                                'is_owner': True
                            })
            except Exception as e:
                logger.error(f"❌ Error fetching public files: {e}")
                drive_connected = False
        
        return render_template(
            'manage_public_files.html',
            public_files=public_files,
            drive_connected=drive_connected,
            notifications=notifications
        )
    except Exception as e:
        logger.error(f"Error in manage_public_files: {e}")
        flash('Error loading public files', 'error')
        return render_template(
            'manage_public_files.html',
            public_files=[],
            drive_connected=False,
            notifications=[]
        )

@app.route('/make_file_private/<file_id>', methods=['POST'])
def make_file_private_api(file_id):
    """Make a Drive file private"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Drive not connected'}), 400
        
        # Check if user owns this file
        try:
            file_info = service.files().get(
                fileId=file_id,
                fields='id, name, owners'
            ).execute()
            
            if file_info.get('owners', [{}])[0].get('emailAddress') != session['email']:
                return jsonify({'error': 'You do not own this file'}), 403
        except Exception as e:
            return jsonify({'error': 'File not found or access denied'}), 404
        
        # Make file private in Drive
        success = make_file_private(service, file_id)
        
        if success:
            # Remove from public_files collection
            db.public_files.delete_one({'file_id': file_id})
            
            # Update in user_files if exists
            db.user_files.update_one(
                {'drive_file_id': file_id, 'user_email': session['email']},
                {'$set': {'is_public': False, 'updated_at': get_indian_time()}}
            )
            
            logger.info(f"✅ File {file_id} made private by {session['email']}")
            return jsonify({'success': True, 'message': 'File made private successfully'})
        else:
            return jsonify({'error': 'Failed to make file private'}), 400
        
    except Exception as e:
        logger.error(f"Error making file private: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/delete_public_file/<file_id>', methods=['DELETE'])
def delete_public_file(file_id):
    """Delete a public file from Drive"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Drive not connected'}), 400
        
        # Check if user owns this file
        try:
            file_info = service.files().get(
                fileId=file_id,
                fields='id, name, owners'
            ).execute()
            
            if file_info.get('owners', [{}])[0].get('emailAddress') != session['email']:
                return jsonify({'error': 'You do not own this file'}), 403
        except Exception as e:
            return jsonify({'error': 'File not found or access denied'}), 404
        
        # Delete from Drive
        success = delete_drive_file(service, file_id)
        
        if success:
            # Remove from public_files collection
            db.public_files.delete_one({'file_id': file_id})
            
            # Remove from user_files if exists
            db.user_files.delete_one({'drive_file_id': file_id, 'user_email': session['email']})
            
            logger.info(f"✅ Public file {file_id} deleted by {session['email']}")
            return jsonify({'success': True, 'message': 'Public file deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete file from Drive'}), 400
        
    except Exception as e:
        logger.error(f"Error deleting public file: {e}")
        return jsonify({'error': str(e)}), 400

# ===================== REMINDER MANAGEMENT =====================
@app.route('/my_reminders')
def my_reminders():
    """View all user reminders"""
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in to view reminders', 'error')
        return redirect(url_for('login'))
    
    try:
        # Get notifications
        notifications = get_user_notifications()
        
        user = db.users.find_one({'email': session['email']})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('user_dashboard'))
        
        # Get all reminders
        reminders = list(db.event_reminders.find({
            'user_id': user['_id']
        }).sort('reminder_datetime', 1))
        
        # Enrich with event data
        for reminder in reminders:
            event = db.events.find_one({'_id': reminder['event_id']})
            if event:
                reminder['event'] = event
        
        return render_template(
            'my_reminders.html',
            reminders=reminders,
            notifications=notifications,
            now=get_indian_time()
        )
        
    except Exception as e:
        logger.error(f"Error loading reminders: {e}")
        flash('Error loading reminders', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/delete_reminder/<reminder_id>', methods=['DELETE'])
def delete_reminder(reminder_id):
    """Delete a reminder"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = db.users.find_one({'email': session['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        result = db.event_reminders.delete_one({
            '_id': ObjectId(reminder_id),
            'user_id': user['_id']
        })
        
        if result.deleted_count > 0:
            return jsonify({
                'success': True,
                'message': 'Reminder deleted successfully'
            })
        else:
            return jsonify({'error': 'Reminder not found'}), 404
        
    except Exception as e:
        logger.error(f"Error deleting reminder: {e}")
        return jsonify({'error': str(e)}), 400

# ===================== SUBSCRIPTION ROUTES =====================
@app.route('/subscribe_to_event', methods=['POST'])
def subscribe_to_event():
    """Subscribe to event updates"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        event_id = data.get('event_id')
        
        if not event_id:
            return jsonify({'error': 'Event ID is required'}), 400
        
        # Get event
        event = db.events.find_one({'_id': ObjectId(event_id)})
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        # Get user
        user = db.users.find_one({'email': session['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if already subscribed
        existing = db.event_subscriptions.find_one({
            'user_id': user['_id'],
            'event_id': event['_id']
        })
        
        if existing:
            return jsonify({
                'success': True,
                'message': 'Already subscribed to this event'
            })
        
        # Create subscription
        db.event_subscriptions.insert_one({
            'user_id': user['_id'],
            'event_id': event['_id'],
            'event_name': event['event_name'],
            'subscribed_at': get_indian_time()
        })
        
        logger.info(f"✅ User {session['email']} subscribed to event: {event['event_name']}")
        
        return jsonify({
            'success': True,
            'message': 'Successfully subscribed to event updates'
        })
        
    except Exception as e:
        logger.error(f"Error subscribing to event: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400

# ===================== DRIVE OPERATIONS =====================
@app.route('/drive/upload', methods=['POST'])
def drive_upload():
    if 'drive_creds' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        file = request.files.get('file')
        folder_id = request.form.get('folder_id', 'root')
        make_public = request.form.get('make_public', 'false') == 'true'
        
        if not file:
            return jsonify({'error': 'No file provided'}), 400
        
        service = get_drive_service()
        
        if not service:
            return jsonify({'error': 'Drive service unavailable'}), 500
        
        file_metadata = {
            'name': secure_filename(file.filename),
            'parents': [folder_id]
        }
        
        file_content = file.read()
        media = MediaIoBaseUpload(
            BytesIO(file_content),
            mimetype=file.mimetype or 'application/octet-stream',
            resumable=True
        )
        
        file_obj = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, webViewLink'
        ).execute()
        
        result = {
            'file_id': file_obj['id'],
            'file_name': file_obj['name'],
            'web_link': file_obj.get('webViewLink', f"https://drive.google.com/file/d/{file_obj['id']}/view")
        }
        
        if make_public:
            if make_file_public(service, file_obj['id']):
                result['public_link'] = f"https://drive.google.com/file/d/{file_obj['id']}/view"
                
                # Store in public_files collection
                db.public_files.insert_one({
                    'file_id': file_obj['id'],
                    'name': file_obj['name'],
                    'uploader_email': session['email'],
                    'web_link': result['public_link'],
                    'uploaded_at': get_indian_time()
                })
        
        # Save reference in user_files
        db.user_files.insert_one({
            'user_email': session['email'],
            'file_name': file_obj['name'],
            'original_filename': file_obj['name'],
            'drive_file_id': file_obj['id'],
            'drive_link': result['web_link'],
            'is_public': make_public,
            'source': 'drive',
            'uploaded_at': get_indian_time()
        })
        
        logger.info(f"✅ File uploaded to Drive: {file_obj['name']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error uploading to Drive: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400

# ===================== MAIN ROUTES =====================
@app.route('/')
def home():
    try:
        records = list(db.ugc_data.find().sort('uploaded_at', -1).limit(50))
        monthly_records = list(db.monthly_engagement.find().sort('uploaded_at', -1).limit(50))
        newsletter_records = list(db.newsletters.find().sort('uploaded_at', -1).limit(50))
        
        # Get current and upcoming events
        today = get_indian_time().date()
        today_str = today.strftime('%Y-%m-%d')
        
        events = list(db.events.find({
            'event_date': {'$gte': today_str}
        }).sort('event_date', 1).limit(100))
        
        public_files = list(db.public_files.find().sort('uploaded_at', -1).limit(20))
        
        user_logged_in = 'email' in session
        user_email = session.get('email', '')
        user_role = session.get('role', '')
        
        return render_template(
            'home.html',
            records=records,
            monthly_records=monthly_records,
            newsletter_records=newsletter_records,
            events=events,
            public_files=public_files,
            today=today,
            user_logged_in=user_logged_in,
            user_email=user_email,
            user_role=user_role
        )
    except Exception as e:
        logger.error(f"Error in home route: {e}", exc_info=True)
        flash('Error loading home page', 'error')
        return render_template('home.html', records=[], monthly_records=[], newsletter_records=[], 
                             events=[], public_files=[], today=get_indian_time().date(),
                             user_logged_in=False, user_email='', user_role='')

@app.route('/jainevents')
def jainevents():
    events = list(db.events.find().sort('event_date', 1))
    return render_template('jainevents.html', events=events)

# ===================== ADMIN ROUTES (Simplified) =====================
@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    # Admin dashboard logic here
    return render_template('admin_dashboard.html')

# ===================== RUN APP =====================
# ===================== SCHEDULER =====================

def start_scheduler():
    scheduler = BackgroundScheduler(timezone=IST)

    @scheduler.scheduled_job('interval', minutes=1, id='reminder_check')
    def scheduled_send_event_reminders():
        with app.app_context():
            logger.info(
                f"[SCHEDULER] Running reminder check at "
                f"{get_indian_time().strftime('%Y-%m-%d %H:%M:%S')} IST"
            )
            send_event_reminders()

    @scheduler.scheduled_job('cron', hour=7, minute=0, id='daily_digest')
    def scheduled_send_daily_event_emails():
        with app.app_context():
            logger.info(
                f"[SCHEDULER] Running daily digest at "
                f"{get_indian_time().strftime('%Y-%m-%d %H:%M:%S')} IST"
            )
            send_daily_event_emails()

    scheduler.start()
    logger.info("✅ Scheduler started (IST)")


# ===================== RUN APP =====================

#if __name__ == '__main__':
 #   start_scheduler()
  #  port = int(os.environ.get("PORT", 5000))
   # app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)
