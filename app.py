#TESTING
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
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_proto=1,
    x_host=1
)

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
                    'message': f"Set for {reminder['reminder_datetime'].strftime('%d %b at %I:%M %p')}",
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
                'link': url_for('my_files')
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
                'link': url_for('user_dashboard')
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
    """Send event reminders based on user preferences - USES INDIAN TIME"""
    try:
        now = get_indian_time()
        
        reminders = list(db.event_reminders.find({
            'sent': False
        }))
        
        logger.info(f"[REMINDER CHECK] Current IST time: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"[REMINDER CHECK] Found {len(reminders)} pending reminders")
        
        for reminder in reminders:
            try:
                reminder_dt = reminder.get('reminder_datetime')
                
                if isinstance(reminder_dt, str):
                    reminder_dt = datetime.strptime(reminder_dt, '%Y-%m-%d %H:%M:%S')
                
                if reminder_dt.tzinfo is None:
                    reminder_dt = IST.localize(reminder_dt)
                else:
                    reminder_dt = reminder_dt.astimezone(IST)
                
                logger.info(f"[REMINDER] Checking reminder for {reminder_dt.strftime('%Y-%m-%d %H:%M:%S')} IST")
                
                if reminder_dt <= now:
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
                else:
                    time_diff = (reminder_dt - now).total_seconds() / 60
                    logger.info(f"[REMINDER PENDING] Will send in {time_diff:.1f} minutes")
                
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

# ===================== MAIN PAGES =====================
@app.route('/')
def home():
    try:
        records = list(db.ugc_data.find().sort('uploaded_at', -1).limit(50))
        monthly_records = list(db.monthly_engagement.find().sort('uploaded_at', -1).limit(50))
        newsletter_records = list(db.newsletters.find().sort('uploaded_at', -1).limit(50))
        
        # Get current and upcoming events
        today = datetime.now().date()
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
                             events=[], public_files=[], today=datetime.now().date(),
                             user_logged_in=False, user_email='', user_role='')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/monthlyengagement')
def monthlyengagement():
    events = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    return render_template('monthly.html', monthly_records=events)

@app.route('/ugc')
def ugc():
    return render_template('ugc.html')

@app.route('/base_user.html')
def base_user():
    """Base user template - should only be extended, but provide context if accessed directly"""
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
    
    try:
        # Get notifications
        notifications = get_user_notifications()
        
        # Get user navbar
        user_navbar = get_user_navbar(session['email'])
        
        return render_template(
            'base_user.html', 
            notifications=notifications,
            user_navbar=user_navbar
        )
    except Exception as e:
        logger.error(f"Error in base_user route: {e}")
        return render_template('base_user.html', notifications=[], user_navbar=[])

@app.route('/jainevents')
def jainevents():
    events = list(db.events.find().sort('event_date', 1))
    return render_template('jainevents.html', events=events)

@app.route('/subscribe', methods=['POST'])
def subscribe():
    try:
        data = request.get_json()
        email = data.get('email')
        school = data.get('school', '')

        if not email:
            return jsonify({"message": "Email is required"}), 400

        db.subscribers.update_one(
            {"email": email},
            {"$set": {"school": school, "subscribed_at": datetime.now()}},
            upsert=True
        )

        return jsonify({"message": "Subscribed successfully"}), 200
    except Exception as e:
        logger.error(f"Error in subscribe: {e}")
        return jsonify({"message": "Subscription failed"}), 500

# ===================== DASHBOARD ROUTES =====================
@app.route('/user')
@app.route('/user_dashboard')
def user_dashboard():
    """User dashboard with tabs and notifications"""
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
        
        # Get today's date
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        next_week = today + timedelta(days=7)
        today_str = today.strftime('%Y-%m-%d')
        next_week_str = next_week.strftime('%Y-%m-%d')
        
        # Get today's events with proper query
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
        
        # Get drive stats
        drive_stats = {'total_files': 0, 'recent_uploads': []}
        drive_connected = 'drive_creds' in session
        if drive_connected:
            try:
                drive_stats = get_drive_stats()
            except Exception as e:
                logger.error(f"❌ Error getting drive stats: {e}")
                drive_connected = False
        
        # Get user's files from MongoDB
        user_files = list(db.user_files.find({
            'user_email': session['email']
        }).sort('uploaded_at', -1).limit(20))
        
        # Get public files
        public_files = list(db.public_files.find().sort('uploaded_at', -1).limit(20))
        
        # Get user navbar
        user_navbar = get_user_navbar(session['email'])
        
        # Gmail connection status
        gmail_connected = 'gmail_creds' in session
        
        return render_template(
            'user_dashboard.html',
            today_events=today_events,
            upcoming_events=upcoming_events,
            user_reminders=user_reminders,
            drive_stats=drive_stats,
            drive_connected=drive_connected,
            gmail_connected=gmail_connected,
            public_files=public_files,
            user_navbar=user_navbar,
            user_files=user_files,
            notifications=notifications
        )
    except Exception as e:
        logger.error(f"❌ Error in user_dashboard: {str(e)}", exc_info=True)
        flash('Error loading dashboard. Please try again.', 'error')
        
        return render_template(
            'user_dashboard.html',
            today_events=[],
            upcoming_events=[],
            user_reminders=[],
            drive_stats={'total_files': 0, 'recent_uploads': []},
            drive_connected=False,
            gmail_connected=False,
            public_files=[],
            user_navbar=[],
            user_files=[],
            notifications=[]
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
    """Set a reminder for an event - ALLOWS TODAY + SENDS IMMEDIATE CONFIRMATION EMAIL"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized', 'success': False}), 401
    
    try:
        data = request.get_json()
        event_id = data.get('event_id')
        reminder_date = data.get('reminder_date')
        reminder_time = data.get('reminder_time')
        
        # Validation
        if not all([event_id, reminder_date, reminder_time]):
            return jsonify({'error': 'Missing required fields: event_id, reminder_date, and reminder_time are required', 'success': False}), 400
        
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
        
        # Handle different date formats
        try:
            # Try parsing as YYYY-MM-DD first
            try:
                reminder_datetime_str = f"{reminder_date} {reminder_time}:00"
                reminder_datetime = datetime.strptime(reminder_datetime_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                # Try parsing as DD-MM-YYYY
                try:
                    day, month, year = reminder_date.split('-')
                    if len(year) == 4 and len(month) == 2 and len(day) == 2:
                        formatted_date = f"{year}-{month}-{day}"
                        reminder_datetime_str = f"{formatted_date} {reminder_time}:00"
                        reminder_datetime = datetime.strptime(reminder_datetime_str, '%Y-%m-%d %H:%M:%S')
                    else:
                        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD or DD-MM-YYYY', 'success': False}), 400
                except ValueError:
                    return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD or DD-MM-YYYY', 'success': False}), 400
            
            # Localize to IST
            reminder_datetime = IST.localize(reminder_datetime)
        except Exception as e:
            return jsonify({'error': f'Invalid date/time format: {str(e)}', 'success': False}), 400
        
        # Allow reminders from current time onwards (including today)
        now = get_indian_time()
        if reminder_datetime <= now:
            return jsonify({'error': 'Reminder time must be in the future (not in the past)', 'success': False}), 400
        
        # Check if reminder is before event date
        try:
            event_date_str = event.get('event_date')
            if event_date_str:
                event_date = datetime.strptime(event_date_str, '%Y-%m-%d')
                event_date = IST.localize(event_date.replace(hour=23, minute=59, second=59))
                
                if reminder_datetime > event_date:
                    return jsonify({'error': 'Reminder cannot be set after the event date', 'success': False}), 400
        except:
            pass  # Skip event date validation if there's an error
        
        # Check if reminder already exists
        existing = db.event_reminders.find_one({
            'user_id': user['_id'],
            'event_id': event['_id']
        })
        
        if existing:
            # Update existing reminder
            db.event_reminders.update_one(
                {'_id': existing['_id']},
                {
                    '$set': {
                        'reminder_datetime': reminder_datetime,
                        'sent': False,
                        'updated_at': get_indian_time()
                    }
                }
            )
            message = 'Reminder updated successfully'
            action = 'updated'
        else:
            # Create new reminder
            db.event_reminders.insert_one({
                'user_id': user['_id'],
                'event_id': event['_id'],
                'reminder_datetime': reminder_datetime,
                'sent': False,
                'created_at': get_indian_time()
            })
            message = 'Reminder set successfully'
            action = 'set'
        
        logger.info(f"✅ Reminder {action} for user {session['email']} - Event: {event['event_name']} at {reminder_datetime.strftime('%Y-%m-%d %H:%M:%S')} IST")
        
        # Send immediate confirmation email
        try:
            msg = Message(
                subject=f"✅ Reminder {action.capitalize()}: {event['event_name']}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[user['email']]
            )
            
            msg.html = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9fafb; border-radius: 10px;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">✅ Reminder {action.capitalize()}</h1>
                </div>
                
                <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                    <h2 style="color: #1f2937; margin-top: 0; font-size: 24px;">{event['event_name']}</h2>
                    
                    <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <p style="margin: 10px 0; color: #374151;"><strong>📅 Event Date:</strong> {event['event_date']}</p>
                        <p style="margin: 10px 0; color: #374151;"><strong>⏰ Event Time:</strong> {event.get('event_time', 'All Day')}</p>
                        <p style="margin: 10px 0; color: #374151;"><strong>📍 Venue:</strong> {event['venue']}</p>
                        <p style="margin: 10px 0; color: #374151;"><strong>🏢 Department:</strong> {event.get('department', 'N/A')}</p>
                        <p style="margin: 10px 0; color: #374151;"><strong>🏫 School:</strong> {event.get('school', 'N/A')}</p>
                    </div>
                    
                    <div style="margin: 20px 0; padding: 15px; background: #dcfce7; border-left: 4px solid #22c55e; border-radius: 4px;">
                        <p style="margin: 0; color: #166534;"><strong>🔔 Your Reminder is Set For:</strong></p>
                        <p style="margin: 10px 0 0 0; color: #166534; font-size: 18px; font-weight: bold;">
                            {reminder_datetime.strftime('%d %B %Y at %I:%M %p')} IST
                        </p>
                    </div>
                    
                    <div style="margin: 20px 0; padding: 15px; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 4px;">
                        <p style="margin: 0; color: #1e40af;"><strong>📝 Description:</strong></p>
                        <p style="margin: 10px 0 0 0; color: #1e40af;">{event.get('description', 'No description provided')}</p>
                    </div>
                    
                    <p style="color: #6b7280; font-size: 14px; margin-top: 20px;">
                        We will send you a reminder email at the scheduled time. Make sure to keep this event in your calendar!
                    </p>
                    
                    <div style="text-align: center; margin-top: 30px;">
                        <p style="color: #9ca3af; font-size: 12px; margin: 5px 0;">Confirmation sent at: {now.strftime('%Y-%m-%d %I:%M %p')} IST</p>
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 20px; padding: 20px;">
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                    <p style="color: #6b7280; font-size: 12px; margin: 5px 0;">
                        Jain University Portal - Office of Academics
                    </p>
                    <p style="color: #9ca3af; font-size: 11px; margin: 5px 0;">
                        This is an automated confirmation. You will receive another reminder at the scheduled time.
                    </p>
                </div>
            </div>
            """
            
            mail.send(msg)
            logger.info(f"✅ Confirmation email sent to {user['email']}")
        except Exception as email_error:
            logger.error(f"❌ Error sending confirmation email: {email_error}")
            # Don't fail the request if email fails
        
        return jsonify({
            'success': True,
            'message': f"{message}! A confirmation email has been sent to your inbox."
        })
        
    except Exception as e:
        logger.error(f"❌ Error setting reminder: {e}", exc_info=True)
        return jsonify({'error': f'Server error: {str(e)}', 'success': False}), 400

# ===================== FILE MANAGEMENT ROUTES =====================
@app.route('/my_files')
def my_files():
    """User's file management page"""
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in to access your files', 'error')
        return redirect(url_for('login'))
    
    try:
        # Get notifications
        notifications = get_user_notifications()
        
        # Get user's local files from MongoDB
        local_files = list(db.user_files.find({
            'user_email': session['email']
        }).sort('uploaded_at', -1))
        
        # Get user's Drive files if connected
        drive_files = []
        drive_connected = 'drive_creds' in session
        if drive_connected:
            try:
                service = get_drive_service()
                if service:
                    results = service.files().list(
                        q="trashed=false",
                        pageSize=100,
                        orderBy="modifiedTime desc",
                        fields="files(id, name, mimeType, size, createdTime, modifiedTime, webViewLink)"
                    ).execute()
                    drive_files = results.get('files', [])
                    logger.info(f"✅ Retrieved {len(drive_files)} Drive files")
            except Exception as e:
                logger.error(f"❌ Error fetching drive files: {e}")
                drive_connected = False
        
        return render_template(
            'my_files.html',
            local_files=local_files,
            drive_files=drive_files,
            drive_connected=drive_connected,
            notifications=notifications
        )
    except Exception as e:
        logger.error(f"Error in my_files: {e}")
        flash('Error loading files', 'error')
        return render_template(
            'my_files.html',
            local_files=[],
            drive_files=[],
            drive_connected=False,
            notifications=[]
        )

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
        
        # Also delete from public_files if it exists there
        db.public_files.delete_one({'file_id': file_doc.get('drive_file_id')})
        
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
            return redirect(url_for('my_files'))
        
        if file_doc.get('source') != 'local':
            flash('This file is not locally stored', 'error')
            return redirect(url_for('my_files'))
        
        directory = os.path.dirname(file_doc['file_path'])
        filename = os.path.basename(file_doc['file_path'])
        
        return send_from_directory(directory, filename, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        flash('Error downloading file', 'error')
        return redirect(url_for('my_files'))

@app.route('/link_drive_file', methods=['POST'])
def link_drive_file():
    """Link a Google Drive file to user's MongoDB collection"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        drive_file_id = data.get('drive_file_id')
        file_name = data.get('file_name', '')
        description = data.get('description', '')
        
        if not drive_file_id:
            return jsonify({'error': 'Drive file ID is required'}), 400
        
        # Get file metadata from Drive
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Drive not connected'}), 400
        
        file_metadata = service.files().get(
            fileId=drive_file_id,
            fields='id, name, mimeType, size, webViewLink'
        ).execute()
        
        # Store reference in MongoDB
        file_doc = {
            'user_email': session['email'],
            'file_name': file_name or file_metadata['name'],
            'original_filename': file_metadata['name'],
            'description': description,
            'drive_file_id': drive_file_id,
            'drive_link': file_metadata.get('webViewLink'),
            'file_type': file_metadata.get('mimeType', ''),
            'source': 'drive',
            'uploaded_at': get_indian_time()
        }
        
        result = db.user_files.insert_one(file_doc)
        
        return jsonify({
            'success': True,
            'message': 'Drive file linked successfully',
            'file_id': str(result.inserted_id)
        })
        
    except Exception as e:
        logger.error(f"Error linking drive file: {e}")
        return jsonify({'error': str(e)}), 400

# ===================== PUBLIC FILE MANAGEMENT =====================
@app.route('/manage_public_files')
def manage_public_files():
    """Manage public files (make private, delete) - USER ONLY"""
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
                    # Get files from public_files collection
                    db_public_files = list(db.public_files.find({
                        'uploader_email': session['email']
                    }).sort('uploaded_at', -1))
                    
                    # Enrich with Drive metadata
                    for file in db_public_files:
                        try:
                            drive_metadata = service.files().get(
                                fileId=file['file_id'],
                                fields='id, name, mimeType, size, webViewLink'
                            ).execute()
                            
                            file['drive_metadata'] = drive_metadata
                            public_files.append(file)
                        except Exception as e:
                            logger.warning(f"Could not get Drive metadata for {file['file_id']}: {e}")
                            file['drive_metadata'] = {'name': file.get('name', 'Unknown')}
                            public_files.append(file)
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
        file_doc = db.public_files.find_one({
            'file_id': file_id,
            'uploader_email': session['email']
        })
        
        if not file_doc:
            return jsonify({'error': 'File not found or unauthorized'}), 404
        
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
        file_doc = db.public_files.find_one({
            'file_id': file_id,
            'uploader_email': session['email']
        })
        
        if not file_doc:
            return jsonify({'error': 'File not found or unauthorized'}), 404
        
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

# ===================== NOTIFICATIONS API =====================
@app.route('/api/notifications')
def api_notifications():
    """Get user notifications as JSON"""
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        notifications = get_user_notifications()
        return jsonify({
            'success': True,
            'notifications': notifications,
            'count': len(notifications)
        })
    except Exception as e:
        logger.error(f"Error getting notifications: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/mark_notification_read/<notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    """Mark notification as read"""
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error marking notification as read: {e}")
        return jsonify({'error': str(e)}), 400

# ===================== GOOGLE OAUTH ROUTES =====================
@app.route('/connect-drive')
def connect_drive():
    if 'role' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))

    try:
        # Clear any existing credentials
        session.pop('drive_creds', None)
        session.pop('drive_state', None)

        # Determine redirect URI based on environment
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

@app.route('/connect-gmail')
def connect_gmail():
    if 'role' not in session:
        return redirect(url_for('login'))
    
    try:
        session.pop('gmail_creds', None)
        session.pop('gmail_state', None)
        
        if request.url_root.startswith('https://'):
            redirect_uri = 'https://office-academic.juooa.cloud/gmail/callback'
        else:
            redirect_uri = 'http://localhost:5000/gmail/callback'
        
        logger.info(f"🔍 Gmail OAuth redirect URI: {redirect_uri}")
        
        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=GMAIL_SCOPES,
            redirect_uri=redirect_uri
        )
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='false',
            prompt='consent'
        )
        session['gmail_state'] = state
        logger.info("✅ Starting Gmail OAuth")
        return redirect(auth_url)
    
    except Exception as e:
        logger.error(f"❌ Gmail connection error: {e}", exc_info=True)
        flash('Error initiating Gmail connection', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/gmail/callback')
def gmail_callback():
    try:
        logger.info(f"📥 Gmail callback received")
        
        if session.get('gmail_state') != request.args.get('state'):
            logger.error("❌ State mismatch in Gmail callback")
            flash('State mismatch. Authorization failed.', 'error')
            return redirect(url_for('user_dashboard'))

        if request.url_root.startswith('https://'):
            redirect_uri = 'https://office-academic.juooa.cloud/gmail/callback'
        else:
            redirect_uri = 'http://localhost:5000/gmail/callback'
        
        logger.info(f"🔍 Gmail callback redirect URI: {redirect_uri}")

        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=GMAIL_SCOPES,
            redirect_uri=redirect_uri
        )
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        session['gmail_creds'] = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': GMAIL_SCOPES
        }
        
        session.pop('gmail_state', None)

        logger.info("✅ Gmail connected successfully")
        flash('✅ Gmail connected successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    except Exception as e:
        logger.error(f"❌ Gmail callback error: {e}", exc_info=True)
        flash('Error connecting to Gmail', 'error')
        return redirect(url_for('user_dashboard'))

# ===================== DRIVE OPERATIONS =====================
@app.route('/drive/files')
def drive_files():
    if 'drive_creds' not in session:
        flash('Please connect your Google Drive first.', 'error')
        return redirect(url_for('connect_drive'))

    try:
        # Get notifications
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

@app.route('/api/drive/folder/<folder_id>')
def get_drive_folder_contents(folder_id):
    if 'drive_creds' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        service = get_drive_service()
        
        if not service:
            return jsonify({'error': 'Drive service unavailable'}), 500
        
        results = service.files().list(
            q=f"'{folder_id}' in parents and trashed=false",
            pageSize=100,
            fields="files(id, name, mimeType, size, createdTime, webViewLink)"
        ).execute()

        files = results.get('files', [])
        return jsonify(files)

    except Exception as e:
        logger.error(f"Error fetching folder contents: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400

@app.route('/api/drive/search')
def search_drive_files():
    if 'drive_creds' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify([])

        service = get_drive_service()
        
        if not service:
            return jsonify({'error': 'Drive service unavailable'}), 500
        
        results = service.files().list(
            q=f"name contains '{query}' and trashed=false",
            pageSize=20,
            fields="files(id, name, mimeType, webViewLink, iconLink)"
        ).execute()

        files = results.get('files', [])
        return jsonify(files)

    except Exception as e:
        logger.error(f"Error searching Drive: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400

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
                
                db.public_files.insert_one({
                    'file_id': file_obj['id'],
                    'name': file_obj['name'],
                    'uploader_email': session['email'],
                    'web_link': result['public_link'],
                    'uploaded_at': get_indian_time()
                })
        
        # Also save reference in user_files
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

@app.route('/drive/create-folder', methods=['POST'])
def drive_create_folder():
    if 'drive_creds' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        folder_name = data.get('folder_name')
        parent_id = data.get('parent_id', 'root')
        
        if not folder_name:
            return jsonify({'error': 'Folder name required'}), 400
        
        service = get_drive_service()
        
        if not service:
            return jsonify({'error': 'Drive service unavailable'}), 500
        
        file_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id]
        }
        
        folder = service.files().create(
            body=file_metadata,
            fields='id, name'
        ).execute()
        
        logger.info(f"✅ Folder created in Drive: {folder_name}")
        
        return jsonify({
            'folder_id': folder['id'],
            'folder_name': folder['name']
        })
        
    except Exception as e:
        logger.error(f"Error creating folder: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400

# ===================== EVENT REMINDER & SUBSCRIPTION ROUTES =====================
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

@app.route('/unsubscribe_from_event/<event_id>', methods=['DELETE'])
def unsubscribe_from_event(event_id):
    """Unsubscribe from event updates"""
    if 'role' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = db.users.find_one({'email': session['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        result = db.event_subscriptions.delete_one({
            'user_id': user['_id'],
            'event_id': ObjectId(event_id)
        })
        
        if result.deleted_count > 0:
            return jsonify({
                'success': True,
                'message': 'Successfully unsubscribed'
            })
        else:
            return jsonify({'error': 'Subscription not found'}), 404
        
    except Exception as e:
        logger.error(f"Error unsubscribing: {e}")
        return jsonify({'error': str(e)}), 400

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
            notifications=notifications
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

# ===================== USER PREFERENCES ROUTES =====================
@app.route('/user_preferences', methods=['GET', 'POST'])
def user_preferences():
    """Manage user preferences"""
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in to access preferences', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            db.user_preferences.update_one(
                {'email': session['email']},
                {
                    '$set': {
                        'email_notifications': data.get('email_notifications', True),
                        'reminder_notifications': data.get('reminder_notifications', True),
                        'event_updates': data.get('event_updates', True),
                        'preferred_schools': data.get('preferred_schools', []),
                        'updated_at': get_indian_time()
                    }
                },
                upsert=True
            )
            
            return jsonify({
                'success': True,
                'message': 'Preferences updated successfully'
            })
            
        except Exception as e:
            logger.error(f"Error updating preferences: {e}")
            return jsonify({'error': str(e)}), 400
    
    # GET request
    try:
        # Get notifications
        notifications = get_user_notifications()
        
        preferences = db.user_preferences.find_one({'email': session['email']})
        if not preferences:
            preferences = {
                'email_notifications': True,
                'reminder_notifications': True,
                'event_updates': True,
                'preferred_schools': []
            }
        
        return render_template(
            'user_preferences.html',
            preferences=preferences,
            notifications=notifications
        )
        
    except Exception as e:
        logger.error(f"Error loading preferences: {e}")
        flash('Error loading preferences', 'error')
        return redirect(url_for('user_dashboard'))

# ===================== ADMIN USER CONTROLS =====================
@app.route('/admin/users')
def view_users():
    if session.get('role') != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    try:
        users = list(db.users.find())
        return render_template('admin_view_users.html', users=users)
    except Exception as e:
        logger.error(f"Error viewing users: {e}")
        flash('Error loading users', 'error')
        return render_template('admin_view_users.html', users=[])

@app.route('/update_user/<user_id>', methods=['POST'])
def update_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        email = request.form['email']
        role = request.form['role']

        db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'email': email, 'role': role}})
        flash('✅ User updated successfully.', 'success')
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        flash('Error updating user', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<user_id>')
def delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        db.users.delete_one({'_id': ObjectId(user_id)})
        flash('✅ User deleted successfully.', 'success')
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        flash('Error deleting user', 'error')
    
    return redirect(url_for('admin_dashboard'))

# ===================== UGC UPLOAD =====================
@app.route('/edit_ugc', methods=['GET', 'POST'])
def edit_ugc():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            text_data = request.form.get('text_data')
            external_link = request.form.get('external_link')
            selected_categories = request.form.getlist('categories')
            files = request.files.getlist('files')

            uploaded_files = []
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    uploaded_files.append(filename)

            db.ugc_data.insert_one({
                "admin_email": session['email'],
                "uploaded_at": get_indian_time(),
                "categories": selected_categories,
                "text_data": text_data,
                "external_link": external_link,
                "files": uploaded_files
            })

            flash('✅ UGC/University Notice data uploaded successfully.', 'success')
            return redirect(url_for('edit_ugc'))
        except Exception as e:
            logger.error(f"Error in edit_ugc POST: {e}")
            flash('Error uploading data', 'error')

    try:
        records = list(db.ugc_data.find().sort('uploaded_at', -1))
        return render_template('edit_ugc.html', records=records)
    except Exception as e:
        logger.error(f"Error in edit_ugc GET: {e}")
        return render_template('edit_ugc.html', records=[])

@app.route('/edit_ugc_record/<record_id>', methods=['GET', 'POST'])
def edit_ugc_record(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        record = db.ugc_data.find_one({'_id': ObjectId(record_id)})
        
        if not record:
            flash('Record not found', 'error')
            return redirect(url_for('edit_ugc'))

        if request.method == 'POST':
            text_data = request.form.get('text_data')
            external_link = request.form.get('external_link')
            selected_categories = request.form.getlist('categories')
            files = request.files.getlist('files')

            updated_files = record.get('files', [])

            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    updated_files.append(filename)

            db.ugc_data.update_one(
                {'_id': ObjectId(record_id)},
                {'$set': {
                    'text_data': text_data,
                    'external_link': external_link,
                    'categories': selected_categories,
                    'files': updated_files
                }}
            )

            flash('✅ UGC/University Notice data updated successfully.', 'success')
            return redirect(url_for('edit_ugc'))

        return render_template('edit_ugc_record.html', record=record)
    except Exception as e:
        logger.error(f"Error in edit_ugc_record: {e}")
        flash('Error processing request', 'error')
        return redirect(url_for('edit_ugc'))

@app.route('/delete_ugc/<record_id>', methods=['GET'])
def delete_ugc(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        db.ugc_data.delete_one({'_id': ObjectId(record_id)})
        flash('✅ UGC record deleted successfully.', 'success')
    except Exception as e:
        logger.error(f"Error deleting UGC: {e}")
        flash('Error deleting record', 'error')
    
    return redirect(url_for('edit_ugc'))

# ===================== MONTHLY ENGAGEMENT =====================
@app.route('/edit_monthly', methods=['GET', 'POST'])
def edit_monthly():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            heading = request.form.get('heading', '').strip()
            description = request.form.get('description', '').strip()
            school = request.form.get('school', '')
            department = request.form.get('department', '')
            tags = request.form.getlist('tags')

            image_file = request.files.get('image_file')
            pdf_file = request.files.get('pdf_file')

            uploaded_files = []

            for file in [image_file, pdf_file]:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    uploaded_files.append(filename)

            db.monthly_engagement.insert_one({
                "admin_email": session.get('email'),
                "uploaded_at": get_indian_time(),
                "heading": heading,
                "description": description,
                "school": school,
                "department": department,
                "tags": tags,
                "files": uploaded_files
            })

            flash('✅ Monthly engagement data uploaded successfully.', 'success')
            return redirect(url_for('edit_monthly'))
        except Exception as e:
            logger.error(f"Error in edit_monthly POST: {e}")
            flash('Error uploading data', 'error')

    try:
        records = list(db.monthly_engagement.find().sort('uploaded_at', -1))
        return render_template('edit_monthly.html', records=records)
    except Exception as e:
        logger.error(f"Error in edit_monthly GET: {e}")
        return render_template('edit_monthly.html', records=[])

@app.route('/edit_record/<record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        collection = db.monthly_engagement
        record = collection.find_one({'_id': ObjectId(record_id)})
        
        if not record:
            flash('Record not found', 'error')
            return redirect(url_for('edit_monthly'))

        if request.method == 'POST':
            updated_data = {}

            if 'heading' in request.form:
                updated_data['heading'] = request.form.get('heading', '').strip()
            if 'description' in request.form:
                updated_data['description'] = request.form.get('description', '').strip()
            if 'school' in request.form:
                updated_data['school'] = request.form.get('school', '')
            if 'department' in request.form:
                updated_data['department'] = request.form.get('department', '')
            if 'tags' in request.form:
                updated_data['tags'] = request.form.getlist('tags')

            if updated_data:
                collection.update_one({'_id': ObjectId(record_id)}, {'$set': updated_data})
                flash('✅ Record updated successfully.', 'success')

            return redirect(url_for('edit_monthly'))

        return render_template('edit_record.html', record=record)
    except Exception as e:
        logger.error(f"Error in edit_record: {e}")
        flash('Error processing request', 'error')
        return redirect(url_for('edit_monthly'))

@app.route('/delete_record/<record_id>', methods=['POST'])
def delete_record(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        collection = db.monthly_engagement
        record = collection.find_one({'_id': ObjectId(record_id)})

        if record and 'files' in record:
            for filename in record['files']:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    os.remove(file_path)

        collection.delete_one({'_id': ObjectId(record_id)})
        flash('✅ Record deleted successfully.', 'success')
    except Exception as e:
        logger.error(f"Error deleting record: {e}")
        flash('Error deleting record', 'error')
    
    return redirect(url_for('edit_monthly'))

# ===================== NEWSLETTER =====================
@app.route('/usernewsletters')
def usernewsletters():
    try:
        newsletters = list(db.newsletters.find().sort('uploaded_at', -1))
        return render_template('user_newsletters.html', records=newsletters)
    except Exception as e:
        logger.error(f"Error in usernewsletters: {e}")
        return render_template('user_newsletters.html', records=[])

@app.route('/newsletter', methods=['GET', 'POST'])
def newsletter():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            tags = request.form.getlist('tags')
            image_file = request.files.get('image')
            recipient_email_raw = request.form.get('recipient_email', '').strip()

            email_list = []

            def is_valid_email(email):
                return re.match(r"[^@]+@[^@]+\.[^@]+", email)

            try:
                parsed = json.loads(recipient_email_raw)
                email_list = [e['value'].strip() for e in parsed if 'value' in e and is_valid_email(e['value'].strip())]
            except:
                email_list = [e.strip() for e in recipient_email_raw.split(',') if is_valid_email(e.strip())]

            if not email_list:
                flash("❌ No valid email addresses provided.", "error")
                return redirect(url_for('newsletter'))

            image_filename = None
            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                image_file.save(image_path)

            newsletter_data = {
                "admin_email": session['email'],
                "uploaded_at": get_indian_time(),
                "title": title,
                "description": description,
                "tags": tags,
                "image": image_filename,
                "recipients": email_list
            }
            db.newsletters.insert_one(newsletter_data)
            
            # Send emails
            send_newsletter_email(title, description, image_filename, email_list)

            flash('✅ Newsletter uploaded and emailed successfully.', 'success')
            return redirect(url_for('newsletter'))
        except Exception as e:
            logger.error(f"Error in newsletter POST: {e}")
            flash('Error creating newsletter', 'error')

    try:
        records = list(db.newsletters.find().sort('uploaded_at', -1))
        return render_template('admin_newsletter.html', records=records)
    except Exception as e:
        logger.error(f"Error in newsletter GET: {e}")
        return render_template('admin_newsletter.html', records=[])

@app.route('/edit_newsletter/<id>', methods=['GET'])
def edit_newsletter(id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        record = db.newsletters.find_one({'_id': ObjectId(id)})
        if not record:
            flash('Newsletter not found.', 'error')
            return redirect(url_for('newsletter'))

        return render_template('edit_newsletter.html', record=record)
    except Exception as e:
        logger.error(f"Error in edit_newsletter: {e}")
        flash('Error loading newsletter', 'error')
        return redirect(url_for('newsletter'))

@app.route('/update_newsletter/<id>', methods=['POST'])
def update_newsletter(id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        record = db.newsletters.find_one({'_id': ObjectId(id)})
        if not record:
            flash('Newsletter not found.', 'error')
            return redirect(url_for('newsletter'))

        title = request.form.get('title')
        description = request.form.get('description')
        tags = request.form.getlist('tags')
        recipient_emails = request.form.get('recipient_email', '').split(',')
        recipient_emails = [email.strip() for email in recipient_emails if email.strip()]

        image_file = request.files.get('image')
        image_filename = record.get('image')

        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            image_filename = filename

        db.newsletters.update_one(
            {'_id': ObjectId(id)},
            {
                '$set': {
                    'title': title,
                    'description': description,
                    'tags': tags,
                    'recipients': recipient_emails,
                    'image': image_filename,
                    'updated_at': get_indian_time()
                }
            }
        )

        flash('✅ Newsletter updated successfully!', 'success')
        return redirect(url_for('newsletter'))
    except Exception as e:
        logger.error(f"Error updating newsletter: {e}")
        flash('Error updating newsletter', 'error')
        return redirect(url_for('newsletter'))

@app.route('/newsletter/delete/<id>')
def delete_newsletter(id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    try:
        db.newsletters.delete_one({"_id": ObjectId(id)})
        flash("✅ Newsletter deleted.", 'success')
    except Exception as e:
        logger.error(f"Error deleting newsletter: {e}")
        flash('Error deleting newsletter', 'error')
    
    return redirect(url_for('newsletter'))

@app.route('/subscribe_newsletter', methods=['POST'])
def subscribe_newsletter():
    try:
        email = request.form.get('email')
        
        if not email:
            flash("Email is required.", "error")
            return redirect(request.referrer or url_for('jainevents'))

        if db.subscribers.find_one({'email': email}):
            flash("You are already subscribed!", "info")
        else:
            db.subscribers.insert_one({
                'email': email,
                'subscribed_at': get_indian_time()
            })

            try:
                msg = Message(
                    subject="🎉 You're Subscribed to Our University Newsletter!",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[email]
                )
                msg.html = f"""
                <h2>Thank you for subscribing!</h2>
                <p>You'll now receive updates, articles, and event highlights directly to your inbox.</p>
                <p>If you did not request this, please ignore this message.</p>
                <br><hr>
                <small>This is an automated message from Jain University Newsletter system.</small>
                """
                mail.send(msg)
                flash("✅ Subscribed successfully! A confirmation email has been sent.", "success")
            except Exception as e:
                flash("Subscribed, but failed to send confirmation email.", "warning")
                logger.error(f"Email send error: {e}")

        return redirect(request.referrer or url_for('jainevents'))
    except Exception as e:
        logger.error(f"Error in subscribe_newsletter: {e}")
        flash('Error processing subscription', 'error')
        return redirect(request.referrer or url_for('jainevents'))

# ===================== EVENTS MANAGEMENT =====================
@app.route("/admin/events")
def admin_events():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        events = list(db.events.find().sort('event_date', -1))
        for e in events:
            e["_id"] = str(e["_id"])
        return render_template("admin_events.html", events=events)
    except Exception as e:
        logger.error(f"Error in admin_events: {e}")
        return render_template("admin_events.html", events=[])

@app.route("/add_event", methods=["POST"])
def add_event():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        data = request.form.to_dict()
        image_file = request.files.get("image")
        pdf_file = request.files.get("pdf")

        image_path = None
        pdf_path = None

        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image_file.save(image_path)
            image_path = "/" + image_path.replace("\\", "/")

        if pdf_file and pdf_file.filename:
            filename = secure_filename(pdf_file.filename)
            pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            pdf_file.save(pdf_path)
            pdf_path = "/" + pdf_path.replace("\\", "/")

        event = {
            "event_name": data.get("event_name"),
            "description": data.get("description"),
            "school": data.get("school"),
            "department": data.get("department"),
            "event_action": data.get("event_action"),
            "event_type": data.get("event_type"),
            "venue": data.get("venue"),
            "event_date": data.get("event_date"),
            "end_date": data.get("end_date"),
            "event_time": data.get("event_time", "All Day"),
            "image": image_path,
            "pdf": pdf_path,
            "created_at": get_indian_time()
        }

        db.events.insert_one(event)
        logger.info(f"✅ Event added: {event['event_name']}")
        flash('✅ Event added successfully!', 'success')
    except Exception as e:
        logger.error(f"Error adding event: {e}")
        flash('Error adding event', 'error')
    
    return redirect(url_for('admin_events'))

@app.route("/delete_event/<event_id>")
def delete_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        db.events.delete_one({"_id": ObjectId(event_id)})
        flash('✅ Event deleted successfully!', 'success')
    except Exception as e:
        logger.error(f"Error deleting event: {e}")
        flash('Error deleting event', 'error')
    
    return redirect(url_for('admin_events'))

@app.route("/edit_event/<event_id>", methods=["GET"])
def edit_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        event = db.events.find_one({"_id": ObjectId(event_id)})
        if not event:
            flash('Event not found.', 'error')
            return redirect(url_for('admin_events'))

        event["_id"] = str(event["_id"])
        return render_template("edit_event.html", event=event)
    except Exception as e:
        logger.error(f"Error in edit_event: {e}")
        flash('Error loading event', 'error')
        return redirect(url_for('admin_events'))

@app.route("/update_event/<event_id>", methods=["POST"])
def update_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        data = request.form.to_dict()
        image_file = request.files.get("image")
        pdf_file = request.files.get("pdf")

        update_data = {
            "event_name": data.get("event_name"),
            "description": data.get("description"),
            "school": data.get("school"),
            "department": data.get("department"),
            "event_action": data.get("event_action"),
            "event_type": data.get("event_type"),
            "venue": data.get("venue"),
            "event_date": data.get("event_date"),
            "end_date": data.get("end_date"),
            "event_time": data.get("event_time", "All Day"),
            "updated_at": get_indian_time()
        }

        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image_file.save(image_path)
            update_data["image"] = "/" + image_path.replace("\\", "/")

        if pdf_file and pdf_file.filename:
            filename = secure_filename(pdf_file.filename)
            pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            pdf_file.save(pdf_path)
            update_data["pdf"] = "/" + pdf_path.replace("\\", "/")

        db.events.update_one({"_id": ObjectId(event_id)}, {"$set": update_data})
        flash('✅ Event updated successfully!', 'success')
    except Exception as e:
        logger.error(f"Error updating event: {e}")
        flash('Error updating event', 'error')
    
    return redirect(url_for('admin_events'))

# ===================== EVENT REMINDER ENDPOINTS =====================
@app.route('/api/events/set-reminder', methods=['POST'])
def set_event_reminder():
    """Set a reminder for an event - USES INDIAN TIME"""
    if session.get('role') != 'user':
        return jsonify({'error': 'Access denied'}), 403

    try:
        data = request.get_json()
        event_id = data.get('event_id')
        reminder_date = data.get('reminder_date')
        reminder_time = data.get('reminder_time')
        
        if not event_id or not reminder_date or not reminder_time:
            return jsonify({'error': 'Event ID, reminder date and time are required'}), 400
        
        event = db.events.find_one({'_id': ObjectId(event_id)})
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        user = db.users.find_one({'email': session['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Parse the reminder datetime and localize to IST
        reminder_datetime_str = f"{reminder_date} {reminder_time}:00"
        reminder_datetime = datetime.strptime(reminder_datetime_str, '%Y-%m-%d %H:%M:%S')
        reminder_datetime = IST.localize(reminder_datetime)
        
        logger.info(f"[SET REMINDER] User: {user['email']} | Event: {event['event_name']} | Time: {reminder_datetime.strftime('%Y-%m-%d %H:%M:%S')} IST")
        
        # Check if reminder already exists
        existing = db.event_reminders.find_one({
            'user_id': user['_id'],
            'event_id': event['_id']
        })
        
        if existing:
            # Update existing reminder
            db.event_reminders.update_one(
                {'_id': existing['_id']},
                {'$set': {
                    'reminder_datetime': reminder_datetime,
                    'sent': False,
                    'updated_at': get_indian_time()
                }}
            )
            logger.info(f"✅ [REMINDER UPDATED] {reminder_datetime.strftime('%Y-%m-%d %H:%M:%S')} IST")
        else:
            # Create new reminder
            db.event_reminders.insert_one({
                'user_id': user['_id'],
                'event_id': event['_id'],
                'reminder_datetime': reminder_datetime,
                'sent': False,
                'created_at': get_indian_time()
            })
            logger.info(f"✅ [REMINDER CREATED] {reminder_datetime.strftime('%Y-%m-%d %H:%M:%S')} IST")
        
        return jsonify({
            'success': True,
            'message': f"✅ Reminder set for {reminder_datetime.strftime('%d %B %Y at %I:%M %p')} IST"
        })
        
    except Exception as e:
        logger.error(f"❌ [SET REMINDER ERROR] {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 400

@app.route('/api/events/subscribe', methods=['POST'])
def subscribe_to_event_api():
    """Subscribe to event notifications"""
    if session.get('role') != 'user':
        return jsonify({'error': 'Access denied'}), 403

    try:
        data = request.get_json()
        event_id = data.get('event_id')
        
        if not event_id:
            return jsonify({'error': 'Event ID is required'}), 400
        
        event = db.events.find_one({'_id': ObjectId(event_id)})
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        user = db.users.find_one({'email': session['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if already subscribed
        existing = db.event_subscriptions.find_one({
            'user_id': user['_id'],
            'event_id': event['_id']
        })
        
        if existing:
            return jsonify({'message': 'Already subscribed to this event'}), 200
        
        # Subscribe user
        db.event_subscriptions.insert_one({
            'user_id': user['_id'],
            'event_id': event['_id'],
            'subscribed_at': get_indian_time()
        })
        
        # Send confirmation email
        try:
            msg = Message(
                subject=f"✅ Subscribed to Event: {event['event_name']}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[user['email']]
            )
            
            msg.html = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>Event Subscription Confirmed</h2>
                <p>You have successfully subscribed to:</p>
                <h3>{event['event_name']}</h3>
                <p><strong>Date:</strong> {event['event_date']}</p>
                <p><strong>Time:</strong> {event.get('event_time', 'All Day')}</p>
                <p><strong>Venue:</strong> {event['venue']}</p>
                <p>You will receive updates and reminders about this event.</p>
                <hr>
                <small>Jain University Portal</small>
            </div>
            """
            
            mail.send(msg)
        except Exception as e:
            logger.error(f"Error sending subscription email: {e}")
        
        return jsonify({'success': True, 'message': 'Subscribed successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error subscribing to event: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400

# ===================== API ENDPOINTS =====================
@app.route('/api/events')
def get_events():
    try:
        current_date = datetime.now().strftime('%Y-%m-%d')

        events = list(db.events.find({
            "$or": [
                {"event_date": {"$gte": current_date}},
                {"end_date": {"$gte": current_date}}
            ]
        }).sort("event_date", 1))

        events_data = []
        for event in events:
            events_data.append({
                'id': str(event['_id']),
                'event_name': event.get('event_name', ''),
                'event_date': event.get('event_date', ''),
                'end_date': event.get('end_date', ''),
                'event_time': event.get('event_time', 'All Day'),
                'venue': event.get('venue', 'TBA'),
                'description': event.get('description', ''),
                'event_type': event.get('event_type', ''),
                'school': event.get('school', ''),
                'department': event.get('department', ''),
                'image': event.get('image', ''),
                'pdf': event.get('pdf', '')
            })

        return jsonify(events_data)
    except Exception as e:
        logger.error(f"Error fetching events: {e}")
        return jsonify([])

@app.route('/api/events/<event_id>')
def get_event(event_id):
    try:
        event = db.events.find_one({"_id": ObjectId(event_id)})
        if not event:
            return jsonify({'error': 'Event not found'}), 404

        return jsonify({
            'id': str(event['_id']),
            'event_name': event.get('event_name', ''),
            'event_date': event.get('event_date', ''),
            'end_date': event.get('end_date', ''),
            'event_time': event.get('event_time', 'All Day'),
            'venue': event.get('venue', 'TBA'),
            'description': event.get('description', ''),
            'event_type': event.get('event_type', ''),
            'school': event.get('school', ''),
            'department': event.get('department', ''),
            'image': event.get('image', ''),
            'pdf': event.get('pdf', '')
        })
    except Exception as e:
        logger.error(f"Error fetching event: {e}")
        return jsonify({'error': 'Event not found'}), 404

@app.route('/api/events/today')
def get_today_events():
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        events = list(db.events.find({
            "$or": [
                {"event_date": today},
                {"end_date": today},
                {"$and": [
                    {"event_date": {"$lte": today}},
                    {"end_date": {"$gte": today}}
                ]}
            ]
        }).sort("event_date", 1))

        events_data = []
        for event in events:
            events_data.append({
                'id': str(event['_id']),
                'event_name': event.get('event_name', ''),
                'event_date': event.get('event_date', ''),
                'event_time': event.get('event_time', 'All Day'),
                'venue': event.get('venue', 'TBA')
            })

        return jsonify(events_data)
    except Exception as e:
        logger.error(f"Error fetching today's events: {e}")
        return jsonify([])

@app.route('/api/events/filter')
def filter_events():
    """Filter events by department, date range, etc."""
    try:
        department = request.args.get('department')
        school = request.args.get('school')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        event_type = request.args.get('event_type')
        
        query = {}
        
        if department:
            query['department'] = department
        
        if school:
            query['school'] = school
        
        if event_type:
            query['event_type'] = event_type
        
        if start_date and end_date:
            query['event_date'] = {'$gte': start_date, '$lte': end_date}
        elif start_date:
            query['event_date'] = {'$gte': start_date}
        elif end_date:
            query['event_date'] = {'$lte': end_date}
        
        events = list(db.events.find(query).sort('event_date', 1))
        
        events_data = []
        for event in events:
            events_data.append({
                'id': str(event['_id']),
                'event_name': event.get('event_name', ''),
                'event_date': event.get('event_date', ''),
                'end_date': event.get('end_date', ''),
                'event_time': event.get('event_time', 'All Day'),
                'venue': event.get('venue', ''),
                'description': event.get('description', ''),
                'event_type': event.get('event_type', ''),
                'school': event.get('school', ''),
                'department': event.get('department', ''),
                'image': event.get('image', ''),
                'pdf': event.get('pdf', '')
            })
        
        return jsonify(events_data)
        
    except Exception as e:
        logger.error(f"Error filtering events: {e}")
        return jsonify([])

@app.route('/api/departments')
def get_departments():
    """Get unique departments from events"""
    try:
        departments = db.events.distinct('department')
        return jsonify(sorted([d for d in departments if d]))
    except Exception as e:
        logger.error(f"Error getting departments: {e}")
        return jsonify([])

@app.route('/api/schools')
def get_schools():
    """Get unique schools from events"""
    try:
        schools = db.events.distinct('school')
        return jsonify(sorted([s for s in schools if s]))
    except Exception as e:
        logger.error(f"Error getting schools: {e}")
        return jsonify([])

# ===================== FILE SERVING =====================
# ===================== FILE SERVING =====================
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return "File not found", 404


@app.route('/newsletter_view/<newsletter_id>')
def newsletter_view(newsletter_id):
    try:
        news = db.newsletters.find_one({'_id': ObjectId(newsletter_id)})
        if not news:
            return "Newsletter not found", 404
        news['_id'] = str(news['_id'])
        return render_template('newsletter_detail.html', news=news)
    except Exception as e:
        logger.error(f"Error viewing newsletter: {e}")
        return "Error loading newsletter", 500

# ===================== ERROR HANDLERS =====================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('500.html'), 500
# ===================== FILE SERVING =====================
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return "File not found", 404

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Maximum size is 50MB.', 'error')
    return redirect(request.referrer or url_for('home'))
@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('login'))

    return render_template('admin_dashboard.html')

# ===================== RUN APP =====================
if __name__ == '__main__':
    # Initialize scheduler with timezone
    scheduler = BackgroundScheduler(timezone=IST)

    # Check for reminders every minute
    @scheduler.scheduled_job('interval', minutes=1, id='reminder_check')
    def scheduled_send_event_reminders():
        with app.app_context():
            logger.info(f"[SCHEDULER] Running reminder check at {get_indian_time().strftime('%Y-%m-%d %H:%M:%S')} IST")
            send_event_reminders()

    # Send daily emails at 7 AM IST
    @scheduler.scheduled_job('cron', hour=7, minute=0, id='daily_digest')
    def scheduled_send_daily_event_emails():
        with app.app_context():
            logger.info(f"[SCHEDULER] Running daily digest at {get_indian_time().strftime('%Y-%m-%d %H:%M:%S')} IST")
            send_daily_event_emails()

    scheduler.start()
    logger.info("✅ Scheduler started successfully with IST timezone")
    logger.info(f"✅ Current IST time: {get_indian_time().strftime('%Y-%m-%d %H:%M:%S')}")

    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)