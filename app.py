import re
##123
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
from functools import wraps

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
from datetime import timedelta

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = False   # Set True only if HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
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

# FIXED: Mail Configuration - Test this configuration first
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'info.loginpanel@gmail.com'
app.config['MAIL_PASSWORD'] = 'wedbfepklgtwtugf'  # This is an app password
app.config['MAIL_DEFAULT_SENDER'] = 'info.loginpanel@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False

# Initialize Mail with app
mail = Mail(app)

# Test mail configuration on startup
with app.app_context():
    try:
        # Test sending a test email to yourself
        test_msg = Message(
            subject="Reminder System Test",
            sender=app.config['MAIL_USERNAME'],
            recipients=[app.config['MAIL_USERNAME']]  # Send to yourself for testing
        )
        test_msg.body = "This is a test email to verify the reminder system is working."
        mail.send(test_msg)
        logger.info("✅ Mail configuration test successful - test email sent")
    except Exception as e:
        logger.error(f"❌ Mail configuration test failed: {e}")

# INDIAN TIMEZONE
IST = pytz.timezone('Asia/Kolkata')

# Google OAuth Scopes
DRIVE_SCOPES = [
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive'
]
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# ===================== DATABASE INDEXES =====================
def create_indexes():
    """Create database indexes for better performance"""
    try:
        # Users collection indexes
        db.users.create_index([('email', 1)], unique=True)
        db.users.create_index([('approved', 1)])
        db.users.create_index([('user_type', 1)])
        db.users.create_index([('special_role', 1)])
        db.users.create_index([('is_online', 1)])
        db.users.create_index([('last_seen', -1)])
        
        # Events collection indexes
        db.events.create_index([('event_date', 1)])
        db.events.create_index([('school', 1)])
        db.events.create_index([('department', 1)])
        
        # Reminders collection indexes - FIXED: Added better indexes
        db.event_reminders.create_index([('user_id', 1)])
        db.event_reminders.create_index([('reminder_datetime', 1)])
        db.event_reminders.create_index([('sent', 1)])
        db.event_reminders.create_index([('sent', 1), ('reminder_datetime', 1)])  # Composite index for faster queries
        db.event_reminders.create_index([('sent', 1), ('reminder_datetime', 1), ('user_id', 1)])  # Most efficient query
        
        # Chat collection indexes
        db.chat_messages.create_index([('sender_id', 1)])
        db.chat_messages.create_index([('receiver_id', 1)])
        db.chat_messages.create_index([('group_id', 1)])
        db.chat_messages.create_index([('timestamp', -1)])
        
        # Document shares indexes
        db.document_shares.create_index([('shared_by', 1)])
        db.document_shares.create_index([('shared_with', 1)])
        db.document_shares.create_index([('shared_at', -1)])
        
        # Office documents indexes
        db.office_documents.create_index([('user_email', 1)])
        db.office_documents.create_index([('status', 1)])
        db.office_documents.create_index([('submitted_at', -1)])
        
        # Activity logs indexes
        db.activity_logs.create_index([('user_id', 1)])
        db.activity_logs.create_index([('timestamp', -1)])
        
        logger.info("✅ Database indexes created successfully")
    except Exception as e:
        logger.error(f"❌ Error creating indexes: {e}")

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

# ===================== DECORATORS =====================
def approval_required(f):
    """Decorator to require admin approval before accessing route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'email' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        
        # Check if user is approved
        if not session.get('approved', False):
            flash('⏳ Your account is pending admin approval. Access denied.', 'warning')
            return redirect(url_for('home'))
        
        # User is approved, proceed to the route
        return f(*args, **kwargs)
    
    return decorated_function

def login_required(f):
    """Decorator to require login before accessing route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ===================== GOOGLE DRIVE FUNCTIONS =====================
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

# ===================== ROLE CHECK FUNCTIONS =====================
def is_faculty():
    """Check if user is regular faculty (not core or leader)"""
    return (session.get('role') == 'user' and 
            session.get('user_type') == 'faculty' and 
            not session.get('special_role'))

def is_core_member():
    """Check if user is core team member"""
    return (session.get('role') == 'user' and 
            session.get('special_role') in ['core', 'office_barrier'])

def is_leader():
    """Check if user is a leader"""
    return (session.get('role') == 'user' and 
            session.get('special_role') == 'leader')

def is_core_or_leader():
    """Check if user is core member or leader"""
    return is_core_member() or is_leader()

def is_office_barrier():
    """Check if user is office barrier (core team)"""
    return is_core_member()

def has_special_access():
    """Check if user has special access (core, leader)"""
    return is_core_or_leader()

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

@app.context_processor
def inject_current_time():
    """Inject current Indian time into templates"""
    return dict(now=get_indian_time())

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
                'link': url_for('home')
            })
        
        # Get document shares
        if is_leader():
            shared_docs = list(db.document_shares.find({
                'shared_with': user['_id']
            }).sort('shared_at', -1).limit(3))
            
            for share in shared_docs:
                sender = db.users.find_one({'_id': share['shared_by']})
                notifications.append({
                    'type': 'share',
                    'icon': 'share-alt',
                    'title': f"Document Shared: {share['document_name']}",
                    'message': f"From: {sender['email'].split('@')[0] if sender else 'Unknown'}",
                    'time': share.get('shared_at', get_indian_time()),
                    'link': url_for('leader_dashboard')
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

# ===================== SCHEDULED TASKS - COMPLETELY FIXED =====================
def send_event_reminders():
    """Send event reminders based on user preferences - FIXED VERSION"""
    try:
        now = get_indian_time()
        now_naive = now.replace(tzinfo=None)  # Convert to naive for comparison with DB if needed
        
        logger.info("=" * 60)
        logger.info(f"[REMINDER CHECK] Starting reminder check at {now.strftime('%Y-%m-%d %H:%M:%S')} IST")
        
        # FIXED: Get all unsent reminders with reminder_datetime <= now
        # We need to handle both timezone-aware and naive datetimes in DB
        reminders = list(db.event_reminders.find({
            'sent': False,
            'reminder_datetime': {'$lte': now}
        }))
        
        logger.info(f"[REMINDER CHECK] Found {len(reminders)} pending reminders to send")
        
        if not reminders:
            logger.info("[REMINDER CHECK] No reminders to send at this time")
            return
        
        sent_count = 0
        error_count = 0
        
        for reminder in reminders:
            try:
                reminder_id = reminder['_id']
                reminder_dt = reminder.get('reminder_datetime')
                
                # Handle string dates
                if isinstance(reminder_dt, str):
                    try:
                        # Try parsing with timezone
                        reminder_dt = datetime.fromisoformat(reminder_dt.replace('Z', '+00:00'))
                    except:
                        try:
                            reminder_dt = datetime.strptime(reminder_dt, '%Y-%m-%d %H:%M:%S')
                        except:
                            try:
                                reminder_dt = datetime.strptime(reminder_dt, '%Y-%m-%dT%H:%M:%S')
                            except Exception as e:
                                logger.error(f"Could not parse reminder datetime: {reminder_dt} - {e}")
                                # Mark as errored
                                db.event_reminders.update_one(
                                    {'_id': reminder_id},
                                    {'$set': {'error': f'Invalid date format: {reminder_dt}', 'last_attempt': now}}
                                )
                                error_count += 1
                                continue
                
                # Ensure timezone awareness and convert to IST for comparison
                if isinstance(reminder_dt, datetime):
                    if reminder_dt.tzinfo is None:
                        # Assume IST if no timezone
                        reminder_dt = IST.localize(reminder_dt)
                    else:
                        reminder_dt = reminder_dt.astimezone(IST)
                
                logger.info(f"[REMINDER] Processing reminder {reminder_id} - Scheduled: {reminder_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Get event details
                event = db.events.find_one({'_id': reminder['event_id']})
                if not event:
                    logger.warning(f"[REMINDER] Event not found: {reminder['event_id']}")
                    # Mark as sent to avoid repeated errors
                    db.event_reminders.update_one(
                        {'_id': reminder_id},
                        {'$set': {'sent': True, 'error': 'Event not found'}}
                    )
                    error_count += 1
                    continue
                
                # Get user details
                user = db.users.find_one({'_id': reminder['user_id']})
                if not user:
                    logger.warning(f"[REMINDER] User not found: {reminder['user_id']}")
                    # Mark as sent to avoid repeated errors
                    db.event_reminders.update_one(
                        {'_id': reminder_id},
                        {'$set': {'sent': True, 'error': 'User not found'}}
                    )
                    error_count += 1
                    continue
                
                logger.info(f"[REMINDER] Sending to: {user['email']} | Event: {event['event_name']}")
                
                # FIXED: Simplified email - plain text first to ensure delivery
                msg = Message(
                    subject=f"🔔 REMINDER: {event['event_name']}",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[user['email']]
                )
                
                # Plain text version (always works)
                msg.body = f"""
========================================
           EVENT REMINDER
========================================

Event: {event['event_name']}
Date: {event['event_date']}
Time: {event.get('event_time', 'All Day')}
Venue: {event['venue']}

Description:
{event.get('description', 'No description provided')}

========================================
This reminder was scheduled for: {reminder_dt.strftime('%d %B %Y at %I:%M %p')} IST

View all events: {request.url_root}jainevents

========================================
Jain University Portal - Office of Academics
This is an automated reminder. Please do not reply.
========================================
                """
                
                # HTML version for better appearance
                msg.html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .header {{ background: #04043a; color: #FFD700; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                        .content {{ background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }}
                        .event-details {{ background: white; padding: 15px; border-radius: 8px; margin: 15px 0; }}
                        .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
                        .button {{ display: inline-block; background: #04043a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>⏰ Event Reminder</h1>
                        </div>
                        <div class="content">
                            <h2 style="color: #04043a;">{event['event_name']}</h2>
                            
                            <div class="event-details">
                                <p><strong>📅 Date:</strong> {event['event_date']}</p>
                                <p><strong>⏰ Time:</strong> {event.get('event_time', 'All Day')}</p>
                                <p><strong>📍 Venue:</strong> {event['venue']}</p>
                                <p><strong>🏢 Department:</strong> {event.get('department', 'N/A')}</p>
                                <p><strong>🏫 School:</strong> {event.get('school', 'N/A')}</p>
                            </div>
                            
                            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0;">
                                <p style="margin: 0;"><strong>📝 Description:</strong></p>
                                <p style="margin: 10px 0 0 0;">{event.get('description', 'No description provided')}</p>
                            </div>
                            
                            <div style="background: #e8f4fd; padding: 15px; border-radius: 8px; margin: 15px 0;">
                                <p style="margin: 0; color: #0056b3;">
                                    <strong>⏳ This reminder was scheduled for:</strong><br>
                                    <span style="font-size: 16px; font-weight: bold;">{reminder_dt.strftime('%d %B %Y at %I:%M %p')} IST</span>
                                </p>
                            </div>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{request.url_root}jainevents" class="button">View All Events</a>
                            </div>
                        </div>
                        <div class="footer">
                            <p>Jain University Portal - Office of Academics</p>
                            <p>This is an automated reminder. Please do not reply.</p>
                            <p>Sent at: {now.strftime('%Y-%m-%d %I:%M %p')} IST</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                # Send the email
                mail.send(msg)
                logger.info(f"✅ [REMINDER SENT] To: {user['email']} | Event: {event['event_name']}")
                
                # Mark as sent in database
                db.event_reminders.update_one(
                    {'_id': reminder_id},
                    {'$set': {
                        'sent': True,
                        'sent_at': now,
                        'email_sent': True
                    }}
                )
                
                sent_count += 1
                
            except Exception as e:
                logger.error(f"❌ [REMINDER ERROR] Failed to send reminder {reminder.get('_id')}: {str(e)}", exc_info=True)
                
                # Mark as errored but don't mark as sent - will retry
                db.event_reminders.update_one(
                    {'_id': reminder['_id']},
                    {'$set': {
                        'last_error': str(e),
                        'last_attempt': now,
                        'attempt_count': (reminder.get('attempt_count', 0) + 1)
                    }}
                )
                error_count += 1
                continue
        
        logger.info(f"[REMINDER CHECK] Completed: {sent_count} sent, {error_count} errors")
        logger.info("=" * 60)
        
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
        }).sort("event_date", 1))
        
        logger.info(f"[DAILY EMAIL] Sending to {len(subscribers)} subscribers about {len(events)} events")
        
        for sub in subscribers:
            try:
                # Filter events by school if subscriber has preference
                user_events = events
                if sub.get('school'):
                    user_events = [e for e in events if e.get('school') == sub.get('school')]
                
                if not user_events:
                    continue
                
                msg = Message(
                    subject="📅 Upcoming University Events - Weekly Digest",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[sub['email']]
                )
                
                # Build email content
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .header {{ background: #04043a; color: #FFD700; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                        .content {{ background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }}
                        .event {{ background: white; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #FFD700; }}
                        .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>📅 Weekly Events Digest</h1>
                        </div>
                        <div class="content">
                            <p>Hello,</p>
                            <p>Here are the upcoming events for this week:</p>
                """
                
                for event in user_events:
                    html_content += f"""
                            <div class="event">
                                <h3 style="color: #04043a; margin-top: 0;">{event['event_name']}</h3>
                                <p><strong>📅 Date:</strong> {event['event_date']}</p>
                                <p><strong>⏰ Time:</strong> {event.get('event_time', 'All Day')}</p>
                                <p><strong>📍 Venue:</strong> {event['venue']}</p>
                                <p><strong>🏫 School:</strong> {event.get('school', 'N/A')}</p>
                                <p><strong>📝 Description:</strong> {event.get('description', '')[:100]}{'...' if len(event.get('description', '')) > 100 else ''}</p>
                            </div>
                    """
                
                html_content += f"""
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{request.url_root}jainevents" style="display: inline-block; background: #04043a; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px;">View All Events</a>
                            </div>
                        </div>
                        <div class="footer">
                            <p>Jain University Portal - Office of Academics</p>
                            <p>To unsubscribe, please visit your preferences page.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                msg.html = html_content
                mail.send(msg)
                logger.info(f"✅ Daily digest sent to {sub['email']}")
                
            except Exception as e:
                logger.error(f"❌ Error sending daily email to {sub['email']}: {e}")
                
    except Exception as e:
        logger.error(f"❌ Error in send_daily_event_emails: {e}")

def send_newsletter_email(title, content, image_filename, recipients):
    """Send newsletter email to recipients"""
    try:
        msg = Message(
            subject=title,
            sender=app.config['MAIL_USERNAME'],
            recipients=recipients
        )
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #04043a; color: #FFD700; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{title}</h1>
                </div>
                <div class="content">
                    <div style="color: #333; line-height: 1.8;">
                        {content}
                    </div>
                </div>
                <div class="footer">
                    <p>Jain University - Office of Academics</p>
                </div>
            </div>
        </body>
        </html>
        """

        if image_filename:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            if os.path.exists(image_path):
                with app.open_resource(image_path) as img:
                    msg.attach(image_filename, "image/jpeg", img.read())

        mail.send(msg)
        logger.info(f"✅ Newsletter '{title}' sent to {len(recipients)} recipients")
    except Exception as e:
        logger.error(f"Error sending newsletter email: {e}")
        raise

# ===================== AUTHENTICATION ROUTES =====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email.endswith('@jainuniversity.ac.in'):
            flash('Only @jainuniversity.ac.in emails allowed', 'error')
            return redirect(url_for('login'))
        
        user = db.users.find_one({'email': email})
        if user and check_password_hash(user['password'], password):
            # ✅ FIX: Clear ALL old session data before setting new session
            session.clear()
            
            # Store all user info in session
            session['email'] = email
            session['role'] = user['role']
            session['user_type'] = user.get('user_type', 'faculty')
            session['special_role'] = user.get('special_role', None)
            session['approved'] = user.get('approved', False)
            session['user_id'] = str(user['_id'])
            session.permanent = True  # Make session permanent to avoid expiry issues
            
            # Update online status
            db.users.update_one(
                {'email': email},
                {
                    '$set': {
                        'is_online': True,
                        'last_seen': get_indian_time()
                    }
                }
            )
            
            # Log activity
            db.activity_logs.insert_one({
                'user_id': user['_id'],
                'user_email': email,
                'action': 'login',
                'details': 'User logged in',
                'timestamp': get_indian_time(),
                'ip_address': request.remote_addr
            })
            
            if user['role'] == 'admin':
                flash('✅ Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                # ✅ FIX: ALL non-admin users go to home, regardless of special_role
                if not user.get('approved', False):
                    flash('⏳ Your account is pending admin approval. Limited access granted.', 'warning')
                else:
                    flash('✅ Login successful! Full access granted.', 'success')
                
                return redirect(url_for('home'))  # Always go to home for non-admin
        else:
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')


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
                msg = Message(
                    'Your OTP for Registration',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[email]
                )
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
                flash('OTP verified. Now set your password and select role.', 'success')
                return redirect(url_for('register'))
            else:
                flash('Invalid OTP. Please try again.', 'error')
                return redirect(url_for('register'))
        
        elif session['step'] == 3:
            password = request.form.get('password')
            user_type = request.form.get('user_type', 'faculty')
            
            if user_type not in ['faculty', 'core']:
                user_type = 'faculty'
            
            hashed_pw = generate_password_hash(password)
            email = session['email']
            
            special_role = 'office_barrier' if user_type == 'core' else None
            
            new_user_id = db.users.insert_one({
                'email': email, 
                'password': hashed_pw, 
                'role': 'user',
                'user_type': user_type,
                'special_role': special_role,
                'approved': False,
                'is_online': True,
                'last_seen': get_indian_time(),
                'profile': {
                    'department': '',
                    'school': '',
                    'phone': ''
                },
                'created_at': get_indian_time()
            }).inserted_id
            
            session['role'] = 'user'
            session['user_type'] = user_type
            session['special_role'] = special_role
            session['approved'] = False
            session['user_id'] = str(new_user_id)
            
            session.pop('otp', None)
            session.pop('step', None)
            session.pop('otp_verified', None)
            
            flash('✅ Registration complete! Waiting for admin approval to access all features.', 'info')
            return redirect(url_for('home'))
    
    otp_sent = session.get('step', 1) >= 2
    otp_verified = session.get('step', 1) == 3
    return render_template('register.html', otp_sent=otp_sent, otp_verified=otp_verified)

@app.route('/refresh_session')
def refresh_session():
    """Refresh user session data from database"""
    if 'email' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        user = db.users.find_one({'email': session['email']})
        if user:
            # Update session with latest data
            session['role'] = user['role']
            session['user_type'] = user.get('user_type', 'faculty')
            session['special_role'] = user.get('special_role', None)
            session['approved'] = user.get('approved', False)
            session['user_id'] = str(user['_id'])
            
            logger.info(f"Session refreshed for {session['email']} - Approved: {session['approved']}, Role: {session['special_role']}")
            
            return jsonify({
                'success': True,
                'message': 'Session refreshed',
                'approved': session['approved'],
                'special_role': session['special_role'],
                'user_type': session['user_type']
            })
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        logger.error(f"Error refreshing session: {e}")
        return jsonify({'error': str(e)}), 500

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
        db.users.insert_one({
            'email': email, 
            'password': hashed_pw, 
            'role': 'admin',
            'user_type': 'admin',
            'special_role': None,
            'approved': True,
            'created_at': get_indian_time()
        })
        flash('✅ Admin registered successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('admin_register.html')

@app.route('/logout')
def logout():
    if 'email' in session:
        # Update online status
        db.users.update_one(
            {'email': session['email']},
            {
                '$set': {
                    'is_online': False,
                    'last_seen': get_indian_time()
                }
            }
        )
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# ===================== MAIN PAGES =====================
@app.route('/')
def index():
    """Landing page - shown to all visitors before login"""
    return render_template('index.html')

@app.route("/home")
@login_required
def home():
    try:
        user = db.users.find_one({"email": session["email"]})
        records = list(db.ugc_data.find().sort("uploaded_at", -1).limit(50))
        monthly_records = list(db.monthly_engagement.find().sort("uploaded_at", -1).limit(50))
        newsletter_records = list(db.newsletters.find().sort("uploaded_at", -1).limit(50))

        # KEY FIX 1: Reliable IST date using UTC conversion
        today_str = get_today_ist_string()
        logger.info(f"[HOME] Today IST: {today_str}")

        # KEY FIX 2: Fetch ALL events then filter in Python (not MongoDB query)
        all_events_raw = list(db.events.find({}).sort("event_date", 1))
        logger.info(f"[HOME] Total events in DB: {len(all_events_raw)}")

        for ev in all_events_raw:
            ev["_id"] = str(ev["_id"])

        today_events = []
        upcoming_events = []
        all_upcoming = []

        for ev in all_events_raw:
            event_date = normalize_date(ev.get("event_date", ""))
            end_date = normalize_date(ev.get("end_date", "")) if ev.get("end_date") else ""
            ev["event_date"] = event_date

            if not event_date:
                continue

            # Multi-day event spanning today
            if end_date and event_date <= today_str <= end_date:
                today_events.append(ev)
                all_upcoming.append(ev)
            elif event_date == today_str:
                today_events.append(ev)
                all_upcoming.append(ev)
            elif event_date > today_str:
                upcoming_events.append(ev)
                all_upcoming.append(ev)

        logger.info(f"[HOME] Today: {len(today_events)}, Upcoming: {len(upcoming_events)}")

        public_files = list(db.public_files.find().sort("uploaded_at", -1).limit(20))
        user_type = session.get("user_type", "faculty")
        special_role = session.get("special_role", None)
        approved = session.get("approved", False)
        can_upload = approved and special_role in ["core", "office_barrier", "leader"]
        is_fac = user_type == "faculty" and not special_role

        return render_template(
            "home.html",
            records=records,
            monthly_records=monthly_records,
            newsletter_records=newsletter_records,
            events=all_upcoming,
            today_events=today_events,
            upcoming_events=upcoming_events,
            all_events=all_events_raw,
            today=today_str,
            public_files=public_files,
            user_logged_in=True,
            user_email=session.get("email", ""),
            user_role=session.get("role", ""),
            user_type=user_type,
            is_faculty=is_fac,
            can_upload=can_upload,
            approved=approved,
            special_role=special_role,
        )
    except Exception as e:
        logger.error(f"Error in home route: {e}", exc_info=True)
        flash("Error loading home page", "error")
        return redirect(url_for("login"))

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
        notifications = get_user_notifications()
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

# ===================== CORE DASHBOARD =====================
@app.route('/core_dashboard')
@approval_required
def core_dashboard():
    """Dashboard for core team members - REQUIRES APPROVAL"""
    if not is_core_member():
        flash('Access denied. Core team members only.', 'error')
        return redirect(url_for('home'))
    
    try:
        user = db.users.find_one({'email': session['email']})
        
        # Get core team members (APPROVED ONLY)
        core_members = list(db.users.find({
            '$or': [
                {'user_type': 'core'},
                {'special_role': 'office_barrier'}
            ],
            'approved': True
        }))
        
        # Get all leaders (APPROVED ONLY)
        leaders = list(db.users.find({
            'special_role': 'leader',
            'approved': True
        }))
        
        # Get user's uploaded documents
        my_documents = list(db.office_documents.find({
            'user_email': session['email']
        }).sort('submitted_at', -1))
        
        # Get recent document shares
        recent_shares = list(db.document_shares.find({
            'shared_by': user['_id']
        }).sort('shared_at', -1).limit(10))
        
        # Enrich shares with leader names
        for share in recent_shares:
            share['shared_with_names'] = []
            for leader_id in share.get('shared_with', []):
                leader = db.users.find_one({'_id': leader_id})
                if leader:
                    share['shared_with_names'].append({
                        'id': str(leader['_id']),
                        'name': leader['email'].split('@')[0]
                    })
        
        # Get chat messages for core team
        chat_messages = list(db.chat_messages.find({
            '$or': [
                {'group_id': 'core_team'},
                {'receiver_id': user['_id']},
                {'sender_id': user['_id']}
            ]
        }).sort('timestamp', -1).limit(50))
        
        # Format chat messages
        formatted_messages = []
        for msg in reversed(chat_messages):
            sender = db.users.find_one({'_id': msg['sender_id']})
            formatted_messages.append({
                'id': str(msg['_id']),
                'sender_id': str(msg['sender_id']),
                'sender_name': sender['email'].split('@')[0] if sender else 'Unknown',
                'sender_email': sender['email'] if sender else '',
                'content': msg.get('content', ''),
                'file_url': msg.get('file_url'),
                'document_id': str(msg['document_id']) if msg.get('document_id') else None,
                'timestamp': msg['timestamp'].strftime('%I:%M %p'),
                'is_me': msg['sender_id'] == user['_id']
            })
        
        return render_template(
            'core_dashboard.html',
            core_members=core_members,
            leaders=leaders,
            my_documents=my_documents,
            recent_shares=recent_shares,
            chat_messages=formatted_messages
        )
        
    except Exception as e:
        logger.error(f"Error in core_dashboard: {e}", exc_info=True)
        flash('Error loading dashboard', 'error')
        return redirect(url_for('home'))

@app.route('/upload_document', methods=['POST'])
@approval_required
def upload_document():
    """Core team members upload documents for leader review"""
    if not is_core_member():
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        user = db.users.find_one({'email': session['email']})
        
        document_name = request.form.get('document_name')
        description = request.form.get('description')
        assigned_leaders = request.form.getlist('assigned_leaders')
        file = request.files.get('file')
        
        # Upload file
        file_url = None
        file_id = None
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            name_part, ext_part = os.path.splitext(filename)
            unique_filename = f"{name_part}_{timestamp}{ext_part}"
            
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            file_url = '/' + filepath.replace('\\', '/')
        
        # If no leaders assigned, all leaders can see it
        if not assigned_leaders or len(assigned_leaders) == 0:
            assigned_leaders = [str(leader['_id']) for leader in db.users.find({'special_role': 'leader'})]
        
        # Create document record
        doc = {
            'user_id': user['_id'],
            'user_email': session['email'],
            'document_name': document_name,
            'description': description,
            'file_id': file_id,
            'file_url': file_url,
            'assigned_leaders': [ObjectId(lid) for lid in assigned_leaders],
            'status': 'pending',
            'submitted_at': get_indian_time(),
            'reviewed_by': None,
            'reviewed_at': None,
            'comments': ''
        }
        
        result = db.office_documents.insert_one(doc)
        
        # Log activity
        db.activity_logs.insert_one({
            'user_id': user['_id'],
            'user_email': session['email'],
            'action': 'document_upload',
            'details': f'Submitted document: {document_name}',
            'timestamp': get_indian_time(),
            'ip_address': request.remote_addr
        })
        
        # Send notifications to assigned leaders
        for leader_id in assigned_leaders:
            leader = db.users.find_one({'_id': ObjectId(leader_id)})
            if leader:
                try:
                    msg = Message(
                        subject=f"📄 New Document for Review: {document_name}",
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[leader['email']]
                    )
                    msg.body = f"""
New Document Submitted for Review

From: {session['email'].split('@')[0]}
Document: {document_name}
Description: {description}

Please log in to review this document.

{request.url_root}leader_dashboard
                    """
                    mail.send(msg)
                except Exception as e:
                    logger.error(f"Error sending notification: {e}")
        
        flash('✅ Document submitted successfully', 'success')
        return redirect(url_for('core_dashboard'))
        
    except Exception as e:
        logger.error(f"Error submitting document: {e}")
        flash(f'Error submitting document: {str(e)[:100]}', 'error')
        return redirect(url_for('core_dashboard'))

# ===================== LEADER DASHBOARD =====================
@app.route('/leader_dashboard')
@approval_required
def leader_dashboard():
    """Dashboard for leaders to review documents - REQUIRES APPROVAL"""
    if not is_leader():
        flash('Access denied. Leaders only.', 'error')
        return redirect(url_for('home'))
    
    try:
        user = db.users.find_one({'email': session['email']})
        
        # Get documents assigned to this leader
        my_assigned_documents = list(db.office_documents.find({
            'assigned_leaders': user['_id']
        }).sort('submitted_at', -1))
        
        # Enrich with uploader info
        for doc in my_assigned_documents:
            uploader = db.users.find_one({'_id': doc['user_id']})
            if uploader:
                doc['uploader_name'] = uploader['email'].split('@')[0]
                doc['uploader_email'] = uploader['email']
        
        # Get documents shared with this leader
        shared_documents = list(db.document_shares.find({
            'shared_with': user['_id']
        }).sort('shared_at', -1))
        
        # Enrich shared documents
        for share in shared_documents:
            sender = db.users.find_one({'_id': share['shared_by']})
            share['sender_name'] = sender['email'].split('@')[0] if sender else 'Unknown'
            share['sender_email'] = sender['email'] if sender else ''
            
            doc = db.office_documents.find_one({'_id': share['document_id']})
            share['file_url'] = doc.get('file_url') if doc else None
        
        # Get all core team members (APPROVED ONLY)
        core_members = list(db.users.find({
            '$or': [
                {'user_type': 'core'},
                {'special_role': 'office_barrier'}
            ],
            'approved': True
        }))
        
        # Get online core members
        five_minutes_ago = get_indian_time() - timedelta(minutes=5)
        online_core = list(db.users.find({
            '$or': [
                {'user_type': 'core'},
                {'special_role': 'office_barrier'}
            ],
            'approved': True,
            '$or': [
                {'is_online': True},
                {'last_seen': {'$gte': five_minutes_ago}}
            ]
        }))
        
        return render_template(
            'leader_dashboard.html',
            my_assigned_documents=my_assigned_documents,
            shared_documents=shared_documents,
            core_members=core_members,
            online_core=online_core
        )
        
    except Exception as e:
        logger.error(f"Error in leader_dashboard: {e}", exc_info=True)
        flash('Error loading dashboard', 'error')
        return redirect(url_for('home'))
def get_today_ist_string():
    """Get today date as YYYY-MM-DD string in IST, always correct."""
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    ist_now = utc_now.astimezone(IST)
    return ist_now.strftime("%Y-%m-%d")


def normalize_date(date_str):
    """Normalize any date string to YYYY-MM-DD format."""
    if not date_str:
        return ""
    date_str = str(date_str).strip()
    if len(date_str) == 10 and date_str[4] == "-":
        return date_str
    for fmt in ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y", "%Y/%m/%d"]:
        try:
            return datetime.strptime(date_str, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return date_str
@app.route('/review_document/<document_id>', methods=['POST'])
@approval_required
def review_document(document_id):
    """Leader reviews a document"""
    if not is_leader():
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        user = db.users.find_one({'email': session['email']})
        
        status = request.form.get('status')
        comments = request.form.get('comments', '')
        
        # Update document
        db.office_documents.update_one(
            {'_id': ObjectId(document_id)},
            {
                '$set': {
                    'status': status,
                    'reviewed_by': user['_id'],
                    'reviewed_at': get_indian_time(),
                    'comments': comments
                }
            }
        )
        
        # Get document and send notification to uploader
        doc = db.office_documents.find_one({'_id': ObjectId(document_id)})
        uploader = db.users.find_one({'_id': doc['user_id']})
        
        if uploader:
            try:
                msg = Message(
                    subject=f"📋 Document Reviewed: {doc['document_name']}",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[uploader['email']]
                )
                msg.body = f"""
Your Document Has Been Reviewed

Document: {doc['document_name']}
Status: {status.upper()}
Reviewed by: {user['email'].split('@')[0]}
Comments: {comments}

View in Dashboard: {request.url_root}core_dashboard
                """
                mail.send(msg)
            except Exception as e:
                logger.error(f"Error sending review notification: {e}")
        
        flash(f'✅ Document {status}', 'success')
        return redirect(url_for('leader_dashboard'))
        
    except Exception as e:
        logger.error(f"Error reviewing document: {e}")
        flash(f'Error reviewing document: {str(e)[:100]}', 'error')
        return redirect(url_for('leader_dashboard'))

# ===================== CHAT ROUTES =====================
@app.route('/api/chat/messages')
@login_required
def get_chat_messages():
    """Get chat messages for user"""
    try:
        user = db.users.find_one({'email': session['email']})
        
        # Get messages where user is sender or receiver
        messages = list(db.chat_messages.find({
            '$or': [
                {'sender_id': user['_id']},
                {'receiver_id': user['_id']},
                {'group_id': 'core_team'}
            ]
        }).sort('timestamp', -1).limit(100))
        
        # Format messages
        formatted_messages = []
        for msg in reversed(messages):
            sender = db.users.find_one({'_id': msg['sender_id']})
            formatted_messages.append({
                'id': str(msg['_id']),
                'sender_id': str(msg['sender_id']),
                'sender_name': sender['email'].split('@')[0] if sender else 'Unknown',
                'sender_email': sender['email'] if sender else '',
                'content': msg.get('content', ''),
                'file_url': msg.get('file_url'),
                'document_id': str(msg['document_id']) if msg.get('document_id') else None,
                'timestamp': msg['timestamp'].strftime('%I:%M %p'),
                'is_me': msg['sender_id'] == user['_id']
            })
        
        return jsonify({
            'success': True,
            'messages': formatted_messages
        })
        
    except Exception as e:
        logger.error(f"Error getting chat messages: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/send', methods=['POST'])
@login_required
def send_chat_message():
    """Send a chat message"""
    try:
        user = db.users.find_one({'email': session['email']})
        
        data = request.get_json()
        content = data.get('content', '').strip()
        receiver_id = data.get('receiver_id')
        file_url = data.get('file_url')
        document_id = data.get('document_id')
        
        if not content and not file_url and not document_id:
            return jsonify({'error': 'Message content, file, or document required'}), 400
        
        # Create message
        message = {
            'sender_id': user['_id'],
            'receiver_id': ObjectId(receiver_id) if receiver_id else None,
            'group_id': 'core_team' if not receiver_id else None,
            'content': content,
            'file_url': file_url,
            'document_id': ObjectId(document_id) if document_id else None,
            'timestamp': get_indian_time(),
            'read': False
        }
        
        result = db.chat_messages.insert_one(message)
        
        # Send notification to receiver(s)
        if receiver_id:
            receiver = db.users.find_one({'_id': ObjectId(receiver_id)})
            if receiver and receiver.get('email'):
                send_chat_notification(user, receiver, content[:50])
        else:
            notify_group_chat(user, content[:50])
        
        return jsonify({
            'success': True,
            'message_id': str(result.inserted_id)
        })
        
    except Exception as e:
        logger.error(f"Error sending chat message: {e}")
        return jsonify({'error': str(e)}), 500

def send_chat_notification(sender, receiver, message_preview):
    """Send email notification for new chat message"""
    try:
        msg = Message(
            subject=f"💬 New message from {sender['email'].split('@')[0]}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[receiver['email']]
        )
        msg.body = f"""
New Message

You have received a new message from {sender['email'].split('@')[0]}:

"{message_preview}..."

View Message: {request.url_root}core_dashboard
        """
        mail.send(msg)
        logger.info(f"Chat notification sent to {receiver['email']}")
    except Exception as e:
        logger.error(f"Error sending chat notification: {e}")

def notify_group_chat(sender, message_preview):
    """Notify all online core members about group chat message"""
    try:
        # Get all online core members except sender
        online_core = list(db.users.find({
            'is_online': True,
            '$or': [
                {'user_type': 'core'},
                {'special_role': 'office_barrier'}
            ],
            'email': {'$ne': sender['email']}
        }))
        
        for member in online_core:
            send_chat_notification(sender, member, message_preview)
    except Exception as e:
        logger.error(f"Error notifying group chat: {e}")

# ===================== DOCUMENT SHARING ROUTES =====================
@app.route('/share_document', methods=['POST'])
@approval_required
def share_document():
    """Share a document with specific leaders"""
    if not is_core_or_leader():
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        user = db.users.find_one({'email': session['email']})
        
        document_id = request.form.get('document_id')
        leader_ids = request.form.getlist('leaders')
        message = request.form.get('message', '').strip()
        
        if not document_id or not leader_ids:
            return jsonify({'error': 'Document and at least one leader required'}), 400
        
        # Get document
        document = db.office_documents.find_one({'_id': ObjectId(document_id)})
        if not document or document['user_email'] != session['email']:
            return jsonify({'error': 'Document not found or unauthorized'}), 404
        
        # Create share record
        share_data = {
            'document_id': ObjectId(document_id),
            'document_name': document['document_name'],
            'shared_by': user['_id'],
            'shared_by_email': session['email'],
            'shared_with': [ObjectId(lid) for lid in leader_ids],
            'message': message,
            'shared_at': get_indian_time(),
            'status': 'sent'
        }
        
        result = db.document_shares.insert_one(share_data)
        
        # Send notifications to leaders
        for leader_id in leader_ids:
            leader = db.users.find_one({'_id': ObjectId(leader_id)})
            if leader:
                send_document_notification(user, leader, document, message)
        
        # Log activity
        db.activity_logs.insert_one({
            'user_id': user['_id'],
            'user_email': session['email'],
            'action': 'document_share',
            'details': f'Shared document {document["document_name"]} with {len(leader_ids)} leaders',
            'timestamp': get_indian_time(),
            'ip_address': request.remote_addr
        })
        
        flash('✅ Document shared successfully', 'success')
        return redirect(url_for('core_dashboard'))
        
    except Exception as e:
        logger.error(f"Error sharing document: {e}")
        flash(f'Error sharing document: {str(e)[:100]}', 'error')
        return redirect(url_for('core_dashboard'))

def send_document_notification(sender, receiver, document, message):
    """Send email notification for shared document"""
    try:
        msg = Message(
            subject=f"📄 Document Shared: {document['document_name']}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[receiver['email']]
        )
        msg.body = f"""
New Document Shared

{sender['email'].split('@')[0]} has shared a document with you:

Document: {document['document_name']}
Description: {document.get('description', 'No description')}
Shared at: {get_indian_time().strftime('%d %B %Y, %I:%M %p')}

{f'Message from sender: {message}' if message else ''}

View Document: {request.url_root}leader_dashboard

Jain University Portal - Office of Academics
        """
        mail.send(msg)
        logger.info(f"Document notification sent to {receiver['email']}")
    except Exception as e:
        logger.error(f"Error sending document notification: {e}")

# ===================== ACTIVITY STATUS ROUTES =====================
@app.route('/api/activity/status')
@login_required
def get_activity_status():
    """Get real-time activity status of core team and leaders"""
    try:
        # Update user's last activity
        db.users.update_one(
            {'email': session['email']},
            {'$set': {'last_seen': get_indian_time()}}
        )
        
        # Get active users (online in last 5 minutes)
        five_minutes_ago = get_indian_time() - timedelta(minutes=5)
        
        active_core = list(db.users.find({
            'approved': True,
            '$or': [
                {'user_type': 'core'},
                {'special_role': 'office_barrier'}
            ],
            '$or': [
                {'is_online': True},
                {'last_seen': {'$gte': five_minutes_ago}}
            ]
        }, {'email': 1, 'user_type': 1, 'special_role': 1, 'last_seen': 1}))
        
        active_leaders = list(db.users.find({
            'approved': True,
            'special_role': 'leader',
            '$or': [
                {'is_online': True},
                {'last_seen': {'$gte': five_minutes_ago}}
            ]
        }, {'email': 1, 'last_seen': 1}))
        
        # Format response
        response = {
            'core_team': [],
            'leaders': [],
            'total_active': len(active_core) + len(active_leaders)
        }
        
        for user in active_core:
            response['core_team'].append({
                'email': user['email'],
                'name': user['email'].split('@')[0],
                'type': user.get('special_role', 'core').capitalize(),
                'last_seen': user.get('last_seen', get_indian_time()).strftime('%I:%M %p'),
                'is_online': user.get('is_online', False)
            })
        
        for user in active_leaders:
            response['leaders'].append({
                'email': user['email'],
                'name': user['email'].split('@')[0],
                'last_seen': user.get('last_seen', get_indian_time()).strftime('%I:%M %p'),
                'is_online': user.get('is_online', False)
            })
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error getting activity status: {e}")
        return jsonify({'error': str(e)}), 500

# ===================== DASHBOARD ROUTES =====================
@app.route('/user')
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    """User dashboard with tabs and notifications"""
    try:
        user = db.users.find_one({'email': session['email']})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('login'))
        
        notifications = get_user_notifications()
        
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        next_week = today + timedelta(days=7)
        today_str = today.strftime('%Y-%m-%d')
        next_week_str = next_week.strftime('%Y-%m-%d')
        
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
        
        tomorrow_str = (today + timedelta(days=1)).strftime('%Y-%m-%d')
        upcoming_events = list(db.events.find({
            "event_date": {
                "$gte": tomorrow_str,
                "$lte": next_week_str
            }
        }).sort('event_date', 1))
        
        user_reminders = list(db.event_reminders.find({
            'user_id': user['_id']
        }).sort('reminder_datetime', 1))
        
        for reminder in user_reminders:
            event = db.events.find_one({'_id': reminder['event_id']})
            if event:
                reminder['event'] = event
        
        drive_stats = {'total_files': 0, 'recent_uploads': []}
        drive_connected = 'drive_creds' in session
        if drive_connected:
            try:
                drive_stats = get_drive_stats()
            except Exception as e:
                logger.error(f"❌ Error getting drive stats: {e}")
                drive_connected = False
        
        user_files = list(db.user_files.find({
            'user_email': session['email']
        }).sort('uploaded_at', -1).limit(20))
        
        public_files = list(db.public_files.find().sort('uploaded_at', -1).limit(20))
        
        user_navbar = get_user_navbar(session['email'])
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

# ===================== FILE MANAGEMENT ROUTES =====================
@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    """Upload file to local MongoDB storage"""
    try:
        file = request.files.get('file')
        file_name = request.form.get('file_name', '')
        description = request.form.get('description', '')
        
        if not file:
            return jsonify({'error': 'No file provided', 'success': False}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed. Allowed types: pdf, docx, txt, png, jpg, jpeg, gif, xlsx, csv, xls', 'success': False}), 400
        
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name_part, ext_part = os.path.splitext(filename)
        unique_filename = f"{name_part}_{timestamp}{ext_part}"
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
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

@app.route('/my_files')
@approval_required
def my_files():
    """User's file management page - REQUIRES APPROVAL"""
    try:
        notifications = get_user_notifications()
        
        local_files = list(db.user_files.find({
            'user_email': session['email']
        }).sort('uploaded_at', -1))
        
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
@login_required
def edit_file(file_id):
    """Edit file metadata"""
    try:
        data = request.get_json()
        new_name = data.get('file_name', '')
        new_description = data.get('description', '')
        
        if not new_name:
            return jsonify({'error': 'File name is required'}), 400
        
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
@login_required
def delete_file(file_id):
    """Delete file"""
    try:
        file_doc = db.user_files.find_one({
            '_id': ObjectId(file_id),
            'user_email': session['email']
        })
        
        if not file_doc:
            return jsonify({'error': 'File not found'}), 404
        
        if file_doc.get('source') == 'local' and 'file_path' in file_doc and os.path.exists(file_doc['file_path']):
            os.remove(file_doc['file_path'])
        
        elif file_doc.get('source') == 'drive' and 'drive_file_id' in file_doc:
            service = get_drive_service()
            if service:
                delete_drive_file(service, file_doc['drive_file_id'])
        
        db.user_files.delete_one({'_id': ObjectId(file_id)})
        db.public_files.delete_one({'file_id': file_doc.get('drive_file_id')})
        
        logger.info(f"✅ File deleted: {file_doc.get('file_name')} by {session['email']}")
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/download_file/<file_id>')
@login_required
def download_file(file_id):
    """Download file"""
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
@login_required
def link_drive_file():
    """Link a Google Drive file to user's MongoDB collection"""
    try:
        data = request.get_json()
        drive_file_id = data.get('drive_file_id')
        file_name = data.get('file_name', '')
        description = data.get('description', '')
        
        if not drive_file_id:
            return jsonify({'error': 'Drive file ID is required'}), 400
        
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Drive not connected'}), 400
        
        file_metadata = service.files().get(
            fileId=drive_file_id,
            fields='id, name, mimeType, size, webViewLink'
        ).execute()
        
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
@login_required
def manage_public_files():
    """Manage public files (make private, delete) - USER ONLY"""
    try:
        notifications = get_user_notifications()
        public_files = []
        drive_connected = 'drive_creds' in session
        
        if drive_connected:
            try:
                service = get_drive_service()
                if service:
                    db_public_files = list(db.public_files.find({
                        'uploader_email': session['email']
                    }).sort('uploaded_at', -1))
                    
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
@login_required
def make_file_private_api(file_id):
    """Make a Drive file private"""
    try:
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Drive not connected'}), 400
        
        file_doc = db.public_files.find_one({
            'file_id': file_id,
            'uploader_email': session['email']
        })
        
        if not file_doc:
            return jsonify({'error': 'File not found or unauthorized'}), 404
        
        success = make_file_private(service, file_id)
        
        if success:
            db.public_files.delete_one({'file_id': file_id})
            
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
@login_required
def delete_public_file(file_id):
    """Delete a public file from Drive"""
    try:
        service = get_drive_service()
        if not service:
            return jsonify({'error': 'Drive not connected'}), 400
        
        file_doc = db.public_files.find_one({
            'file_id': file_id,
            'uploader_email': session['email']
        })
        
        if not file_doc:
            return jsonify({'error': 'File not found or unauthorized'}), 404
        
        success = delete_drive_file(service, file_id)
        
        if success:
            db.public_files.delete_one({'file_id': file_id})
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
@login_required
def api_notifications():
    """Get user notifications as JSON"""
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
@login_required
def mark_notification_read(notification_id):
    """Mark notification as read"""
    try:
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error marking notification as read: {e}")
        return jsonify({'error': str(e)}), 400

# ===================== GOOGLE OAUTH ROUTES =====================
@app.route('/connect-drive')
@login_required
def connect_drive():
    try:
        session.pop('drive_creds', None)
        session.pop('drive_state', None)

        if request.url_root.startswith('https://'):
            redirect_uri = 'https://office-academic.juooa.cloud/drive/callback'
        else:
            redirect_uri = 'http://localhost:5000/drive/callback'
        
        logger.info(f"🔍 Drive OAuth redirect URI: {redirect_uri}")

        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=DRIVE_SCOPES,
            redirect_uri=redirect_uri
        )

        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )

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
        
        if session.get('drive_state') != request.args.get('state'):
            logger.error("❌ State mismatch in Drive callback")
            flash('Authorization failed: State mismatch', 'error')
            return redirect(url_for('user_dashboard'))

        if request.url_root.startswith('https://'):
            redirect_uri = 'https://office-academic.juooa.cloud/drive/callback'
        else:
            redirect_uri = 'http://localhost:5000/drive/callback'
        
        logger.info(f"🔍 Drive callback redirect URI: {redirect_uri}")

        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=DRIVE_SCOPES,
            redirect_uri=redirect_uri,
            state=session['drive_state']
        )

        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        session['drive_creds'] = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': DRIVE_SCOPES
        }

        session.pop('drive_state', None)

        logger.info(f"✅ Google Drive connected successfully for {session.get('email')}")
        flash('✅ Google Drive connected successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    except Exception as e:
        logger.error(f"❌ Drive callback error: {e}", exc_info=True)
        flash('Error connecting to Google Drive. Please try again.', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/connect-gmail')
@login_required
def connect_gmail():
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
@login_required
def drive_files():
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

@app.route('/api/drive/folder/<folder_id>')
@login_required
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
@login_required
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
        logger.error(f"Error searching Drive: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/drive/upload', methods=['POST'])
@login_required
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
@login_required
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

# ===================== EVENT REMINDER & SUBSCRIPTION ROUTES - FIXED =====================
@app.route('/set_reminder', methods=['POST'])
@login_required
def set_reminder():
    """Set a reminder for an event - FIXED VERSION"""
    try:
        data = request.get_json()
        event_id = data.get('event_id')
        reminder_date = data.get('reminder_date')
        reminder_time = data.get('reminder_time')
        
        # Log incoming request for debugging
        logger.info(f"Set reminder request - event_id: {event_id}, date: {reminder_date}, time: {reminder_time}")
        
        if not all([event_id, reminder_date, reminder_time]):
            return jsonify({
                'error': 'Missing required fields: event_id, reminder_date, and reminder_time are required', 
                'success': False
            }), 400
        
        # Validate event ID
        try:
            event = db.events.find_one({'_id': ObjectId(event_id)})
        except Exception as e:
            logger.error(f"Invalid event ID format: {event_id}")
            return jsonify({'error': 'Invalid event ID format', 'success': False}), 400
            
        if not event:
            logger.error(f"Event not found: {event_id}")
            return jsonify({'error': 'Event not found', 'success': False}), 404
        
        # Get user
        user = db.users.find_one({'email': session['email']})
        if not user:
            logger.error(f"User not found: {session['email']}")
            return jsonify({'error': 'User not found', 'success': False}), 404
        
        # Parse reminder datetime
        try:
            # Handle DD-MM-YYYY format if needed
            if '-' in reminder_date and len(reminder_date.split('-')[0]) == 2:
                # Convert DD-MM-YYYY to YYYY-MM-DD
                day, month, year = reminder_date.split('-')
                if len(year) == 4 and len(month) == 2 and len(day) == 2:
                    reminder_date = f"{year}-{month}-{day}"
            
            # Ensure time has seconds
            if len(reminder_time.split(':')) == 2:
                reminder_time = f"{reminder_time}:00"
            
            reminder_datetime_str = f"{reminder_date} {reminder_time}"
            reminder_datetime = datetime.strptime(reminder_datetime_str, '%Y-%m-%d %H:%M:%S')
            
            # Localize to IST
            reminder_datetime = IST.localize(reminder_datetime)
            
        except Exception as e:
            logger.error(f"Date parsing error: {e}")
            return jsonify({'error': f'Invalid date/time format. Use YYYY-MM-DD and HH:MM: {str(e)}', 'success': False}), 400
        
        # Check if reminder is in the future
        now = get_indian_time()
        if reminder_datetime <= now:
            return jsonify({'error': 'Reminder time must be in the future', 'success': False}), 400
        
        # Check for existing reminder
        existing = db.event_reminders.find_one({
            'user_id': user['_id'],
            'event_id': event['_id']
        })
        
        # Save reminder to database
        if existing:
            # Update existing reminder
            db.event_reminders.update_one(
                {'_id': existing['_id']},
                {
                    '$set': {
                        'reminder_datetime': reminder_datetime,
                        'sent': False,
                        'updated_at': now
                    }
                }
            )
            message = 'Reminder updated successfully'
            action = 'updated'
            logger.info(f"Updated reminder for user {session['email']} - Event: {event['event_name']}")
        else:
            # Create new reminder
            result = db.event_reminders.insert_one({
                'user_id': user['_id'],
                'event_id': event['_id'],
                'reminder_datetime': reminder_datetime,
                'sent': False,
                'created_at': now,
                'attempt_count': 0
            })
            message = 'Reminder set successfully'
            action = 'set'
            logger.info(f"Created new reminder for user {session['email']} - Event: {event['event_name']}")
        
        # Send confirmation email
        try:
            msg = Message(
                subject=f"✅ Reminder {action.capitalize()}: {event['event_name']}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[user['email']]
            )
            
            # Simple plain text version for reliability
            msg.body = f"""
========================================
        REMINDER CONFIRMATION
========================================

Event: {event['event_name']}
Event Date: {event['event_date']}
Event Time: {event.get('event_time', 'All Day')}
Venue: {event['venue']}

Your reminder is set for: {reminder_datetime.strftime('%d %B %Y at %I:%M %p')} IST

We'll send you a reminder email at the scheduled time.

View all events: {request.url_root}jainevents

========================================
Jain University Portal - Office of Academics
========================================
            """
            
            # HTML version
            msg.html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: #04043a; color: #FFD700; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .content {{ background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }}
                    .event-details {{ background: white; padding: 15px; border-radius: 8px; margin: 15px 0; }}
                    .reminder-box {{ background: #e8f4fd; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #0056b3; }}
                    .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
                    .button {{ display: inline-block; background: #04043a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>✅ Reminder {action.capitalize()}</h1>
                    </div>
                    <div class="content">
                        <h2 style="color: #04043a;">{event['event_name']}</h2>
                        
                        <div class="event-details">
                            <p><strong>📅 Event Date:</strong> {event['event_date']}</p>
                            <p><strong>⏰ Event Time:</strong> {event.get('event_time', 'All Day')}</p>
                            <p><strong>📍 Venue:</strong> {event['venue']}</p>
                            <p><strong>🏢 Department:</strong> {event.get('department', 'N/A')}</p>
                            <p><strong>🏫 School:</strong> {event.get('school', 'N/A')}</p>
                        </div>
                        
                        <div class="reminder-box">
                            <p style="margin: 0; color: #0056b3;">
                                <strong>⏰ Your reminder is set for:</strong><br>
                                <span style="font-size: 18px; font-weight: bold;">{reminder_datetime.strftime('%d %B %Y at %I:%M %p')} IST</span>
                            </p>
                        </div>
                        
                        <p>We'll send you a reminder email at the scheduled time.</p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{request.url_root}jainevents" class="button">View All Events</a>
                        </div>
                    </div>
                    <div class="footer">
                        <p>Jain University Portal - Office of Academics</p>
                        <p>Confirmation sent at: {now.strftime('%Y-%m-%d %I:%M %p')} IST</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            mail.send(msg)
            logger.info(f"✅ Confirmation email sent to {user['email']}")
            
        except Exception as email_error:
            logger.error(f"❌ Error sending confirmation email: {email_error}")
            # Don't fail the request if email fails - reminder is still saved
        
        return jsonify({
            'success': True,
            'message': f"{message}! A confirmation email has been sent to your inbox."
        })
        
    except Exception as e:
        logger.error(f"❌ Error setting reminder: {e}", exc_info=True)
        return jsonify({
            'error': f'Server error: {str(e)}', 
            'success': False
        }), 500

@app.route('/subscribe_to_event', methods=['POST'])
@login_required
def subscribe_to_event():
    """Subscribe to event updates"""
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
        
        existing = db.event_subscriptions.find_one({
            'user_id': user['_id'],
            'event_id': event['_id']
        })
        
        if existing:
            return jsonify({
                'success': True,
                'message': 'Already subscribed to this event'
            })
        
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
@login_required
def unsubscribe_from_event(event_id):
    """Unsubscribe from event updates"""
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
@login_required
def my_reminders():
    """View all user reminders"""
    try:
        notifications = get_user_notifications()
        
        user = db.users.find_one({'email': session['email']})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('user_dashboard'))
        
        reminders = list(db.event_reminders.find({
            'user_id': user['_id']
        }).sort('reminder_datetime', 1))
        
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
@login_required
def delete_reminder(reminder_id):
    """Delete a reminder"""
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
@login_required
def user_preferences():
    """Manage user preferences"""
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
    
    try:
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

@app.route('/submit_document', methods=['POST'])
@approval_required
def submit_document():
    """Office barriers submit documents for review"""
    if not is_office_barrier():
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        user = db.users.find_one({'email': session['email']})
        
        document_name = request.form.get('document_name')
        description = request.form.get('description')
        file = request.files.get('file')
        
        file_url = None
        file_id = None
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            file_url = '/' + filepath.replace('\\', '/')
        
        doc = {
            'user_id': user['_id'],
            'user_email': session['email'],
            'document_name': document_name,
            'description': description,
            'file_id': file_id,
            'file_url': file_url,
            'status': 'pending',
            'submitted_at': get_indian_time(),
            'reviewed_by': None,
            'reviewed_at': None,
            'comments': ''
        }
        
        result = db.office_documents.insert_one(doc)
        
        db.activity_logs.insert_one({
            'user_id': user['_id'],
            'user_email': session['email'],
            'action': 'document_upload',
            'details': f'Submitted document: {document_name}',
            'timestamp': get_indian_time(),
            'ip_address': request.remote_addr
        })
        
        flash('✅ Document submitted successfully', 'success')
        return redirect(url_for('core_dashboard'))
        
    except Exception as e:
        logger.error(f"Error submitting document: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/office_documents')
def office_documents():
    """Core and leaders can view all office barrier submissions"""
    if not is_core_or_leader():
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    try:
        documents = list(db.office_documents.find().sort('submitted_at', -1))
        
        for doc in documents:
            user = db.users.find_one({'_id': doc['user_id']})
            if user:
                doc['user_name'] = user['email'].split('@')[0]
                doc['user_type'] = user.get('user_type', 'N/A')
        
        online_users = list(db.users.find({
            'special_role': 'office_barrier',
            'is_online': True
        }))
        
        return render_template(
            'office_documents.html', 
            documents=documents,
            online_users=online_users
        )
        
    except Exception as e:
        logger.error(f"Error loading office documents: {e}")
        flash('Error loading documents', 'error')
        return redirect(url_for('home'))

@app.route('/activity_logs')
def activity_logs():
    """View activity logs of all users"""
    if not is_core_or_leader():
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    try:
        logs = list(db.activity_logs.find().sort('timestamp', -1).limit(100))
        
        online_users = list(db.users.find({
            'is_online': True
        }, {'email': 1, 'user_type': 1, 'special_role': 1}))
        
        return render_template(
            'activity_logs.html',
            logs=logs,
            online_users=online_users
        )
        
    except Exception as e:
        logger.error(f"Error loading activity logs: {e}")
        flash('Error loading logs', 'error')
        return redirect(url_for('home'))

# ===================== ADMIN DASHBOARD =====================
@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('login'))

    try:
        logger.info(f"Admin {session.get('email')} accessing dashboard")
        
        try:
            total_count = db.users.count_documents({})
            logger.info(f"Total users in database: {total_count}")
        except Exception as db_error:
            logger.error(f"Database error: {db_error}")
            flash('Database connection error. Please check MongoDB.', 'error')
            return render_template(
                'admin_dashboard.html', 
                users=[],
                total_users=0,
                pending_users=0,
                approved_users=0
            )
        
        search_query = request.args.get('search', '')
        type_filter = request.args.get('type_filter', '')
        role_filter = request.args.get('role_filter', '')
        
        query = {}
        
        if search_query:
            query['email'] = {'$regex': search_query, '$options': 'i'}
            logger.info(f"Searching for: {search_query}")
        
        if type_filter:
            if type_filter == 'core':
                query['$or'] = [
                    {'user_type': 'core'},
                    {'special_role': 'office_barrier'}
                ]
                logger.info("Filtering for core team members")
            else:
                query['user_type'] = type_filter
                logger.info(f"Filtering user_type: {type_filter}")
            
        if role_filter:
            if role_filter == 'office_barrier':
                query['$or'] = [
                    {'user_type': 'core'},
                    {'special_role': 'office_barrier'}
                ]
                logger.info("Filtering for office barriers")
            elif role_filter == 'leader':
                query['special_role'] = 'leader'
                logger.info("Filtering for leaders")
            elif role_filter == 'none':
                query['special_role'] = {'$in': [None, '']}
                logger.info("Filtering for users with no special role")
            else:
                query['special_role'] = role_filter
                logger.info(f"Filtering special_role: {role_filter}")
        
        logger.info(f"Database query: {query}")
        
        users = list(db.users.find(query).sort('created_at', -1))
        
        logger.info(f"Found {len(users)} users matching query")
        
        total_users = len(users)
        pending_users = len([u for u in users if not u.get('approved', False)])
        approved_users = len([u for u in users if u.get('approved', False)])
        
        for user in users[:5]:
            logger.info(f"User: {user.get('email')} - Approved: {user.get('approved', False)} - Type: {user.get('user_type')} - Role: {user.get('special_role')}")
        
        for user in users:
            user.setdefault('approved', False)
            user.setdefault('user_type', 'faculty')
            user.setdefault('special_role', None)
            
            if user.get('user_type') == 'core' or user.get('special_role') == 'office_barrier':
                user['display_type'] = 'Core Team'
                user['display_special'] = 'Office Barrier'
            elif user.get('special_role') == 'leader':
                user['display_type'] = 'Leader'
                user['display_special'] = 'Leader'
            else:
                user['display_type'] = user.get('user_type', 'faculty').capitalize()
                user['display_special'] = user.get('special_role', 'None').capitalize() if user.get('special_role') else 'None'
        
        return render_template(
            'admin_dashboard.html', 
            users=users,
            total_users=total_users,
            pending_users=pending_users,
            approved_users=approved_users
        )
        
    except Exception as e:
        logger.error(f"Error in admin_dashboard: {e}", exc_info=True)
        flash(f'Error loading dashboard: {str(e)[:100]}', 'error')
        return render_template(
            'admin_dashboard.html', 
            users=[],
            total_users=0,
            pending_users=0,
            approved_users=0
        )

@app.route('/update_user/<user_id>', methods=['POST'])
def update_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('login'))

    try:
        email = request.form['email']
        role = request.form['role']
        user_type = request.form.get('user_type', 'faculty')
        special_role = request.form.get('special_role', '')
        approved = request.form.get('approved', 'false') == 'true'
        
        logger.info(f"Updating user {user_id}:")
        logger.info(f"  Email: {email}")
        logger.info(f"  Role: {role}")
        logger.info(f"  User Type: {user_type}")
        logger.info(f"  Special Role: {special_role}")
        logger.info(f"  Approved: {approved}")
        
        if special_role == '':
            special_role = None
        
        if role not in ['user', 'admin']:
            role = 'user'
        
        if user_type not in ['faculty', 'core']:
            user_type = 'faculty'
        
        if special_role and special_role not in ['office_barrier', 'leader']:
            special_role = None
        
        if special_role == 'office_barrier':
            user_type = 'core'
        elif special_role == 'leader':
            user_type = 'faculty'
        elif user_type == 'core':
            special_role = 'office_barrier'
        
        update_data = {
            'email': email, 
            'role': role,
            'user_type': user_type,
            'special_role': special_role,
            'approved': approved,
            'updated_at': get_indian_time()
        }
        
        logger.info(f"Update data: {update_data}")
        
        result = db.users.update_one(
            {'_id': ObjectId(user_id)}, 
            {'$set': update_data}
        )
        
        logger.info(f"Update result: {result.modified_count} documents modified")
        
        user = db.users.find_one({'_id': ObjectId(user_id)})
        core_chat = db.chat_groups.find_one({'group_type': 'core_team'})
        
        if user_type == 'core' or special_role == 'office_barrier':
            if core_chat:
                db.chat_groups.update_one(
                    {'_id': core_chat['_id']},
                    {'$addToSet': {'members': ObjectId(user_id)}}
                )
                logger.info(f"Added user {user_id} to core team chat")
            else:
                db.chat_groups.insert_one({
                    'name': 'Office of Academic Barriers - Core Team',
                    'group_type': 'core_team',
                    'description': 'Automatic group for all core team members',
                    'created_at': get_indian_time(),
                    'members': [ObjectId(user_id)],
                    'created_by': ObjectId(user_id)
                })
                logger.info(f"Created core team chat with user {user_id}")
        else:
            if core_chat:
                db.chat_groups.update_one(
                    {'_id': core_chat['_id']},
                    {'$pull': {'members': ObjectId(user_id)}}
                )
                logger.info(f"Removed user {user_id} from core team chat")
        
        if approved:
            try:
                role_msg = ""
                if special_role == 'office_barrier':
                    role_msg = "You have been assigned to the Office of Academic Barriers (Core Team)."
                elif special_role == 'leader':
                    role_msg = "You have been assigned as a Leader."
                else:
                    role_msg = "You now have full faculty access."
                
                msg = Message(
                    subject="✅ Account Updated - Access Modified",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[email]
                )
                
                msg.body = f"""
Account Updated

Dear User,

Your account at Jain University Portal - Office of Academics has been updated by the administrator.

New Role Details:
- Email: {email}
- User Type: {user_type.capitalize()}
- Special Role: {special_role.capitalize() if special_role else 'None'}
- Approval Status: {'Approved' if approved else 'Pending'}

{role_msg}

Login to Portal: {request.url_root}login

Jain University Portal - Office of Academics
                """
                mail.send(msg)
                logger.info(f"Notification email sent to {email}")
            except Exception as e:
                logger.error(f"Error sending update email: {e}")
        
        flash('✅ User updated successfully.', 'success')
        
    except Exception as e:
        logger.error(f"Error updating user: {e}", exc_info=True)
        flash(f'Error updating user: {str(e)[:100]}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('login'))

    try:
        user = db.users.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        if user['email'] == session.get('email'):
            flash('You cannot delete your own account', 'error')
            return redirect(url_for('admin_dashboard'))
        
        user_email = user['email']
        
        db.users.delete_one({'_id': ObjectId(user_id)})
        db.user_files.delete_many({'user_email': user_email})
        db.event_reminders.delete_many({'user_id': ObjectId(user_id)})
        db.event_subscriptions.delete_many({'user_id': ObjectId(user_id)})
        db.office_documents.delete_many({'user_id': ObjectId(user_id)})
        
        db.chat_groups.update_many(
            {'members': ObjectId(user_id)},
            {'$pull': {'members': ObjectId(user_id)}}
        )
        
        db.user_preferences.delete_many({'email': user_email})
        db.user_navbars.delete_many({'user_email': user_email})
        db.activity_logs.delete_many({'user_id': ObjectId(user_id)})
        
        flash(f'✅ User {user_email} deleted successfully along with all associated data.', 'success')
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
                msg.body = f"""
Thank you for subscribing!

You'll now receive updates, articles, and event highlights directly to your inbox.

If you did not request this, please ignore this message.

This is an automated message from Jain University Newsletter system.
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

@app.route("/api/events/today")
def get_today_events():
    try:
        today = get_today_ist_string()
        all_events = list(db.events.find({}))
        events_data = []
        for event in all_events:
            event_date = normalize_date(event.get("event_date", ""))
            end_date = normalize_date(event.get("end_date", "")) if event.get("end_date") else ""
            if event_date == today or (end_date and event_date <= today <= end_date):
                events_data.append({
                    "id": str(event["_id"]),
                    "event_name": event.get("event_name", ""),
                    "event_date": event_date,
                    "event_time": event.get("event_time", "All Day"),
                    "venue": event.get("venue", "TBA"),
                })
        return jsonify(events_data)
    except Exception as e:
        logger.error(f"Error fetching today events: {e}")
        return jsonify([])
@app.route("/debug/events")
def debug_events():
    try:
        today_str = get_today_ist_string()
        utc_now = datetime.utcnow()
        ist_now = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(IST)
        events = list(db.events.find({}).limit(15))
        samples = []
        for ev in events:
            raw = ev.get("event_date", "NO_DATE")
            norm = normalize_date(str(raw))
            samples.append({
                "name": ev.get("event_name", ""),
                "raw_date": str(raw),
                "normalized": norm,
                "is_today": norm == today_str,
                "is_future": norm > today_str if norm else False,
            })
        return jsonify({
            "server_utc_time": utc_now.strftime("%Y-%m-%d %H:%M:%S"),
            "server_ist_time": ist_now.strftime("%Y-%m-%d %H:%M:%S"),
            "today_ist": today_str,
            "total_events": db.events.count_documents({}),
            "events_today": sum(1 for s in samples if s["is_today"]),
            "events_future": sum(1 for s in samples if s["is_future"]),
            "event_samples": samples,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
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
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return "File not found", 404

# ===================== NEWSLETTER VIEW ROUTE =====================
@app.route('/newsletter_view/<newsletter_id>')
def newsletter_view(newsletter_id):
    """
    View a single newsletter article - PUBLIC ACCESS (no login required)
    This allows users to view newsletters even if not logged in
    """
    try:
        # Get newsletter from database
        news = db.newsletters.find_one({'_id': ObjectId(newsletter_id)})
        
        if not news:
            flash('Newsletter not found', 'error')
            return redirect(url_for('newsletter_page'))
        
        # Convert ObjectId to string for template
        news['_id'] = str(news['_id'])
        
        # Format date for display
        if news.get('uploaded_at'):
            if isinstance(news['uploaded_at'], datetime):
                news['formatted_date'] = news['uploaded_at'].strftime('%B %d, %Y')
            else:
                news['formatted_date'] = str(news['uploaded_at'])
        
        # Get user info if logged in (for navbar display)
        user_email = session.get('email')
        user_navbar = []
        if user_email:
            user_navbar = get_user_navbar(user_email)
        
        # Render the newsletter detail template
        return render_template(
            'newsletter_detail.html',
            news=news,
            user_logged_in='email' in session,
            user_email=user_email,
            user_navbar=user_navbar
        )
        
    except Exception as e:
        logger.error(f"Error viewing newsletter: {e}", exc_info=True)
        flash('Error loading newsletter', 'error')
        return redirect(url_for('newsletter_page'))

@app.route('/newsletters')
def newsletter_page():
    """
    Newsletter listing page - PUBLIC ACCESS (no login required)
    Shows all newsletters in a grid format
    """
    try:
        # Get all newsletters, sorted by date (newest first)
        records = list(db.newsletters.find().sort('uploaded_at', -1))
        
        # Format dates for display
        for article in records:
            article['_id'] = str(article['_id'])
            if article.get('uploaded_at'):
                if isinstance(article['uploaded_at'], datetime):
                    article['formatted_date'] = article['uploaded_at'].strftime('%B %d, %Y')
                else:
                    article['formatted_date'] = str(article['uploaded_at'])
        
        # Get user info if logged in
        user_email = session.get('email')
        user_navbar = []
        if user_email:
            user_navbar = get_user_navbar(user_email)
        
        return render_template(
            'newsletter_page.html',
            records=records,
            user_logged_in='email' in session,
            user_email=user_email,
            user_navbar=user_navbar
        )
        
    except Exception as e:
        logger.error(f"Error in newsletter_page: {e}", exc_info=True)
        flash('Error loading newsletters', 'error')
        return render_template(
            'newsletter_page.html',
            records=[],
            user_logged_in='email' in session,
            user_email=session.get('email')
        )

# ===================== DEBUG ROUTES =====================
@app.route('/debug/users')
def debug_users():
    """Debug route to check user data"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        users = list(db.users.find({}))
        
        user_list = []
        for user in users:
            user_list.append({
                'id': str(user.get('_id')),
                'email': user.get('email'),
                'role': user.get('role'),
                'user_type': user.get('user_type'),
                'special_role': user.get('special_role'),
                'approved': user.get('approved', False),
                'created_at': str(user.get('created_at')) if user.get('created_at') else None
            })
        
        return jsonify({
            'total_users': len(users),
            'users': user_list,
            'database': str(db),
            'collection': 'users'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/db')
def debug_db():
    """Debug database connection"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        db_status = {
            'connected': True,
            'collections': list(db.list_collection_names()),
            'users_count': db.users.count_documents({}),
            'config': {
                'MONGO_URI': app.config.get('MONGO_URI', 'Not set')[0:50] + '...' if app.config.get('MONGO_URI') else 'Not set',
                'MONGO_DBNAME': app.config.get('MONGO_DBNAME', 'Not set')
            }
        }
        
        return jsonify(db_status)
    except Exception as e:
        return jsonify({'error': str(e), 'connected': False}), 500

@app.route('/debug/create_test_user')
def create_test_user():
    """Create a test user for debugging"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        test_email = f"test.admin{random.randint(100,999)}@jainuniversity.ac.in"
        
        existing = db.users.find_one({'email': test_email})
        if existing:
            return jsonify({
                'message': 'Test user already exists',
                'user': {
                    'email': existing.get('email'),
                    'role': existing.get('role'),
                    'approved': existing.get('approved', False)
                }
            })
        
        user_data = {
            'email': test_email,
            'password': generate_password_hash('test123'),
            'role': 'user',
            'user_type': 'faculty',
            'special_role': None,
            'approved': False,
            'is_online': False,
            'last_seen': get_indian_time(),
            'profile': {
                'department': 'Test Department',
                'school': 'Test School',
                'phone': ''
            },
            'created_at': get_indian_time()
        }
        
        result = db.users.insert_one(user_data)
        
        return jsonify({
            'message': 'Test user created successfully',
            'user': {
                'id': str(result.inserted_id),
                'email': test_email,
                'password': 'test123',
                'approved': False
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/setup/admin')
def setup_admin():
    """Emergency route to create admin user if none exist"""
    try:
        admin_exists = db.users.find_one({'role': 'admin'})
        
        if admin_exists:
            return jsonify({
                'message': 'Admin already exists',
                'admin_email': admin_exists.get('email')
            })
        
        admin_email = 'admin@jainuniversity.ac.in'
        admin_password = 'admin123'
        
        hashed_pw = generate_password_hash(admin_password)
        
        db.users.insert_one({
            'email': admin_email,
            'password': hashed_pw,
            'role': 'admin',
            'user_type': 'admin',
            'special_role': None,
            'approved': True,
            'is_online': True,
            'last_seen': get_indian_time(),
            'created_at': get_indian_time()
        })
        
        return jsonify({
            'message': 'Admin user created successfully!',
            'email': admin_email,
            'password': admin_password,
            'note': 'Please change the password immediately after login!'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===================== ERROR HANDLERS =====================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Maximum size is 50MB.', 'error')
    return redirect(request.referrer or url_for('home'))

# ===================== TEST EMAIL ROUTE =====================
@app.route('/test-email')
def test_email():
    """Test route to verify email configuration"""
    try:
        msg = Message(
            subject="Test Email from Reminder System",
            sender=app.config['MAIL_USERNAME'],
            recipients=[app.config['MAIL_USERNAME']]  # Send to yourself
        )
        msg.body = "This is a test email to verify the reminder system is working correctly."
        msg.html = "<h1>Test Email</h1><p>This is a test email to verify the reminder system is working correctly.</p>"
        mail.send(msg)
        return jsonify({"success": True, "message": "Test email sent successfully"})
    except Exception as e:
        logger.error(f"Test email failed: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ===================== RUN APP =====================
if __name__ == '__main__':
    # Create database indexes
    create_indexes()
    
    # ✅ Only use APScheduler in LOCAL development, NOT on Hostinger
    import platform
    is_local = os.environ.get('FLASK_ENV', 'production') == 'development'
    
    if is_local:
        from apscheduler.schedulers.background import BackgroundScheduler
        
        scheduler = BackgroundScheduler(timezone=IST)

        @scheduler.scheduled_job('interval', seconds=30, id='reminder_check')
        def scheduled_send_event_reminders():
            with app.app_context():
                try:
                    send_event_reminders()
                except Exception as e:
                    logger.error(f"[SCHEDULER ERROR] {e}")

        @scheduler.scheduled_job('cron', hour=7, minute=0, id='daily_digest')
        def scheduled_send_daily_event_emails():
            with app.app_context():
                try:
                    send_daily_event_emails()
                except Exception as e:
                    logger.error(f"[SCHEDULER ERROR] {e}")

        scheduler.start()
        logger.info("✅ Scheduler started (LOCAL DEV MODE)")
    else:
        logger.info("⚠️ Running on production - use /cron/send-reminders endpoint instead of APScheduler")
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=is_local, use_reloader=False)