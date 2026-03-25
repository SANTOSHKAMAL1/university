import re
import os
import logging
import random
import json
import platform
from functools import wraps
from datetime import datetime, timedelta, date
from io import StringIO, BytesIO

# ── Environment ────────────────────────────────────────────────────────
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
from dotenv import load_dotenv
load_dotenv()

# ── Flask & extensions ─────────────────────────────────────────────────
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, send_from_directory, jsonify, json as flask_json)
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

# ── Database / serialization ───────────────────────────────────────────
from bson import ObjectId
import pytz
import pandas as pd
import requests as http_requests

# ── Google OAuth ───────────────────────────────────────────────────────
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# ── APScheduler ────────────────────────────────────────────────────────
from apscheduler.schedulers.background import BackgroundScheduler

# ── Groq (Jain AI) ────────────────────────────────────────────────────
from groq import Groq

# ── PDF extraction ─────────────────────────────────────────────────────
try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False
    logging.warning("PyMuPDF not installed — PDF text extraction disabled.")

# ══════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
#  FLASK APP INIT
# ══════════════════════════════════════════════════════════════════════
app = Flask(__name__)
from config import Config
app.config.from_object(Config)

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE']   = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

UPLOAD_FOLDER      = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf','docx','txt','png','jpg','jpeg','gif','xlsx','csv','xls'}
app.config['UPLOAD_FOLDER']      = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

mongo = PyMongo(app)
db    = mongo.db

app.config['MAIL_SERVER']         = 'smtp.gmail.com'
app.config['MAIL_PORT']           = 587
app.config['MAIL_USE_TLS']        = True
app.config['MAIL_USERNAME']       = 'info.loginpanel@gmail.com'
app.config['MAIL_PASSWORD']       = 'wedbfepklgtwtugf'
app.config['MAIL_DEFAULT_SENDER'] = 'info.loginpanel@gmail.com'
app.config['MAIL_MAX_EMAILS']     = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False
mail = Mail(app)

with app.app_context():
    try:
        test_msg = Message(subject="Reminder System Test",
                           sender=app.config['MAIL_USERNAME'],
                           recipients=[app.config['MAIL_USERNAME']])
        test_msg.body = "Test email – reminder system OK."
        mail.send(test_msg)
        logger.info("✅ Mail config test passed")
    except Exception as e:
        logger.error(f"❌ Mail config test failed: {e}")

_groq_key = os.getenv("GROQ_API_KEY", "").strip()
if not _groq_key:
    logger.warning("⚠️  GROQ_API_KEY not set — Jain AI features will return errors")
ai_client = Groq(api_key=_groq_key)

IST = pytz.timezone('Asia/Kolkata')
DRIVE_SCOPES = ['https://www.googleapis.com/auth/drive.file',
                'https://www.googleapis.com/auth/drive']
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# ══════════════════════════════════════════════════════════════════════
#  TIMEZONE HELPERS
# ══════════════════════════════════════════════════════════════════════
def make_timezone_aware(dt):
    if dt is None: return None
    if dt.tzinfo is None: return IST.localize(dt)
    return dt.astimezone(IST)

def make_timezone_naive(dt):
    if dt is None: return None
    if dt.tzinfo is not None: return dt.astimezone(IST).replace(tzinfo=None)
    return dt

def normalize_datetime_for_query(dt):
    if dt is None: return None
    return dt.replace(tzinfo=None) if dt.tzinfo else dt

def get_indian_time():
    return datetime.now(IST).replace(tzinfo=None)

def get_indian_time_aware():
    return datetime.now(IST)

def convert_to_ist(dt):
    if dt.tzinfo is None: dt = pytz.utc.localize(dt)
    return dt.astimezone(IST)

def get_today_ist_string():
    return datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(IST).strftime("%Y-%m-%d")

def normalize_date(date_str):
    if not date_str: return ""
    date_str = str(date_str).strip()
    if len(date_str) == 10 and date_str[4] == "-": return date_str
    for fmt in ["%Y-%m-%d","%d/%m/%Y","%d-%m-%Y","%m/%d/%Y","%Y/%m/%d"]:
        try: return datetime.strptime(date_str, fmt).strftime("%Y-%m-%d")
        except ValueError: continue
    return date_str

# ══════════════════════════════════════════════════════════════════════
#  DB INDEXES
# ══════════════════════════════════════════════════════════════════════
def create_indexes():
    try:
        db.users.create_index([('email',1)], unique=True)
        db.users.create_index([('approved',1)])
        db.users.create_index([('user_type',1)])
        db.users.create_index([('special_role',1)])
        db.users.create_index([('is_online',1)])
        db.users.create_index([('last_seen',-1)])
        db.events.create_index([('event_date',1)])
        db.events.create_index([('school',1)])
        db.events.create_index([('department',1)])
        db.event_reminders.create_index([('user_id',1)])
        db.event_reminders.create_index([('reminder_datetime',1)])
        db.event_reminders.create_index([('sent',1)])
        db.event_reminders.create_index([('sent',1),('reminder_datetime',1)])
        db.office_documents.create_index([('user_id',1)])
        db.office_documents.create_index([('status',1)])
        db.office_documents.create_index([('submitted_at',-1)])
        db.document_shares.create_index([('shared_by',1)])
        db.document_shares.create_index([('shared_with',1)])
        db.document_shares.create_index([('shared_at',-1)])
        db.chat_messages.create_index([('sender_id',1)])
        db.chat_messages.create_index([('receiver_id',1)])
        db.chat_messages.create_index([('group_id',1)])
        db.chat_messages.create_index([('timestamp',-1)])
        db.chat_groups.create_index([('group_type',1)])
        db.tasks.create_index([('assigned_to',1)])
        db.tasks.create_index([('assigned_by',1)])
        db.tasks.create_index([('status',1)])
        db.tasks.create_index([('due_date',1)])
        db.activity_logs.create_index([('user_id',1)])
        db.activity_logs.create_index([('timestamp',-1)])
        db.user_files.create_index([('user_email',1)])
        db.user_files.create_index([('uploaded_at',-1)])
        db.public_files.create_index([('uploaded_at',-1)])
        db.ugc_data.create_index([('uploaded_at',-1)])
        db.monthly_engagement.create_index([('uploaded_at',-1)])
        db.newsletters.create_index([('uploaded_at',-1)])
        db.direct_messages.create_index([('sender_id',1)])
        db.direct_messages.create_index([('receiver_id',1)])
        db.direct_messages.create_index([('timestamp',-1)])
        db.direct_messages.create_index([('read',1)])
        logger.info("✅ DB indexes created")
    except Exception as e:
        logger.error(f"❌ Index creation error: {e}")

# ══════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def _allowed(filename):
    return allowed_file(filename)

# ══════════════════════════════════════════════════════════════════════
#  AUTH DECORATORS
# ══════════════════════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'email' not in session:
            if request.path.startswith('/api/') or request.is_json or \
               request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'Not logged in'}), 401
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def approval_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'email' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Not logged in'}), 401
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        approved = session.get('approved', False)
        if not approved:
            user = db.users.find_one({'email': session['email']})
            if user:
                approved = user.get('approved', False)
                session['approved'] = approved
        if not approved:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Account pending approval'}), 403
            flash('⏳ Your account is pending admin approval.', 'warning')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated

def _login_required(f):
    return login_required(f)

def _core_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('email'):
            return redirect(url_for('login'))
        if not (session.get('user_type') == 'core' or
                session.get('special_role') == 'office_barrier' or
                session.get('role') == 'admin'):
            flash('Access denied. Core team only.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════════════
#  ROLE CHECKS
# ══════════════════════════════════════════════════════════════════════
def is_faculty():
    return (session.get('role') == 'user' and
            session.get('user_type') == 'faculty' and
            not session.get('special_role'))

def is_core_member():
    if session.get('special_role') in ['core','office_barrier'] or session.get('user_type') == 'core':
        return True
    if 'email' in session:
        user = db.users.find_one({'email': session['email']})
        if user and (user.get('special_role') in ['core','office_barrier'] or user.get('user_type') == 'core'):
            return True
    return False

def is_leader():
    if session.get('special_role') == 'leader':
        return True
    if 'email' in session:
        user = db.users.find_one({'email': session['email']})
        if user and user.get('special_role') == 'leader':
            return True
    return False

def is_core_or_leader():
    return is_core_member() or is_leader()

def is_office_barrier():
    return is_core_member()

def has_special_access():
    return is_core_or_leader()

# ══════════════════════════════════════════════════════════════════════
#  USER INFO HELPER
# ══════════════════════════════════════════════════════════════════════
def _get_user_info():
    return {
        'user_logged_in':   bool(session.get('email')),
        'user_email':       session.get('email', ''),
        'user_role':        session.get('role', 'user'),
        'user_type':        session.get('user_type', ''),
        'special_role':     session.get('special_role', ''),
        'approved':         session.get('approved', False),
        'user_department':  session.get('user_department', ''),
        'user_location':    session.get('user_location', ''),
    }

def _track_activity(action_description=None):
    email = session.get('email')
    if not email: return
    update = {'$set': {'last_seen': datetime.utcnow()}}
    if action_description:
        update['$inc'] = {'changes_made': 1}
        update['$push'] = {
            'activity_log': {
                'action': action_description,
                'at': datetime.utcnow(),
                'session_id': session.get('session_id', '')
            }
        }
    db.users.update_one({'email': email}, update)

# ══════════════════════════════════════════════════════════════════════
#  JAIN AI HELPERS
# ══════════════════════════════════════════════════════════════════════
def extract_text_from_file(file_url: str, max_chars: int = 4000) -> str:
    try:
        response = http_requests.get(file_url, timeout=15)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "")
        if "pdf" in content_type or file_url.lower().endswith(".pdf"):
            if PYMUPDF_AVAILABLE:
                doc = fitz.open(stream=response.content, filetype="pdf")
                text = "\n".join(page.get_text() for page in doc)
                doc.close()
                return text[:max_chars]
            return ""
        elif any(file_url.lower().endswith(ext) for ext in [".txt", ".csv", ".md"]):
            return response.text[:max_chars]
        elif file_url.lower().endswith(".docx"):
            try:
                from docx import Document
                doc = Document(BytesIO(response.content))
                return "\n".join(p.text for p in doc.paragraphs)[:max_chars]
            except ImportError:
                return ""
        return ""
    except Exception as e:
        logger.error(f"[Jain AI] File extraction error: {e}")
        return ""

def call_claude(prompt: str, system: str = None, max_tokens: int = 1000) -> str:
    try:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = ai_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        err = str(e).lower()
        if "auth" in err or "api key" in err or "unauthorized" in err:
            raise Exception("Invalid GROQ_API_KEY — please check your .env file")
        if "rate" in err:
            raise Exception("Jain AI rate limit reached — please try again in a moment")
        if "connect" in err:
            raise Exception("Could not connect to Jain AI — check your internet connection")
        raise Exception(f"Jain AI error: {str(e)}")

def call_claude_chat(messages: list, system: str = None, max_tokens: int = 800) -> str:
    try:
        groq_messages = []
        if system:
            groq_messages.append({"role": "system", "content": system})
        groq_messages.extend(messages)
        response = ai_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=groq_messages,
            max_tokens=max_tokens,
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        err = str(e).lower()
        if "auth" in err or "api key" in err or "unauthorized" in err:
            raise Exception("Invalid GROQ_API_KEY — please check your .env file")
        if "rate" in err:
            raise Exception("Jain AI rate limit reached — please try again in a moment")
        raise Exception(f"Jain AI error: {str(e)}")

# ══════════════════════════════════════════════════════════════════════
#  GOOGLE DRIVE HELPERS
# ══════════════════════════════════════════════════════════════════════
def get_drive_service():
    if 'drive_creds' not in session: return None
    try:
        c = session['drive_creds']
        required = ['token','refresh_token','token_uri','client_id','client_secret']
        for f in required:
            if f not in c: return None
        creds = Credentials(
            token=c['token'], refresh_token=c['refresh_token'],
            token_uri=c['token_uri'], client_id=c['client_id'],
            client_secret=c['client_secret'], scopes=c.get('scopes', DRIVE_SCOPES)
        )
        return build('drive', 'v3', credentials=creds)
    except Exception as e:
        logger.error(f"Drive service error: {e}")
        session.pop('drive_creds', None)
        return None

def make_file_public(service, file_id):
    try:
        service.permissions().create(fileId=file_id, body={'type':'anyone','role':'reader'}).execute()
        return True
    except Exception as e:
        logger.error(f"Make public error: {e}")
        return False

def make_file_private(service, file_id):
    try:
        perms = service.permissions().list(fileId=file_id).execute()
        for p in perms.get('permissions', []):
            if p.get('type') == 'anyone':
                service.permissions().delete(fileId=file_id, permissionId=p['id']).execute()
        return True
    except Exception as e:
        logger.error(f"Make private error: {e}")
        return False

def delete_drive_file(service, file_id):
    try:
        service.files().delete(fileId=file_id).execute()
        return True
    except Exception as e:
        logger.error(f"Delete drive file error: {e}")
        return False

def get_drive_stats():
    try:
        service = get_drive_service()
        if not service: return {'total_files': 0, 'recent_uploads': []}
        seven_days_ago = (get_indian_time() - timedelta(days=7)).isoformat()
        recent = service.files().list(
            q=f"createdTime >= '{seven_days_ago}' and trashed=false",
            pageSize=10, orderBy="createdTime desc",
            fields="files(id,name,mimeType,createdTime,parents,webViewLink)"
        ).execute()
        recent_files = recent.get('files', [])
        for f in recent_files:
            if f.get('parents'):
                try:
                    folder = service.files().get(fileId=f['parents'][0], fields='name').execute()
                    f['folder_name'] = folder.get('name', 'Root')
                except:
                    f['folder_name'] = 'Root'
            else:
                f['folder_name'] = 'Root'
        all_files = service.files().list(q="trashed=false", pageSize=1000, fields="files(id)").execute()
        return {'total_files': len(all_files.get('files', [])), 'recent_uploads': recent_files}
    except Exception as e:
        logger.error(f"Drive stats error: {e}")
        return {'total_files': 0, 'recent_uploads': []}

def get_user_navbar(email):
    try:
        nav = db.user_navbars.find_one({"user_email": email})
        return nav.get('items', []) if nav else []
    except:
        return []

# ══════════════════════════════════════════════════════════════════════
#  NOTIFICATION HELPERS
# ══════════════════════════════════════════════════════════════════════
def get_user_notifications():
    try:
        if 'email' not in session: return []
        user = db.users.find_one({'email': session['email']})
        if not user: return []
        notifications = []
        upcoming_reminders = list(db.event_reminders.find(
            {'user_id': user['_id'], 'sent': False}).sort('reminder_datetime',1).limit(5))
        for reminder in upcoming_reminders:
            event = db.events.find_one({'_id': reminder['event_id']})
            if event:
                notifications.append({
                    'type':'reminder','icon':'bell',
                    'title':f"Reminder: {event['event_name']}",
                    'message':f"Set for {reminder['reminder_datetime'].strftime('%d %b at %I:%M %p')}",
                    'time': reminder.get('created_at', get_indian_time()),
                    'link': url_for('jainevents')
                })
        subscriptions = list(db.event_subscriptions.find(
            {'user_id': user['_id']}).sort('subscribed_at',-1).limit(3))
        for sub in subscriptions:
            event = db.events.find_one({'_id': sub['event_id']})
            if event:
                notifications.append({
                    'type':'subscription','icon':'envelope',
                    'title':f"Subscribed to {event['event_name']}",
                    'message':f"Event on {event['event_date']}",
                    'time': sub.get('subscribed_at', get_indian_time()),
                    'link': url_for('jainevents')
                })
        recent_uploads = list(db.user_files.find(
            {'user_email': session['email']}).sort('uploaded_at',-1).limit(3))
        for upload in recent_uploads:
            notifications.append({
                'type':'file','icon':'file',
                'title':f"File uploaded: {upload['file_name']}",
                'message':f"Source: {upload.get('source','Local')}",
                'time': upload.get('uploaded_at', get_indian_time()),
                'link': url_for('my_files')
            })
        office_files = list(db.public_files.find().sort('uploaded_at',-1).limit(3))
        for file in office_files:
            notifications.append({
                'type':'office','icon':'building',
                'title':f"New Public File: {file['name']}",
                'message':'Uploaded by Office of Academics',
                'time': file.get('uploaded_at', get_indian_time()),
                'link': url_for('home')
            })
        if is_leader():
            shared_docs = list(db.document_shares.find(
                {'shared_with': user['_id']}).sort('shared_at',-1).limit(3))
            for share in shared_docs:
                sender = db.users.find_one({'_id': share['shared_by']})
                notifications.append({
                    'type':'share','icon':'share-alt',
                    'title':f"Document Shared: {share['document_name']}",
                    'message':f"From: {sender['email'].split('@')[0] if sender else 'Unknown'}",
                    'time': share.get('shared_at', get_indian_time()),
                    'link': url_for('leader_dashboard')
                })
        # unread direct messages
        unread_dms = db.direct_messages.count_documents({
            'receiver_id': user['_id'], 'read': False
        })
        if unread_dms > 0:
            notifications.append({
                'type':'message','icon':'comments',
                'title':f"You have {unread_dms} unread message(s)",
                'message':'Click Messages in the navbar to read',
                'time': get_indian_time(),
                'link': '#'
            })
        notifications.sort(key=lambda x: x['time'], reverse=True)
        return notifications[:10]
    except Exception as e:
        logger.error(f"Notifications error: {e}")
        return []

# ══════════════════════════════════════════════════════════════════════
#  CONTEXT PROCESSORS
# ══════════════════════════════════════════════════════════════════════
@app.context_processor
def inject_notifications():
    try:
        if 'email' in session and session.get('role') == 'user':
            return dict(notifications=get_user_notifications())
    except:
        pass
    return dict(notifications=[])

@app.context_processor
def inject_user_navbar():
    try:
        if 'email' in session and session.get('role') == 'user':
            return dict(user_navbar=get_user_navbar(session['email']))
    except:
        pass
    return dict(user_navbar=[])

@app.context_processor
def inject_current_time():
    return dict(now=get_indian_time())

# ══════════════════════════════════════════════════════════════════════
#  EMAIL NOTIFICATION FUNCTIONS
# ══════════════════════════════════════════════════════════════════════
def send_document_notification(sender, receiver, document, message):
    try:
        msg = Message(
            subject=f"📄 New Document for Review: {document['document_name']}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[receiver['email']])
        msg.body = (f"New Document for Review\n\nFrom: {sender['email']}\n"
                    f"Document: {document['document_name']}\nDescription: {document.get('description','')}\n\n"
                    f"Message:\n{message}\n\nView: {request.url_root}leader_dashboard")
        mail.send(msg)
    except Exception as e:
        logger.error(f"Doc notification error: {e}")

def send_task_notification(sender, receiver, task_title, due_date, attachment_msg="", priority="medium", description=""):
    try:
        msg = Message(subject=f"📋 New Task Assigned: {task_title}",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[receiver['email']])
        msg.body = (f"New Task Assigned\n\nFrom: {sender['email'].split('@')[0]}\n"
                    f"Task: {task_title}\nDue: {due_date}\nPriority: {priority}{attachment_msg}\n\n"
                    f"Description:\n{description}\n\nView: {request.url_root}core_dashboard")
        mail.send(msg)
    except Exception as e:
        logger.error(f"Task notification error: {e}")

def send_review_reply(reviewer, recipient, document, comments, status):
    try:
        msg = Message(
            subject=f"{'✅' if status=='approved' else '❌'} Document Review: {document['document_name']}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[recipient['email']])
        msg.body = (f"Document Review Complete\n\nDocument: {document['document_name']}\n"
                    f"Status: {status.upper()}\nReviewed by: {reviewer['email']}\n\n"
                    f"Comments:\n{comments}\n\nView: {request.url_root}core_dashboard")
        mail.send(msg)
    except Exception as e:
        logger.error(f"Review reply error: {e}")

def send_chat_notification(sender, receiver, message_preview):
    try:
        msg = Message(subject=f"💬 New message from {sender['email'].split('@')[0]}",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[receiver['email']])
        msg.body = (f"New message from {sender['email'].split('@')[0]}:\n\n"
                    f"\"{message_preview}...\"\n\nView: {request.url_root}core_dashboard")
        mail.send(msg)
    except Exception as e:
        logger.error(f"Chat notification error: {e}")

def notify_group_chat(sender, message_preview):
    try:
        online_core = list(db.users.find({
            'is_online': True,
            '$or': [{'user_type':'core'},{'special_role':'office_barrier'}],
            'email': {'$ne': sender['email']}
        }))
        for member in online_core:
            send_chat_notification(sender, member, message_preview)
    except Exception as e:
        logger.error(f"Group chat notify error: {e}")

def send_newsletter_email(title, content, image_filename, recipients):
    try:
        msg = Message(subject=title, sender=app.config['MAIL_USERNAME'], recipients=recipients)
        msg.html = (f"<html><body><div style='max-width:600px;margin:0 auto;font-family:Arial,sans-serif'>"
                    f"<div style='background:#04043a;color:#FFD700;padding:20px;text-align:center'><h1>{title}</h1></div>"
                    f"<div style='padding:20px'>{content}</div>"
                    f"<div style='text-align:center;font-size:12px;color:#666;padding:20px'>Jain University - Office of Academics</div>"
                    f"</div></body></html>")
        if image_filename:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            if os.path.exists(image_path):
                with app.open_resource(image_path) as img:
                    msg.attach(image_filename, "image/jpeg", img.read())
        mail.send(msg)
        logger.info(f"Newsletter '{title}' sent to {len(recipients)} recipients")
    except Exception as e:
        logger.error(f"Newsletter email error: {e}")
        raise

def send_completion_notification(assigner, completer, task, comment, attachment_url=None):
    try:
        attachment_msg = " with attachment" if attachment_url else ""
        msg = Message(subject=f"✅ Task Completed: {task['title']}",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[assigner['email']])
        msg.body = (f"Task Completed\n\nTask: {task['title']}\n"
                    f"Completed by: {completer['email'].split('@')[0]}\n"
                    f"Progress: {task.get('progress',0)}%{attachment_msg}\n\n"
                    f"Completion note:\n{comment if comment else 'Marked as completed'}\n\n"
                    f"View: {request.url_root}leader_dashboard")
        if attachment_url:
            msg.body += f"\n\nAttachment: {request.url_root.rstrip('/')}{attachment_url}"
        mail.send(msg)
    except Exception as e:
        logger.error(f"Completion notification error: {e}")

def record_login(email):
    import uuid
    sid = str(uuid.uuid4())[:8]
    session['session_id'] = sid
    db.users.update_one({'email': email}, {
        '$set': {'last_login': datetime.utcnow(), 'last_seen': datetime.utcnow(),
                 'is_active': True, 'session_id': sid},
        '$inc': {'total_logins': 1}
    })

def record_logout(email):
    db.users.update_one({'email': email}, {
        '$set': {'is_active': False, 'last_seen': datetime.utcnow(), 'session_id': ''}
    })

# ══════════════════════════════════════════════════════════════════════
#  SCHEDULED REMINDERS
# ══════════════════════════════════════════════════════════════════════
def send_event_reminders():
    try:
        now = get_indian_time_aware()
        now_naive = make_timezone_naive(now)
        reminders = list(db.event_reminders.find({'sent': False, 'reminder_datetime': {'$lte': now_naive}}))
        logger.info(f"[REMINDER] Found {len(reminders)} pending")
        sent_count = 0
        for reminder in reminders:
            try:
                reminder_id = reminder['_id']
                event = db.events.find_one({'_id': reminder['event_id']})
                if not event:
                    db.event_reminders.update_one({'_id': reminder_id}, {'$set': {'sent': True, 'error': 'Event not found'}})
                    continue
                user = db.users.find_one({'_id': reminder['user_id']})
                if not user:
                    db.event_reminders.update_one({'_id': reminder_id}, {'$set': {'sent': True, 'error': 'User not found'}})
                    continue
                reminder_dt = reminder.get('reminder_datetime')
                if isinstance(reminder_dt, datetime):
                    if reminder_dt.tzinfo is None:
                        reminder_dt = IST.localize(reminder_dt)
                    else:
                        reminder_dt = reminder_dt.astimezone(IST)
                msg = Message(subject=f"🔔 REMINDER: {event['event_name']}",
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[user['email']])
                msg.body = (f"EVENT REMINDER\n\nEvent: {event['event_name']}\n"
                            f"Date: {event['event_date']}\nTime: {event.get('event_time','All Day')}\n"
                            f"Venue: {event['venue']}\n\nDescription:\n{event.get('description','')}\n\n"
                            f"Scheduled reminder: {reminder_dt.strftime('%d %B %Y at %I:%M %p') if isinstance(reminder_dt, datetime) else ''} IST\n\n"
                            f"View: {request.url_root}jainevents")
                mail.send(msg)
                db.event_reminders.update_one({'_id': reminder_id},
                    {'$set': {'sent': True, 'sent_at': now_naive, 'email_sent': True}})
                sent_count += 1
            except Exception as e:
                logger.error(f"Reminder send error {reminder.get('_id')}: {e}")
                db.event_reminders.update_one({'_id': reminder['_id']},
                    {'$set': {'last_error': str(e), 'last_attempt': now_naive,
                              'attempt_count': reminder.get('attempt_count', 0) + 1}})
        logger.info(f"[REMINDER] Sent: {sent_count}")
    except Exception as e:
        logger.error(f"[REMINDER SYSTEM ERROR] {e}")

# ══════════════════════════════════════════════════════════════════════
#  JAIN AI ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route("/api/ai/summarize", methods=["POST"])
@login_required
def ai_summarize():
    try:
        data        = request.get_json(force=True) or {}
        doc_name    = data.get("document_name", "Document")
        description = data.get("description", "")
        file_url    = data.get("file_url", "")
        file_text   = extract_text_from_file(file_url) if file_url else ""
        context     = file_text or description or "No content available."
        prompt = (f"You are an assistant for a university student organisation (OOA, Jain University).\n"
                  f"Summarize the following document concisely for a team member.\n\n"
                  f"Document name: {doc_name}\nContent:\n{context[:3000]}\n\n"
                  f"Provide:\n1. Main topic (1 sentence)\n2. Key points (3-5 bullet points)\n"
                  f"3. Action items, if any\n\nBe concise and professional. Plain text only.")
        summary = call_claude(prompt, max_tokens=800)
        return jsonify({"success": True, "summary": summary})
    except Exception as e:
        logger.error(f"[Jain AI] summarize error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/task-help", methods=["POST"])
@login_required
def ai_task_help():
    try:
        data        = request.get_json(force=True) or {}
        title       = data.get("title", "")
        description = data.get("description", "")
        due_date    = data.get("due_date", "")
        priority    = data.get("priority", "medium")
        prompt = (f"You are a helpful assistant for a university student organisation (OOA, Jain University).\n"
                  f"A core team member needs help completing this task:\n\n"
                  f"Task: {title}\nDescription: {description}\nDue date: {due_date}\nPriority: {priority}\n\n"
                  f"Give a clear, practical step-by-step plan to complete this task on time.\n"
                  f"Be specific and actionable. Include time estimates if helpful. Plain text only.")
        help_text = call_claude(prompt, max_tokens=900)
        return jsonify({"success": True, "help": help_text})
    except Exception as e:
        logger.error(f"[Jain AI] task-help error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/chat", methods=["POST"])
@login_required
def ai_chat():
    try:
        data       = request.get_json(force=True) or {}
        message    = data.get("message", "")
        task_title = data.get("task_title", "")
        task_desc  = data.get("task_desc", "")
        history    = data.get("history", [])
        system = (f"You are Jain AI, an AI assistant embedded in the Jain University OOA "
                  f"(Office of Academics) dashboard. You help core team members and leaders "
                  f"with tasks, document reviews, planning, and general questions.\n"
                  f"Current context — Task: {task_title}. Description: {task_desc}.\n"
                  f"Be concise, helpful, and professional. Use plain text without markdown.")
        messages = []
        for h in history[-8:]:
            if h.get("role") in ("user", "assistant") and h.get("content"):
                messages.append({"role": h["role"], "content": h["content"]})
        if not messages or messages[-1]["role"] != "user":
            messages.append({"role": "user", "content": message})
        reply = call_claude_chat(messages, system=system, max_tokens=800)
        return jsonify({"success": True, "reply": reply})
    except Exception as e:
        logger.error(f"[Jain AI] chat error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/suggest-feedback", methods=["POST"])
@login_required
def ai_suggest_feedback():
    try:
        data         = request.get_json(force=True) or {}
        doc_name     = data.get("document_name", "")
        description  = data.get("description", "")
        submitted_by = data.get("submitted_by", "a core member")
        prompt = (f"You are a Jain University OOA leader reviewing a submitted document.\n\n"
                  f"Document: {doc_name}\nSubmitted by: {submitted_by}\nDescription: {description}\n\n"
                  f"Write professional, constructive feedback (150-200 words).\n"
                  f"- Be specific and actionable\n- Point out what is good and what needs improvement\n"
                  f"- Do NOT approve or reject — only provide feedback\n- Plain text, no markdown")
        feedback = call_claude(prompt, max_tokens=600)
        return jsonify({"success": True, "feedback": feedback})
    except Exception as e:
        logger.error(f"[Jain AI] suggest-feedback error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/suggest-task-desc", methods=["POST"])
@login_required
def ai_suggest_task_desc():
    try:
        data  = request.get_json(force=True) or {}
        title = data.get("title", "")
        prompt = (f"You are a Jain University OOA leader creating a task for a core team member.\n\n"
                  f"Task title: {title}\n\n"
                  f"Write a clear, detailed task description (3-5 sentences) that:\n"
                  f"- Explains what needs to be done\n- Mentions deliverables or outputs expected\n"
                  f"- Notes quality standards or guidelines\n- Is specific enough to act on\n\nPlain text only.")
        description = call_claude(prompt, max_tokens=400)
        return jsonify({"success": True, "description": description})
    except Exception as e:
        logger.error(f"[Jain AI] suggest-task-desc error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/analyze-task", methods=["POST"])
@login_required
def ai_analyze_task():
    try:
        data        = request.get_json(force=True) or {}
        title       = data.get("title", "")
        description = data.get("description", "")
        progress    = data.get("progress", 0)
        status      = data.get("status", "pending")
        prompt = (f"You are a Jain University OOA leader reviewing a task's progress.\n\n"
                  f"Task: {title}\nDescription: {description}\n"
                  f"Current progress: {progress}%\nStatus: {status}\n\n"
                  f"Provide a brief progress analysis (100-150 words):\n"
                  f"- Is the progress on track?\n- Any risks or concerns?\n"
                  f"- Recommendations (accept, request rework, follow up)?\n\nPlain text only.")
        analysis = call_claude(prompt, max_tokens=500)
        return jsonify({"success": True, "analysis": analysis})
    except Exception as e:
        logger.error(f"[Jain AI] analyze-task error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/suggest-rework-feedback", methods=["POST"])
@login_required
def ai_suggest_rework_feedback():
    try:
        data        = request.get_json(force=True) or {}
        title       = data.get("title", "")
        description = data.get("description", "")
        progress    = data.get("progress", 100)
        prompt = (f"You are a Jain University OOA leader requesting a rework on a completed task.\n\n"
                  f"Task: {title}\nDescription: {description}\nProgress reported: {progress}%\n\n"
                  f"Write specific, constructive rework instructions (100-150 words) that:\n"
                  f"- Clearly explain what was not satisfactory\n"
                  f"- State exactly what changes or additions are needed\n"
                  f"- Are respectful and professional in tone\n\nPlain text only.")
        feedback = call_claude(prompt, max_tokens=500)
        return jsonify({"success": True, "feedback": feedback})
    except Exception as e:
        logger.error(f"[Jain AI] suggest-rework-feedback error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/member-insight", methods=["POST"])
@login_required
def ai_member_insight():
    try:
        data     = request.get_json(force=True) or {}
        name     = data.get("name", "")
        email    = data.get("email", "")
        total    = data.get("total_documents", 0)
        pending  = data.get("pending", 0)
        approved = data.get("approved", 0)
        revision = data.get("revision", 0)
        prompt = (f"You are a Jain University OOA leader reviewing a core team member's performance.\n\n"
                  f"Member: {name} ({email})\n"
                  f"Documents submitted: {total}\nApproved: {approved}\n"
                  f"Pending: {pending}\nNeeds revision: {revision}\n\n"
                  f"Write a brief performance insight (100-150 words):\n"
                  f"- Highlight strengths\n- Note areas for improvement\n"
                  f"- Give 1-2 concrete suggestions for the leader\n\nPlain text, professional tone.")
        insight = call_claude(prompt, max_tokens=500)
        return jsonify({"success": True, "insight": insight})
    except Exception as e:
        logger.error(f"[Jain AI] member-insight error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ── NEW: AI dashboard stats summary ──
@app.route("/api/ai/dashboard-summary", methods=["POST"])
@login_required
def ai_dashboard_summary():
    """Generate an AI summary of the user's current dashboard stats."""
    try:
        data   = request.get_json(force=True) or {}
        stats  = data.get("stats", {})
        role   = data.get("role", "core")
        lines  = "\n".join(f"- {k.replace('_',' ').title()}: {v}" for k, v in stats.items())
        prompt = (f"You are Jain AI, assistant for Jain University OOA portal.\n"
                  f"The user is a {role} team member. Here are their current dashboard stats:\n\n"
                  f"{lines}\n\n"
                  f"Give a concise (120-180 word) performance snapshot:\n"
                  f"1. Overall status (healthy/needs attention)\n"
                  f"2. Top 2 priorities right now\n"
                  f"3. One practical recommendation\n"
                  f"Be encouraging but honest. Plain text only.")
        summary = call_claude(prompt, max_tokens=500)
        return jsonify({"success": True, "summary": summary})
    except Exception as e:
        logger.error(f"[Jain AI] dashboard-summary error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email')
        password = request.form.get('password')
        if not email.endswith('@jainuniversity.ac.in'):
            flash('Only @jainuniversity.ac.in emails allowed', 'error')
            return redirect(url_for('login'))
        user = db.users.find_one({'email': email})
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['email']        = email
            session['role']         = user['role']
            session['user_type']    = user.get('user_type', 'faculty')
            session['special_role'] = user.get('special_role', None)
            session['approved']     = user.get('approved', False)
            session['user_id']      = str(user['_id'])
            session.permanent       = True
            profile = user.get('profile', {}) or {}
            session['user_department'] = user.get('department','') or profile.get('department','')
            session['user_location']   = user.get('location','') or profile.get('location','')
            db.users.update_one({'email': email},
                {'$set': {'is_online': True, 'last_seen': get_indian_time()}})
            db.activity_logs.insert_one({
                'user_id': user['_id'], 'user_email': email,
                'action': 'login', 'details': 'User logged in',
                'timestamp': get_indian_time(), 'ip_address': request.remote_addr
            })
            if user['role'] == 'admin':
                flash('✅ Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                if not user.get('approved', False):
                    flash('⏳ Account pending approval. Limited access.', 'warning')
                else:
                    if user.get('special_role') == 'leader':
                        flash('✅ Leader login successful!', 'success')
                    elif user.get('user_type') == 'core' or user.get('special_role') == 'office_barrier':
                        flash('✅ Core Team login successful!', 'success')
                    else:
                        flash('✅ Login successful!', 'success')
                return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'email' in session:
        db.users.update_one({'email': session['email']},
            {'$set': {'is_online': False, 'last_seen': get_indian_time()}})
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

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
            session['otp']   = otp
            try:
                msg = Message('Your OTP for Registration',
                              sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your OTP is: {otp}\nValid for this session only.'
                mail.send(msg)
                session['step'] = 2
                flash('OTP sent to your email.', 'info')
            except Exception as e:
                logger.error(f"OTP send error: {e}")
                flash('Error sending OTP. Please try again.', 'error')
            return redirect(url_for('register'))
        elif session['step'] == 2:
            if request.form.get('otp') == session.get('otp'):
                session['otp_verified'] = True
                session['step'] = 3
                flash('OTP verified. Set your password.', 'success')
            else:
                flash('Invalid OTP.', 'error')
            return redirect(url_for('register'))
        elif session['step'] == 3:
            password   = request.form.get('password')
            department = request.form.get('department', '').strip()
            location   = request.form.get('location', '').strip()
            if not department:
                flash('Please select your department.', 'error')
                return redirect(url_for('register'))
            if not location:
                flash('Please select your campus.', 'error')
                return redirect(url_for('register'))
            email = session['email']
            assigned_leader = db.pre_assigned_leaders.find_one({'email': email})
            assigned_core   = db.pre_assigned_core.find_one({'email': email})
            hashed_pw = generate_password_hash(password)
            if assigned_leader:
                db.users.insert_one({
                    'email': email, 'password': hashed_pw, 'role': 'user',
                    'user_type': 'faculty', 'special_role': 'leader', 'approved': True,
                    'is_online': True, 'last_seen': get_indian_time(),
                    'department': department, 'location': location,
                    'profile': {'department': department, 'location': location,
                                'school': assigned_leader.get('school',''), 'phone': ''},
                    'created_at': get_indian_time()
                })
                db.pre_assigned_leaders.delete_one({'email': email})
                flash('✅ Registered as Leader! Please log in.', 'success')
            elif assigned_core:
                db.users.insert_one({
                    'email': email, 'password': hashed_pw, 'role': 'user',
                    'user_type': 'core', 'special_role': 'office_barrier', 'approved': True,
                    'is_online': True, 'last_seen': get_indian_time(),
                    'department': department, 'location': location,
                    'profile': {'department': department, 'location': location,
                                'school': assigned_core.get('department',''), 'phone': ''},
                    'created_at': get_indian_time()
                })
                db.pre_assigned_core.delete_one({'email': email})
                flash('✅ Registered as Core Team member! Please log in.', 'success')
            else:
                db.users.insert_one({
                    'email': email, 'password': hashed_pw, 'role': 'user',
                    'user_type': 'faculty', 'special_role': None, 'approved': False,
                    'is_online': True, 'last_seen': get_indian_time(),
                    'department': department, 'location': location,
                    'profile': {'department': department, 'location': location,
                                'school': '', 'phone': ''},
                    'created_at': get_indian_time()
                })
                flash('✅ Registration complete! Awaiting admin approval.', 'info')
            return redirect(url_for('login'))
    otp_sent     = session.get('step', 1) >= 2
    otp_verified = session.get('step', 1) == 3
    return render_template('register.html', otp_sent=otp_sent, otp_verified=otp_verified)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email is required', 'error')
            return redirect(url_for('forgot_password'))
        user = db.users.find_one({'email': email})
        if not user:
            flash('Email not registered.', 'error')
            return redirect(url_for('forgot_password'))
        otp    = str(random.randint(100000, 999999))
        now    = get_indian_time_aware()
        expiry = make_timezone_naive(now + timedelta(minutes=10))
        db.password_resets.update_one({'email': email},
            {'$set': {'otp': otp, 'expiry': expiry, 'attempts': 0,
                      'verified': False, 'created_at': make_timezone_naive(now)}},
            upsert=True)
        try:
            msg = Message('🔐 Password Reset OTP - Jain University',
                          sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Your OTP: {otp}\n\nValid for 10 minutes."
            mail.send(msg)
            session['reset_email'] = email
            flash('OTP sent to your email.', 'success')
            return redirect(url_for('verify_reset_otp'))
        except Exception as e:
            logger.error(f"Reset OTP send error: {e}")
            flash('Error sending OTP. Please try again.', 'error')
    return render_template('forgot_password.html')

@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if 'reset_email' not in session:
        flash('Please start the password reset process first.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        otp   = request.form.get('otp')
        email = session.get('reset_email')
        record = db.password_resets.find_one({'email': email})
        if not record:
            flash('No reset request found.', 'error')
            return redirect(url_for('forgot_password'))
        attempts = record.get('attempts', 0)
        if attempts >= 3:
            flash('Too many failed attempts. Please request a new OTP.', 'error')
            db.password_resets.delete_one({'email': email})
            session.pop('reset_email', None)
            return redirect(url_for('forgot_password'))
        db.password_resets.update_one({'email': email}, {'$inc': {'attempts': 1}})
        expiry = record.get('expiry')
        if expiry:
            expiry_aware = IST.localize(expiry) if expiry.tzinfo is None else expiry
            if get_indian_time_aware() > expiry_aware:
                flash('OTP expired. Please request a new one.', 'error')
                db.password_resets.delete_one({'email': email})
                session.pop('reset_email', None)
                return redirect(url_for('forgot_password'))
        if record.get('otp') == otp:
            db.password_resets.update_one({'email': email}, {'$set': {'verified': True}})
            session['reset_verified'] = True
            flash('OTP verified. Set your new password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            remaining = 3 - (attempts + 1)
            flash(f'Invalid OTP. {remaining} attempt(s) left.', 'error')
    return render_template('verify_otp.html')

@app.route('/resend-reset-otp')
def resend_reset_otp():
    if 'reset_email' not in session:
        flash('Please start the password reset process first.', 'error')
        return redirect(url_for('forgot_password'))
    email = session.get('reset_email')
    if not db.users.find_one({'email': email}):
        flash('Email not found.', 'error')
        session.pop('reset_email', None)
        return redirect(url_for('forgot_password'))
    otp    = str(random.randint(100000, 999999))
    now    = get_indian_time_aware()
    expiry = make_timezone_naive(now + timedelta(minutes=10))
    db.password_resets.update_one({'email': email},
        {'$set': {'otp': otp, 'expiry': expiry, 'attempts': 0,
                  'verified': False, 'created_at': make_timezone_naive(now)}},
        upsert=True)
    try:
        msg = Message('🔐 New Password Reset OTP - Jain University',
                      sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Your new OTP: {otp}\n\nValid for 10 minutes."
        mail.send(msg)
        flash('New OTP sent.', 'success')
    except Exception as e:
        logger.error(f"Resend OTP error: {e}")
        flash('Error sending OTP.', 'error')
    return redirect(url_for('verify_reset_otp'))

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session or 'reset_verified' not in session:
        flash('Please complete OTP verification first.', 'error')
        return redirect(url_for('forgot_password'))
    email = session.get('reset_email')
    if request.method == 'POST':
        new_password     = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not new_password or not confirm_password:
            flash('Both fields are required', 'error')
            return redirect(url_for('reset_password'))
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password'))
        if len(new_password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('reset_password'))
        result = db.users.update_one({'email': email},
            {'$set': {'password': generate_password_hash(new_password), 'updated_at': get_indian_time()}})
        if result.modified_count > 0:
            user = db.users.find_one({'email': email})
            db.activity_logs.insert_one({
                'user_id': user['_id'] if user else None, 'user_email': email,
                'action': 'password_reset', 'details': 'Password reset via forgot password',
                'timestamp': get_indian_time(), 'ip_address': request.remote_addr
            })
            db.password_resets.delete_one({'email': email})
            session.pop('reset_email', None)
            session.pop('reset_verified', None)
            try:
                msg = Message('✅ Password Changed - Jain University',
                              sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = "Your password has been changed successfully."
                mail.send(msg)
            except:
                pass
            flash('✅ Password changed! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error updating password.', 'error')
    return render_template('reset_password.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        email    = request.form['email']
        password = request.form['password']
        if not email.endswith('@jainuniversity.ac.in'):
            flash('Only @jainuniversity.ac.in emails allowed', 'error')
            return redirect(url_for('admin'))
        if db.users.find_one({'email': email}):
            flash('Email already registered', 'error')
            return redirect(url_for('admin'))
        db.users.insert_one({
            'email': email, 'password': generate_password_hash(password),
            'role': 'admin', 'user_type': 'admin', 'special_role': None,
            'approved': True, 'created_at': get_indian_time()
        })
        flash('✅ Admin registered. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('admin_register.html')

@app.route('/refresh_session')
def refresh_session():
    if 'email' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    try:
        user = db.users.find_one({'email': session['email']})
        if user:
            session['role']        = user['role']
            session['user_type']   = user.get('user_type', 'faculty')
            session['special_role']= user.get('special_role', None)
            session['approved']    = user.get('approved', False)
            session['user_id']     = str(user['_id'])
            return jsonify({'success': True, 'approved': session['approved'],
                            'special_role': session['special_role'],
                            'user_type': session['user_type']})
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  MAIN USER ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route("/home")
@login_required
def home():
    try:
        user      = db.users.find_one({"email": session["email"]})
        today_str = get_today_ist_string()
        all_events_raw = list(db.events.find({}).sort("event_date", 1))
        today_events = []; upcoming_events = []; all_upcoming = []
        for ev in all_events_raw:
            ev["_id"]       = str(ev["_id"])
            event_date      = normalize_date(ev.get("event_date", ""))
            end_date        = normalize_date(ev.get("end_date", "")) if ev.get("end_date") else ""
            ev["event_date"]= event_date
            if not event_date: continue
            if end_date and event_date <= today_str <= end_date:
                today_events.append(ev); all_upcoming.append(ev)
            elif event_date == today_str:
                today_events.append(ev); all_upcoming.append(ev)
            elif event_date > today_str:
                upcoming_events.append(ev); all_upcoming.append(ev)
        public_files  = list(db.public_files.find().sort("uploaded_at", -1).limit(20))
        user_type     = session.get("user_type", "faculty")
        special_role  = session.get("special_role", None)
        approved      = session.get("approved", False)
        can_upload    = approved and special_role in ["core","office_barrier","leader"]
        is_fac        = user_type == "faculty" and not special_role
        user_department = session.get("user_department", "")
        user_location   = session.get("user_location", "")
        if not user_department or not user_location:
            if user:
                profile = user.get("profile", {})
                user_department = profile.get("department","") or user.get("department","")
                user_location   = profile.get("location","") or user.get("location","")
                session["user_department"] = user_department
                session["user_location"]   = user_location
        return render_template("home.html",
            records=list(db.ugc_data.find().sort("uploaded_at",-1).limit(50)),
            monthly_records=list(db.monthly_engagement.find().sort("uploaded_at",-1).limit(50)),
            newsletter_records=list(db.newsletters.find().sort("uploaded_at",-1).limit(50)),
            events=all_upcoming, today_events=today_events,
            upcoming_events=upcoming_events, all_events=all_events_raw,
            today=today_str, public_files=public_files, user_logged_in=True,
            user_email=session.get("email",""), user_role=session.get("role",""),
            user_type=user_type, is_faculty=is_fac, can_upload=can_upload,
            approved=approved, special_role=special_role,
            user_department=user_department, user_location=user_location)
    except Exception as e:
        logger.error(f"Home route error: {e}", exc_info=True)
        flash("Error loading home page", "error")
        return redirect(url_for("login"))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/jainevents')
def jainevents():
    events = list(db.events.find().sort('event_date', 1))
    return render_template('jainevents.html', events=events)

@app.route('/monthlyengagement')
def monthlyengagement():
    events = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    return render_template('monthly.html', monthly_records=events)

@app.route('/ugc')
def ugc():
    return render_template('ugc.html')

@app.route('/base_user.html')
def base_user():
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    try:
        return render_template('base_user.html',
            notifications=get_user_notifications(),
            user_navbar=get_user_navbar(session['email']))
    except Exception as e:
        return render_template('base_user.html', notifications=[], user_navbar=[])

@app.route('/user')
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    try:
        user = db.users.find_one({'email': session['email']})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('login'))
        today = datetime.now().replace(hour=0,minute=0,second=0,microsecond=0)
        today_str    = today.strftime('%Y-%m-%d')
        next_week_str= (today + timedelta(days=7)).strftime('%Y-%m-%d')
        tomorrow_str = (today + timedelta(days=1)).strftime('%Y-%m-%d')
        today_events = list(db.events.find({"$or":[
            {"event_date": today_str},
            {"$and":[{"event_date":{"$lte":today_str}},{"end_date":{"$gte":today_str}}]}
        ]}).sort('event_date',1))
        upcoming_events = list(db.events.find(
            {"event_date":{"$gte":tomorrow_str,"$lte":next_week_str}}).sort('event_date',1))
        user_reminders = list(db.event_reminders.find({'user_id':user['_id']}).sort('reminder_datetime',1))
        for reminder in user_reminders:
            event = db.events.find_one({'_id': reminder['event_id']})
            if event: reminder['event'] = event
        drive_stats = {'total_files':0,'recent_uploads':[]}
        drive_connected = 'drive_creds' in session
        if drive_connected:
            try: drive_stats = get_drive_stats()
            except: drive_connected = False
        user_files   = list(db.user_files.find({'user_email':session['email']}).sort('uploaded_at',-1).limit(20))
        public_files = list(db.public_files.find().sort('uploaded_at',-1).limit(20))
        return render_template('user_dashboard.html',
            today_events=today_events, upcoming_events=upcoming_events,
            user_reminders=user_reminders, drive_stats=drive_stats,
            drive_connected=drive_connected, gmail_connected='gmail_creds' in session,
            public_files=public_files, user_navbar=get_user_navbar(session['email']),
            user_files=user_files, notifications=get_user_notifications())
    except Exception as e:
        logger.error(f"user_dashboard error: {e}", exc_info=True)
        flash('Error loading dashboard.', 'error')
        return render_template('user_dashboard.html',
            today_events=[], upcoming_events=[], user_reminders=[],
            drive_stats={'total_files':0,'recent_uploads':[]},
            drive_connected=False, gmail_connected=False, public_files=[],
            user_navbar=[], user_files=[], notifications=[])

# ══════════════════════════════════════════════════════════════════════
#  CORE DASHBOARD
# ══════════════════════════════════════════════════════════════════════
@app.route('/core_dashboard')
@approval_required
def core_dashboard():
    if not is_core_member():
        flash('Access denied. Core team members only.', 'error')
        return redirect(url_for('home'))
    try:
        user = db.users.find_one({'email': session['email']})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('home'))
        now            = get_indian_time_aware()
        now_naive      = make_timezone_naive(now)
        today_start_n  = make_timezone_naive(now.replace(hour=0,minute=0,second=0,microsecond=0))
        week_start_n   = make_timezone_naive((now - timedelta(days=now.weekday())).replace(hour=0,minute=0,second=0,microsecond=0))
        month_start_n  = make_timezone_naive(now.replace(day=1,hour=0,minute=0,second=0,microsecond=0))
        core_members = list(db.users.find({
            '$or':[{'user_type':'core'},{'special_role':'office_barrier'}],
            'approved': True}) or [])
        leaders = list(db.users.find({'special_role':'leader','approved':True}) or [])
        my_documents = list(db.office_documents.find({'user_id':user['_id']}).sort('submitted_at',-1) or [])
        total_docs     = len(my_documents)
        pending_count  = len([d for d in my_documents if d.get('status')=='pending'])
        approved_count = len([d for d in my_documents if d.get('status')=='approved'])
        revision_count = len([d for d in my_documents if d.get('status')=='revision'])
        rejected_count = len([d for d in my_documents if d.get('status')=='rejected'])
        docs_today     = db.office_documents.count_documents({'user_id':user['_id'],'submitted_at':{'$gte':today_start_n}})
        docs_this_week = db.office_documents.count_documents({'user_id':user['_id'],'submitted_at':{'$gte':week_start_n}})
        docs_this_month= db.office_documents.count_documents({'user_id':user['_id'],'submitted_at':{'$gte':month_start_n}})
        my_tasks = list(db.tasks.find({'assigned_to':user['_id']}).sort('created_at',-1) or [])
        for task in my_tasks:
            assigner = db.users.find_one({'_id': task['assigned_by']})
            task['assigned_by_name'] = assigner['email'].split('@')[0] if assigner else 'Unknown'
            task['progress']  = task.get('progress', 0)
            task['priority']  = task.get('priority', 'medium')
            task['status']    = task.get('status', 'pending')
            task['updates']   = task.get('updates', [])
            task['rework_comment'] = task.get('rework_comment', '')
            if task.get('due_date'):
                task['due_date_str'] = task['due_date'].strftime('%d %b %Y') if isinstance(task['due_date'], datetime) else str(task['due_date'])
            else:
                task['due_date_str'] = 'No due date'
        total_tasks        = len(my_tasks)
        pending_tasks      = len([t for t in my_tasks if t.get('status')=='pending'])
        in_progress_tasks  = len([t for t in my_tasks if t.get('status')=='in_progress'])
        completed_tasks    = len([t for t in my_tasks if t.get('status')=='completed'])
        high_priority_tasks= len([t for t in my_tasks if t.get('priority')=='high' and t.get('status')!='completed'])
        overdue_tasks      = len([t for t in my_tasks if t.get('due_date') and
                                   t.get('due_date') < now_naive and t.get('status') not in ['completed','accepted']])
        online_core = list(db.users.find({
            '$or':[{'user_type':'core'},{'special_role':'office_barrier'}],
            'approved': True, 'is_online': True}) or [])
        for member in core_members:
            if member.get('last_seen'):
                ls = member['last_seen']
                if isinstance(ls, datetime):
                    ls_aware = IST.localize(ls) if ls.tzinfo is None else ls
                    diff = now - ls_aware
                    if diff.days > 0:    member['last_seen_formatted'] = f"{diff.days}d ago"
                    elif diff.seconds//3600 > 0: member['last_seen_formatted'] = f"{diff.seconds//3600}h ago"
                    else: member['last_seen_formatted'] = f"{diff.seconds//60}m ago"
            else:
                member['last_seen_formatted'] = 'Never'
        recent_shares = []
        try:
            recent_shares = list(db.document_shares.find({
                '$or':[{'shared_by':user['_id']},{'shared_with':user['_id']}]
            }).sort('shared_at',-1).limit(10) or [])
            for share in recent_shares:
                sender = db.users.find_one({'_id': share['shared_by']})
                share['sender_name'] = sender['email'].split('@')[0] if sender else 'Unknown'
        except:
            recent_shares = []
        recent_activity = []
        for doc in my_documents[:5]:
            if doc.get('submitted_at'):
                recent_activity.append({'type':'document','title':doc['document_name'],
                    'time':doc['submitted_at'].strftime('%d %b, %I:%M %p'),
                    'status':doc.get('status','pending'),'icon':'file-upload','color':'blue'})
            if doc.get('reviewed_at'):
                recent_activity.append({'type':'document','title':doc['document_name'],
                    'time':doc['reviewed_at'].strftime('%d %b, %I:%M %p'),
                    'status':doc.get('status',''),'icon':'check-circle',
                    'color':'green' if doc['status']=='approved' else 'red'})
        for task in my_tasks[:5]:
            if task.get('created_at'):
                recent_activity.append({'type':'task','title':task['title'],
                    'time':task['created_at'].strftime('%d %b, %I:%M %p'),
                    'status':task.get('status','pending'),'icon':'tasks','color':'purple'})
        recent_activity.sort(key=lambda x: x['time'], reverse=True)
        return render_template('core_dashboard.html',
            user=user, core_members=core_members, leaders=leaders,
            my_documents=my_documents, my_tasks=my_tasks,
            pending_count=pending_count, approved_count=approved_count,
            revision_count=revision_count, rejected_count=rejected_count,
            total_docs=total_docs, docs_today=docs_today,
            docs_this_week=docs_this_week, docs_this_month=docs_this_month,
            total_tasks=total_tasks, pending_tasks=pending_tasks,
            in_progress_tasks=in_progress_tasks, completed_tasks=completed_tasks,
            high_priority_tasks=high_priority_tasks, overdue_tasks=overdue_tasks,
            recent_activity=recent_activity, online_core=online_core,
            recent_shares=recent_shares, chat_messages=[],
            now=get_indian_time())
    except Exception as e:
        logger.error(f"core_dashboard error: {e}", exc_info=True)
        flash('Error loading dashboard.', 'error')
        return render_template('core_dashboard.html',
            user={'email':session.get('email',''),'_id':'unknown'},
            core_members=[], leaders=[], my_documents=[], my_tasks=[],
            pending_count=0, approved_count=0, revision_count=0, rejected_count=0,
            total_docs=0, docs_today=0, docs_this_week=0, docs_this_month=0,
            total_tasks=0, pending_tasks=0, in_progress_tasks=0, completed_tasks=0,
            high_priority_tasks=0, overdue_tasks=0, recent_activity=[],
            online_core=[], recent_shares=[], chat_messages=[], now=get_indian_time())

@app.route('/upload_document', methods=['POST'])
@approval_required
def upload_document():
    if not is_core_member():
        return jsonify({'error': 'Access denied'}), 403
    try:
        user           = db.users.find_one({'email': session['email']})
        document_name  = request.form.get('document_name')
        description    = request.form.get('description')
        assigned_users = request.form.getlist('assigned_users')
        notify_users   = request.form.get('notify_users') == 'on'
        file           = request.files.get('file')
        file_url       = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
            name_part, ext_part = os.path.splitext(filename)
            unique_fn = f"{name_part}_{ts}{ext_part}"
            filepath  = os.path.join(app.config['UPLOAD_FOLDER'], unique_fn)
            file.save(filepath)
            file_url  = '/' + filepath.replace('\\', '/')
        if not assigned_users:
            all_users = (list(db.users.find({'special_role':'leader','approved':True})) +
                         list(db.users.find({'$or':[{'user_type':'core'},{'special_role':'office_barrier'}],'approved':True})))
            assigned_users = [str(u['_id']) for u in all_users]
        doc = {
            'user_id': user['_id'], 'user_email': session['email'],
            'document_name': document_name, 'description': description,
            'file_url': file_url,
            'assigned_reviewers': [ObjectId(uid) for uid in assigned_users],
            'status': 'pending', 'submitted_at': get_indian_time(),
            'reviewed_by': None, 'reviewed_at': None, 'comments': '', 'notified': False
        }
        result = db.office_documents.insert_one(doc)
        db.activity_logs.insert_one({
            'user_id': user['_id'], 'user_email': session['email'],
            'action': 'document_upload', 'details': f'Submitted: {document_name}',
            'timestamp': get_indian_time(), 'ip_address': request.remote_addr
        })
        if notify_users:
            for uid in assigned_users:
                reviewer = db.users.find_one({'_id': ObjectId(uid)})
                if reviewer and reviewer.get('email'):
                    try:
                        send_document_notification(user, reviewer,
                            {'document_name':document_name,'description':description,'_id':result.inserted_id},
                            description)
                    except Exception as e:
                        logger.error(f"Notify error: {e}")
            db.office_documents.update_one({'_id':result.inserted_id},{'$set':{'notified':True}})
        flash('✅ Document submitted successfully', 'success')
        return redirect(url_for('core_dashboard'))
    except Exception as e:
        logger.error(f"upload_document error: {e}")
        flash(f'Error submitting document: {str(e)[:100]}', 'error')
        return redirect(url_for('core_dashboard'))

# ══════════════════════════════════════════════════════════════════════
#  LEADER DASHBOARD
# ══════════════════════════════════════════════════════════════════════
@app.route('/leader_dashboard')
@approval_required
def leader_dashboard():
    if not is_leader():
        flash('Access denied. Leaders only.', 'error')
        return redirect(url_for('home'))
    try:
        user = db.users.find_one({'email': session['email']})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('home'))
        my_assigned_documents = list(db.office_documents.find(
            {'assigned_reviewers': user['_id']}).sort('submitted_at',-1))
        now_aware = get_indian_time_aware()
        for doc in my_assigned_documents:
            if doc.get('status') == 'pending':
                sat = doc['submitted_at']
                sat_aware = IST.localize(sat) if sat.tzinfo is None else sat
                diff = now_aware - sat_aware
                doc['time_in_queue'] = f"{diff.days}d {diff.seconds//3600}h" if diff.days > 0 else f"{diff.seconds//3600}h"
            uploader = db.users.find_one({'_id': doc['user_id']})
            if uploader:
                doc['uploader_name']  = uploader['email'].split('@')[0]
                doc['uploader_email'] = uploader['email']
        shared_documents = []
        try:
            shared_documents = list(db.document_shares.find(
                {'shared_with': user['_id']}).sort('shared_at',-1))
            for share in shared_documents:
                sender = db.users.find_one({'_id': share['shared_by']})
                share['sender_name']  = sender['email'].split('@')[0] if sender else 'Unknown'
                share['sender_email'] = sender['email'] if sender else ''
                doc = db.office_documents.find_one({'_id': share['document_id']}) if share.get('document_id') else None
                share['file_url'] = doc.get('file_url') if doc else share.get('file_url')
        except Exception as e:
            logger.error(f"Shared docs error: {e}")
        assigned_tasks = []
        try:
            assigned_tasks = list(db.tasks.find({'assigned_by': user['_id']}).sort('created_at',-1))
            for task in assigned_tasks:
                assignee = db.users.find_one({'_id': task['assigned_to']})
                if assignee:
                    task['assigned_to_name'] = assignee['email'].split('@')[0]
                task['due_date_str'] = (task['due_date'].strftime('%d %b %Y')
                                        if isinstance(task.get('due_date'), datetime)
                                        else str(task.get('due_date','')))
        except Exception as e:
            logger.error(f"Assigned tasks error: {e}")
        core_members = list(db.users.find({
            '$or':[{'user_type':'core'},{'special_role':'office_barrier'}],'approved':True}))
        online_core = list(db.users.find({
            '$or':[{'user_type':'core'},{'special_role':'office_barrier'}],
            'approved':True,'is_online':True}))
        for member in core_members:
            member['doc_count'] = db.office_documents.count_documents({'user_id':member['_id']})
            if member.get('last_seen'):
                ls = member['last_seen']
                ls_aware = IST.localize(ls) if ls.tzinfo is None else ls
                diff = now_aware - ls_aware
                if diff.days > 0:   member['last_seen_formatted'] = f"{diff.days}d ago"
                elif diff.seconds//3600 > 0: member['last_seen_formatted'] = f"{diff.seconds//3600}h ago"
                else: member['last_seen_formatted'] = f"{diff.seconds//60}m ago"
            else:
                member['last_seen_formatted'] = "Never"
        leaders = list(db.users.find({'special_role':'leader','approved':True}))
        today_start_n = make_timezone_naive(now_aware.replace(hour=0,minute=0,second=0,microsecond=0))
        today_shared_count = db.document_shares.count_documents(
            {'shared_with':user['_id'],'shared_at':{'$gte':today_start_n}})
        pending_count = len([d for d in my_assigned_documents if d.get('status')=='pending'])
        return render_template('leader_dashboard.html',
            user=user, my_assigned_documents=my_assigned_documents,
            shared_documents=shared_documents, assigned_tasks=assigned_tasks,
            core_members=core_members, online_core=online_core, leaders=leaders,
            pending_count=pending_count, today_shared_count=today_shared_count,
            today_date=get_indian_time().strftime('%Y-%m-%d'), now=get_indian_time())
    except Exception as e:
        logger.error(f"leader_dashboard error: {e}", exc_info=True)
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('home'))

@app.route('/review_document/<document_id>', methods=['POST'])
@approval_required
def review_document(document_id):
    if not is_leader():
        return jsonify({'error': 'Access denied'}), 403
    try:
        user       = db.users.find_one({'email': session['email']})
        status     = request.form.get('status')
        comments   = request.form.get('comments', '')
        send_reply = request.form.get('send_reply') == 'on'
        db.office_documents.update_one({'_id': ObjectId(document_id)},
            {'$set': {'status': status, 'reviewed_by': user['_id'],
                      'reviewed_at': get_indian_time(), 'comments': comments}})
        doc      = db.office_documents.find_one({'_id': ObjectId(document_id)})
        uploader = db.users.find_one({'_id': doc['user_id']})
        if uploader and send_reply:
            try: send_review_reply(user, uploader, doc, comments, status)
            except Exception as e: logger.error(f"Review reply error: {e}")
        flash(f'✅ Document {status}', 'success')
        return redirect(url_for('leader_dashboard'))
    except Exception as e:
        logger.error(f"review_document error: {e}")
        flash(f'Error reviewing document: {str(e)[:100]}', 'error')
        return redirect(url_for('leader_dashboard'))

@app.route('/share_document_leader', methods=['POST'])
@approval_required
def share_document_leader():
    if not is_leader():
        return jsonify({'error': 'Access denied'}), 403
    try:
        user        = db.users.find_one({'email': session['email']})
        document_id = request.form.get('document_id')
        leader_ids  = request.form.getlist('leaders')
        core_ids    = request.form.getlist('core_members')
        message     = request.form.get('message', '').strip()
        file        = request.files.get('share_file')
        file_url    = None; file_name = None
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            n, e = os.path.splitext(filename)
            ufn  = f"share_{n}_{ts}{e}"
            fp   = os.path.join(app.config['UPLOAD_FOLDER'], ufn)
            file.save(fp)
            file_url  = '/' + fp.replace('\\', '/')
            file_name = filename
        recipient_ids = leader_ids + core_ids
        if not recipient_ids:
            flash('Please select at least one recipient', 'error')
            return redirect(url_for('leader_dashboard'))
        document_name = "Shared File"
        if document_id:
            document = db.office_documents.find_one({'_id': ObjectId(document_id)})
            if document:
                document_name = document['document_name']
                if not file_url: file_url = document.get('file_url')
        if not document_id and not file_url:
            flash('Please select a document or upload a file', 'error')
            return redirect(url_for('leader_dashboard'))
        share_data = {
            'document_id':     ObjectId(document_id) if document_id else None,
            'document_name':   document_name,
            'shared_by':       user['_id'],
            'shared_by_email': session['email'],
            'shared_with':     [ObjectId(rid) for rid in recipient_ids],
            'message':         message,
            'file_url':        file_url,
            'file_name':       file_name,
            'shared_at':       get_indian_time(),
            'status':          'sent'
        }
        result = db.document_shares.insert_one(share_data)
        for rid in recipient_ids:
            recipient = db.users.find_one({'_id': ObjectId(rid)})
            if recipient:
                send_document_notification(user, recipient,
                    {'document_name':document_name,'description':message,'_id':result.inserted_id}, message)
        flash('✅ Document shared successfully', 'success')
        return redirect(url_for('leader_dashboard'))
    except Exception as e:
        logger.error(f"share_document_leader error: {e}")
        flash(f'Error sharing document: {str(e)[:100]}', 'error')
        return redirect(url_for('leader_dashboard'))

# ══════════════════════════════════════════════════════════════════════
#  TASK ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route('/assign_task', methods=['POST'])
@approval_required
def assign_task():
    if not is_leader():
        return jsonify({'error': 'Access denied'}), 403
    try:
        user        = db.users.find_one({'email': session['email']})
        task_title  = request.form.get('task_title')
        description = request.form.get('description')
        due_date    = request.form.get('due_date')
        priority    = request.form.get('priority', 'medium')
        assigned_to = request.form.get('assigned_to')
        file        = request.files.get('task_file')
        file_url    = None; file_name = None
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            n, e = os.path.splitext(filename)
            ufn  = f"task_{n}_{ts}{e}"
            fp   = os.path.join(app.config['UPLOAD_FOLDER'], ufn)
            file.save(fp)
            file_url  = '/' + fp.replace('\\', '/')
            file_name = filename
        due_datetime = IST.localize(datetime.strptime(due_date, '%Y-%m-%d'))
        task = {
            'assigned_by':       user['_id'],
            'assigned_by_email': session['email'],
            'assigned_to':       ObjectId(assigned_to),
            'title':             task_title,
            'description':       description,
            'due_date':          make_timezone_naive(due_datetime),
            'priority':          priority,
            'status':            'pending',
            'progress':          0,
            'has_attachment':    file_url is not None,
            'attachment_url':    file_url,
            'attachment_name':   file_name,
            'updates':           [],
            'leader_comments':   [],
            'created_at':        get_indian_time(),
            'updated_at':        get_indian_time()
        }
        db.tasks.insert_one(task)
        db.activity_logs.insert_one({
            'user_id': user['_id'], 'user_email': session['email'],
            'action': 'task_assigned', 'details': f'Assigned task: {task_title}',
            'timestamp': get_indian_time(), 'ip_address': request.remote_addr
        })
        assigned_user = db.users.find_one({'_id': ObjectId(assigned_to)})
        if assigned_user:
            send_task_notification(user, assigned_user, task_title, due_date,
                                   " with attachment" if file_url else "",
                                   priority, description)
        flash('✅ Task assigned successfully', 'success')
        return redirect(url_for('leader_dashboard'))
    except Exception as e:
        logger.error(f"assign_task error: {e}")
        flash(f'Error assigning task: {str(e)[:100]}', 'error')
        return redirect(url_for('leader_dashboard'))

@app.route('/api/update_task_progress/<task_id>', methods=['POST'])
@login_required
def update_task_progress(task_id):
    try:
        if request.content_type and 'application/json' in request.content_type:
            data       = request.get_json(force=True) or {}
            progress   = int(data.get('progress', 0))
            status     = data.get('status', 'in_progress')
            comment    = data.get('comment', '')
            attachment = None
        else:
            progress   = int(request.form.get('progress', 0))
            status     = request.form.get('status', 'in_progress')
            comment    = request.form.get('comment', '')
            attachment = request.files.get('attachment')
        user = db.users.find_one({'email': session['email']})
        if not user: return jsonify({'success': False, 'error': 'User not found'}), 404
        task = db.tasks.find_one({'_id': ObjectId(task_id)})
        if not task: return jsonify({'success': False, 'error': 'Task not found'}), 404
        if str(task['assigned_to']) != str(user['_id']):
            return jsonify({'success': False, 'error': 'Not assigned to this task'}), 403
        file_url = None; file_name = None
        if attachment and attachment.filename and allowed_file(attachment.filename):
            filename = secure_filename(attachment.filename)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            n, e = os.path.splitext(filename)
            ufn  = f"task_update_{n}_{ts}{e}"
            fp   = os.path.join(app.config['UPLOAD_FOLDER'], ufn)
            attachment.save(fp)
            file_url  = '/' + fp.replace('\\', '/')
            file_name = filename
        update_entry = {'progress': progress, 'status': status,
                        'comment': comment, 'timestamp': get_indian_time()}
        if file_url:
            update_entry['attachment_url']  = file_url
            update_entry['attachment_name'] = file_name
        set_data = {'progress': progress, 'status': status, 'updated_at': get_indian_time()}
        if file_url:
            set_data['latest_attachment_url']  = file_url
            set_data['latest_attachment_name'] = file_name
        db.tasks.update_one({'_id': ObjectId(task_id)},
            {'$set': set_data, '$push': {'updates': update_entry}})
        db.activity_logs.insert_one({
            'user_id': user['_id'], 'user_email': session['email'],
            'action': 'task_update',
            'details': f'Updated: {task["title"]} → {status} ({progress}%)',
            'timestamp': get_indian_time(), 'ip_address': request.remote_addr
        })
        if status == 'completed':
            assigner = db.users.find_one({'_id': task['assigned_by']})
            if assigner:
                try: send_completion_notification(assigner, user, task, comment, file_url)
                except Exception as e: logger.error(f"Completion notification error: {e}")
        return jsonify({'success': True,
                        'message': 'Task updated' + (' with attachment' if file_url else '')})
    except Exception as e:
        logger.error(f"update_task_progress error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/leader/accept_task/<task_id>', methods=['POST'])
@approval_required
def leader_accept_task(task_id):
    if not is_leader(): return jsonify({'error': 'Access denied'}), 403
    try:
        user = db.users.find_one({'email': session['email']})
        task = db.tasks.find_one({'_id': ObjectId(task_id)})
        if not task: return jsonify({'error': 'Task not found'}), 404
        if str(task['assigned_by']) != str(user['_id']): return jsonify({'error': 'Not authorized'}), 403
        db.tasks.update_one({'_id': ObjectId(task_id)},
            {'$set': {'status': 'accepted', 'accepted_at': get_indian_time(),
                      'accepted_by': user['_id'], 'updated_at': get_indian_time()}})
        assignee = db.users.find_one({'_id': task['assigned_to']})
        if assignee:
            try:
                msg = Message(subject=f"✅ Task Accepted: {task['title']}",
                              sender=app.config['MAIL_USERNAME'], recipients=[assignee['email']])
                msg.body = (f"Your task '{task['title']}' has been accepted by "
                            f"{user['email'].split('@')[0]}! Great work!\n\n"
                            f"View: {request.url_root}core_dashboard")
                mail.send(msg)
            except Exception as e: logger.error(f"Accept task email error: {e}")
        return jsonify({'success': True, 'message': 'Task accepted successfully'})
    except Exception as e:
        logger.error(f"accept_task error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/leader/request_rework/<task_id>', methods=['POST'])
@approval_required
def leader_request_rework(task_id):
    if not is_leader(): return jsonify({'error': 'Access denied'}), 403
    try:
        user = db.users.find_one({'email': session['email']})
        task = db.tasks.find_one({'_id': ObjectId(task_id)})
        if not task: return jsonify({'error': 'Task not found'}), 404
        if str(task['assigned_by']) != str(user['_id']): return jsonify({'error': 'Not authorized'}), 403
        data         = request.get_json(force=True) or {}
        comment      = data.get('comment', '').strip()
        new_due_date = data.get('new_due_date', '')
        if not comment: return jsonify({'error': 'Rework instructions are required'}), 400
        update_data = {
            'status': 'rework', 'rework_comment': comment,
            'rework_requested_at': get_indian_time(),
            'rework_by': user['_id'], 'progress': 0, 'updated_at': get_indian_time()
        }
        if new_due_date:
            new_date_obj = datetime.strptime(new_due_date, '%Y-%m-%d')
            if new_date_obj.date() < get_indian_time().date():
                return jsonify({'error': 'New due date cannot be in the past'}), 400
            update_data['due_date'] = make_timezone_naive(IST.localize(new_date_obj))
        update_entry = {'progress': 0, 'status': 'rework',
                        'comment': f'LEADER REWORK REQUEST: {comment}',
                        'timestamp': get_indian_time()}
        db.tasks.update_one({'_id': ObjectId(task_id)},
            {'$set': update_data, '$push': {'updates': update_entry}})
        assignee = db.users.find_one({'_id': task['assigned_to']})
        if assignee:
            try:
                msg = Message(subject=f"🔄 Rework Required: {task['title']}",
                              sender=app.config['MAIL_USERNAME'], recipients=[assignee['email']])
                msg.body = (f"Rework requested by {user['email'].split('@')[0]}\n\n"
                            f"Task: {task['title']}\n"
                            f"{f'New Due: {new_due_date}' if new_due_date else ''}\n\n"
                            f"Instructions:\n{comment}\n\nView: {request.url_root}core_dashboard")
                mail.send(msg)
            except Exception as e: logger.error(f"Rework email error: {e}")
        return jsonify({'success': True, 'message': 'Rework requested successfully'})
    except Exception as e:
        logger.error(f"request_rework error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/leader/reschedule_task/<task_id>', methods=['POST'])
@login_required
def leader_reschedule_task(task_id):
    if not is_leader(): return jsonify({'error': 'Access denied'}), 403
    try:
        user = db.users.find_one({'email': session['email']})
        task = db.tasks.find_one({'_id': ObjectId(task_id)})
        if not task: return jsonify({'error': 'Task not found'}), 404
        if str(task['assigned_by']) != str(user['_id']): return jsonify({'error': 'Not authorized'}), 403
        data         = request.get_json(force=True) or {}
        new_due_date = data.get('new_due_date', '')
        reason       = data.get('reason', '').strip()
        if not new_due_date: return jsonify({'error': 'New due date is required'}), 400
        new_date_obj = datetime.strptime(new_due_date, '%Y-%m-%d')
        if new_date_obj.date() < get_indian_time().date():
            return jsonify({'error': 'Date cannot be in the past'}), 400
        new_date_naive = make_timezone_naive(IST.localize(new_date_obj))
        update_entry = {
            'progress': task.get('progress', 0), 'status': task.get('status', 'pending'),
            'comment': f'Due date rescheduled to {new_due_date}' + (f'. Reason: {reason}' if reason else ''),
            'timestamp': get_indian_time()
        }
        db.tasks.update_one({'_id': ObjectId(task_id)},
            {'$set': {'due_date': new_date_naive, 'rescheduled_at': get_indian_time(),
                      'rescheduled_by': user['_id'], 'updated_at': get_indian_time()},
             '$push': {'updates': update_entry}})
        assignee = db.users.find_one({'_id': task['assigned_to']})
        if assignee:
            try:
                msg = Message(subject=f"📅 Task Rescheduled: {task['title']}",
                              sender=app.config['MAIL_USERNAME'], recipients=[assignee['email']])
                msg.body = (f"Task rescheduled by {user['email'].split('@')[0]}\n\n"
                            f"Task: {task['title']}\nNew Due: {new_due_date}\n"
                            f"{f'Reason: {reason}' if reason else ''}\n\nView: {request.url_root}core_dashboard")
                mail.send(msg)
            except Exception as e: logger.error(f"Reschedule email error: {e}")
        return jsonify({'success': True, 'message': 'Task rescheduled successfully'})
    except Exception as e:
        logger.error(f"reschedule_task error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/leader/add_task_comment/<task_id>', methods=['POST'])
@approval_required
def leader_add_task_comment(task_id):
    if not is_leader(): return jsonify({'error': 'Access denied'}), 403
    try:
        user = db.users.find_one({'email': session['email']})
        task = db.tasks.find_one({'_id': ObjectId(task_id)})
        if not task: return jsonify({'error': 'Task not found'}), 404
        if str(task['assigned_by']) != str(user['_id']): return jsonify({'error': 'Not authorized'}), 403
        data    = request.get_json(force=True) or {}
        comment = data.get('comment', '').strip()
        if not comment: return jsonify({'error': 'Comment is required'}), 400
        comment_entry = {
            'comment': comment, 'commented_by': user['email'].split('@')[0],
            'timestamp': get_indian_time(), 'type': 'leader_comment'
        }
        db.tasks.update_one({'_id': ObjectId(task_id)},
            {'$push': {'leader_comments': comment_entry},
             '$set': {'updated_at': get_indian_time()}})
        assignee = db.users.find_one({'_id': task['assigned_to']})
        if assignee:
            try:
                msg = Message(subject=f"💬 New Comment: {task['title']}",
                              sender=app.config['MAIL_USERNAME'], recipients=[assignee['email']])
                msg.body = (f"{user['email'].split('@')[0]} commented:\n\n\"{comment}\"\n\n"
                            f"View: {request.url_root}core_dashboard")
                mail.send(msg)
            except Exception as e: logger.error(f"Comment email error: {e}")
        return jsonify({'success': True, 'message': 'Comment added'})
    except Exception as e:
        logger.error(f"add_task_comment error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/leader/add_share_comment/<share_id>', methods=['POST'])
@approval_required
def leader_add_share_comment(share_id):
    if not is_leader(): return jsonify({'error': 'Access denied'}), 403
    try:
        user    = db.users.find_one({'email': session['email']})
        data    = request.get_json(force=True) or {}
        comment = data.get('comment', '').strip()
        if not comment: return jsonify({'error': 'Comment is required'}), 400
        db.document_shares.update_one(
            {'_id': ObjectId(share_id), 'shared_with': user['_id']},
            {'$set': {'leader_comment': comment,
                      'leader_comment_at': get_indian_time(),
                      'leader_comment_by': user['email']}})
        return jsonify({'success': True, 'message': 'Comment saved'})
    except Exception as e:
        logger.error(f"add_share_comment error: {e}")
        return jsonify({'error': str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  ACTIVITY STATUS
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/activity/status')
@login_required
def get_activity_status():
    try:
        user = db.users.find_one({'email': session['email']})
        if not user: return jsonify({'error': 'User not found'}), 404
        now   = get_indian_time_aware()
        five_n= make_timezone_naive(now - timedelta(minutes=5))
        new_tasks    = db.tasks.count_documents({'assigned_to':user['_id'],'created_at':{'$gte':five_n},'status':'pending'})
        new_documents= db.document_shares.count_documents({'shared_with':user['_id'],'shared_at':{'$gte':five_n}})
        overdue_tasks= db.tasks.count_documents({'assigned_to':user['_id'],'due_date':{'$lt':five_n},'status':{'$ne':'completed'}})
        updated_tasks = 0
        if is_leader():
            updated_tasks = db.tasks.count_documents({'assigned_by':user['_id'],'updated_at':{'$gte':five_n},'status':{'$in':['in_progress','completed']}})
        unread_messages = db.direct_messages.count_documents({'receiver_id':user['_id'],'read':False})
        db.users.update_one({'_id':user['_id']},{'$set':{'last_seen':get_indian_time()}})
        return jsonify({'success':True,'new_tasks':new_tasks,'new_documents':new_documents,
                        'overdue_tasks':overdue_tasks,'updated_tasks':updated_tasks,
                        'unread_messages': unread_messages,
                        'timestamp':get_indian_time().strftime('%Y-%m-%d %H:%M:%S')})
    except Exception as e:
        logger.error(f"activity_status error: {e}")
        return jsonify({'error': str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  ANALYTICS
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/core-member/analytics/<member_id>')
@approval_required
def core_member_analytics(member_id):
    if not is_leader(): return jsonify({'error': 'Access denied'}), 403
    try:
        member    = db.users.find_one({'_id': ObjectId(member_id)})
        if not member: return jsonify({'error': 'Member not found'}), 404
        documents = list(db.office_documents.find({'user_id':member['_id']}).sort('submitted_at',-1))
        total     = len(documents)
        pending   = len([d for d in documents if d.get('status')=='pending'])
        approved  = len([d for d in documents if d.get('status')=='approved'])
        revision  = len([d for d in documents if d.get('status')=='revision'])
        rejected  = len([d for d in documents if d.get('status')=='rejected'])
        recent_activity = []
        for doc in documents[:5]:
            recent_activity.append({
                'description': f"Submitted: {doc['document_name']}",
                'time': doc['submitted_at'].strftime('%d %b %Y, %I:%M %p'),
                'icon': 'file-alt', 'color': 'blue'
            })
        docs_list = []
        for doc in documents:
            docs_list.append({
                'name': doc['document_name'],
                'submitted': doc['submitted_at'].strftime('%d %b %Y'),
                'status': doc['status'],
                'file_url': doc.get('file_url', '#')
            })
        last_seen = member['last_seen'].strftime('%d %b %Y, %I:%M %p') if member.get('last_seen') else 'Never'
        return jsonify({
            'email': member['email'], 'name': member['email'].split('@')[0],
            'is_online': member.get('is_online', False), 'last_seen': last_seen,
            'total_documents': total, 'pending': pending, 'approved': approved,
            'revision': revision, 'rejected': rejected,
            'recent_activity': recent_activity[:10], 'documents': docs_list
        })
    except Exception as e:
        logger.error(f"core_member_analytics error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents/by-date')
@approval_required
def documents_by_date():
    if not is_leader(): return jsonify({'error': 'Access denied'}), 403
    try:
        date_str    = request.args.get('date')
        if not date_str: return jsonify({'error': 'Date required'}), 400
        filter_date = IST.localize(datetime.strptime(date_str, '%Y-%m-%d'))
        next_day    = filter_date + timedelta(days=1)
        documents   = list(db.office_documents.find({
            'submitted_at': {'$gte': make_timezone_naive(filter_date),
                             '$lt':  make_timezone_naive(next_day)}
        }))
        return jsonify({
            'total':    len(documents),
            'approved': len([d for d in documents if d.get('status')=='approved']),
            'pending':  len([d for d in documents if d.get('status')=='pending']),
            'revision': len([d for d in documents if d.get('status')=='revision']),
            'rejected': len([d for d in documents if d.get('status')=='rejected'])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  OFFICE DOCUMENTS
# ══════════════════════════════════════════════════════════════════════
@app.route('/office_documents')
def office_documents():
    if not is_core_or_leader():
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    try:
        documents = list(db.office_documents.find().sort('submitted_at', -1))
        for doc in documents:
            u = db.users.find_one({'_id': doc['user_id']})
            if u:
                doc['user_name'] = u['email'].split('@')[0]
                doc['user_type'] = u.get('user_type', 'N/A')
        online_users = list(db.users.find({'special_role':'office_barrier','is_online':True}))
        return render_template('office_documents.html', documents=documents, online_users=online_users)
    except Exception as e:
        logger.error(f"office_documents error: {e}")
        flash('Error loading documents', 'error')
        return redirect(url_for('home'))

@app.route('/activity_logs')
def activity_logs():
    if not is_core_or_leader():
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    try:
        logs = list(db.activity_logs.find().sort('timestamp',-1).limit(100))
        online_users = list(db.users.find({'is_online':True}, {'email':1,'user_type':1,'special_role':1}))
        return render_template('activity_logs.html', logs=logs, online_users=online_users)
    except Exception as e:
        logger.error(f"activity_logs error: {e}")
        flash('Error loading logs', 'error')
        return redirect(url_for('home'))

# ══════════════════════════════════════════════════════════════════════
#  CHAT API (Group / Core Team)
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/chat/messages')
@login_required
def get_chat_messages():
    try:
        user = db.users.find_one({'email': session['email']})
        messages = list(db.chat_messages.find({
            '$or':[{'sender_id':user['_id']},{'receiver_id':user['_id']},{'group_id':'core_team'}]
        }).sort('timestamp',-1).limit(100))
        formatted = []
        for msg in reversed(messages):
            sender = db.users.find_one({'_id': msg['sender_id']})
            ts = msg.get('timestamp')
            ts_str = ''
            if ts:
                ts_aware = IST.localize(ts) if ts.tzinfo is None else ts
                ts_str   = ts_aware.strftime('%I:%M %p')
            formatted.append({
                'id':           str(msg['_id']),
                'sender_id':    str(msg['sender_id']),
                'sender_name':  sender['email'].split('@')[0] if sender else 'Unknown',
                'sender_email': sender['email'] if sender else '',
                'content':      msg.get('content',''),
                'file_url':     msg.get('file_url'),
                'document_id':  str(msg['document_id']) if msg.get('document_id') else None,
                'timestamp':    ts_str,
                'is_me':        msg['sender_id'] == user['_id']
            })
        return jsonify({'success': True, 'messages': formatted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/send', methods=['POST'])
@login_required
def send_chat_message():
    try:
        user        = db.users.find_one({'email': session['email']})
        data        = request.get_json(force=True) or {}
        content     = data.get('content','').strip()
        receiver_id = data.get('receiver_id')
        file_url    = data.get('file_url')
        document_id = data.get('document_id')
        if not content and not file_url and not document_id:
            return jsonify({'error': 'Message content, file, or document required'}), 400
        message = {
            'sender_id':   user['_id'],
            'receiver_id': ObjectId(receiver_id) if receiver_id else None,
            'group_id':    'core_team' if not receiver_id else None,
            'content':     content,
            'file_url':    file_url,
            'document_id': ObjectId(document_id) if document_id else None,
            'timestamp':   get_indian_time(),
            'read':        False
        }
        result = db.chat_messages.insert_one(message)
        if receiver_id:
            receiver = db.users.find_one({'_id': ObjectId(receiver_id)})
            if receiver and receiver.get('email'):
                send_chat_notification(user, receiver, content[:50])
        else:
            notify_group_chat(user, content[:50])
        return jsonify({'success': True, 'message_id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  DIRECT MESSAGES API (Navbar messaging)
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/dm/send', methods=['POST'])
@login_required
def send_direct_message():
    """Send a direct message to a specific user."""
    try:
        sender      = db.users.find_one({'email': session['email']})
        data        = request.get_json(force=True) or {}
        receiver_id = data.get('receiver_id')
        content     = data.get('content', '').strip()
        if not content: return jsonify({'error': 'Message content required'}), 400
        receiver = db.users.find_one({'_id': ObjectId(receiver_id)}) if receiver_id else None
        msg = {
            'sender_id':   sender['_id'],
            'sender_email':session['email'],
            'receiver_id': ObjectId(receiver_id) if receiver_id else None,
            'content':     content,
            'timestamp':   get_indian_time(),
            'read':        False
        }
        db.direct_messages.insert_one(msg)
        if receiver:
            try: send_chat_notification(sender, receiver, content[:50])
            except: pass
        return jsonify({'success': True, 'message': 'Message sent'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dm/messages')
@login_required
def get_direct_messages():
    """Get direct messages for current user."""
    try:
        user = db.users.find_one({'email': session['email']})
        # mark received as read
        db.direct_messages.update_many(
            {'receiver_id': user['_id'], 'read': False},
            {'$set': {'read': True}}
        )
        messages = list(db.direct_messages.find({
            '$or': [{'sender_id': user['_id']}, {'receiver_id': user['_id']}]
        }).sort('timestamp', -1).limit(50))
        formatted = []
        for msg in reversed(messages):
            sender = db.users.find_one({'_id': msg['sender_id']})
            ts = msg.get('timestamp')
            ts_str = ts.strftime('%d %b, %I:%M %p') if ts else ''
            formatted.append({
                'id':           str(msg['_id']),
                'sender_name':  sender['email'].split('@')[0] if sender else 'Unknown',
                'sender_email': sender['email'] if sender else '',
                'content':      msg.get('content', ''),
                'timestamp':    ts_str,
                'is_me':        msg['sender_id'] == user['_id'],
                'read':         msg.get('read', True)
            })
        return jsonify({'success': True, 'messages': formatted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dm/unread-count')
@login_required
def unread_dm_count():
    """Get unread DM count for badge."""
    try:
        user  = db.users.find_one({'email': session['email']})
        count = db.direct_messages.count_documents({'receiver_id': user['_id'], 'read': False})
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  GOOGLE OAUTH
# ══════════════════════════════════════════════════════════════════════
@app.route('/connect-drive')
@login_required
def connect_drive():
    try:
        session.pop('drive_creds', None); session.pop('drive_state', None)
        redirect_uri = ('https://office-academic.juooa.cloud/drive/callback'
                        if request.url_root.startswith('https://') else
                        'http://localhost:5000/drive/callback')
        flow = Flow.from_client_secrets_file('client_secret.json', scopes=DRIVE_SCOPES, redirect_uri=redirect_uri)
        auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent')
        session['drive_state'] = state
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"connect_drive error: {e}")
        flash('Error initiating Drive connection.', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/drive/callback')
def drive_callback():
    try:
        if session.get('drive_state') != request.args.get('state'):
            flash('Authorization failed: State mismatch', 'error')
            return redirect(url_for('user_dashboard'))
        redirect_uri = ('https://office-academic.juooa.cloud/drive/callback'
                        if request.url_root.startswith('https://') else
                        'http://localhost:5000/drive/callback')
        flow = Flow.from_client_secrets_file('client_secret.json', scopes=DRIVE_SCOPES,
                                              redirect_uri=redirect_uri, state=session['drive_state'])
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        session['drive_creds'] = {
            'token': creds.token, 'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri, 'client_id': creds.client_id,
            'client_secret': creds.client_secret, 'scopes': DRIVE_SCOPES
        }
        session.pop('drive_state', None)
        flash('✅ Google Drive connected!', 'success')
        return redirect(url_for('user_dashboard'))
    except Exception as e:
        logger.error(f"drive_callback error: {e}")
        flash('Error connecting to Drive.', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/connect-gmail')
@login_required
def connect_gmail():
    try:
        session.pop('gmail_creds', None); session.pop('gmail_state', None)
        redirect_uri = ('https://office-academic.juooa.cloud/gmail/callback'
                        if request.url_root.startswith('https://') else
                        'http://localhost:5000/gmail/callback')
        flow = Flow.from_client_secrets_file('client_secret.json', scopes=GMAIL_SCOPES, redirect_uri=redirect_uri)
        auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='false', prompt='consent')
        session['gmail_state'] = state
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"connect_gmail error: {e}")
        flash('Error initiating Gmail connection.', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/gmail/callback')
def gmail_callback():
    try:
        if session.get('gmail_state') != request.args.get('state'):
            flash('State mismatch. Authorization failed.', 'error')
            return redirect(url_for('user_dashboard'))
        redirect_uri = ('https://office-academic.juooa.cloud/gmail/callback'
                        if request.url_root.startswith('https://') else
                        'http://localhost:5000/gmail/callback')
        flow = Flow.from_client_secrets_file('client_secret.json', scopes=GMAIL_SCOPES, redirect_uri=redirect_uri)
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        session['gmail_creds'] = {
            'token': creds.token, 'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri, 'client_id': creds.client_id,
            'client_secret': creds.client_secret, 'scopes': GMAIL_SCOPES
        }
        session.pop('gmail_state', None)
        flash('✅ Gmail connected!', 'success')
        return redirect(url_for('user_dashboard'))
    except Exception as e:
        logger.error(f"gmail_callback error: {e}")
        flash('Error connecting to Gmail.', 'error')
        return redirect(url_for('user_dashboard'))

# ══════════════════════════════════════════════════════════════════════
#  DRIVE OPERATIONS
# ══════════════════════════════════════════════════════════════════════
@app.route('/drive/files')
@login_required
def drive_files():
    if 'drive_creds' not in session:
        flash('Please connect your Google Drive first.', 'error')
        return redirect(url_for('connect_drive'))
    try:
        service = get_drive_service()
        if not service:
            flash('Error connecting to Drive. Please reconnect.', 'error')
            return redirect(url_for('connect_drive'))
        results = service.files().list(
            q="trashed=false and mimeType='application/vnd.google-apps.folder'",
            pageSize=100, fields="files(id,name,mimeType,createdTime,webViewLink,iconLink)",
            orderBy="name").execute()
        folders = results.get('files', [])
        user_folders     = db.user_navbars.find_one({'user_email': session['email']})
        saved_folder_ids = [item['ref_id'] for item in user_folders['items']] if user_folders and 'items' in user_folders else []
        for folder in folders:
            if 'webViewLink' not in folder:
                folder['webViewLink'] = f"https://drive.google.com/drive/folders/{folder['id']}"
        return render_template('drive_files.html', folders=folders,
                               saved_folder_ids=saved_folder_ids, total_folders=len(folders),
                               notifications=get_user_notifications())
    except Exception as e:
        logger.error(f"drive_files error: {e}")
        flash('Error connecting to Google Drive', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/api/drive/folder/<folder_id>')
@login_required
def get_drive_folder_contents(folder_id):
    if 'drive_creds' not in session: return jsonify({'error': 'Not authenticated'}), 401
    try:
        service = get_drive_service()
        if not service: return jsonify({'error': 'Drive service unavailable'}), 500
        results = service.files().list(
            q=f"'{folder_id}' in parents and trashed=false",
            pageSize=100, fields="files(id,name,mimeType,size,createdTime,webViewLink)").execute()
        return jsonify(results.get('files', []))
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/drive/search')
@login_required
def search_drive_files():
    if 'drive_creds' not in session: return jsonify({'error': 'Not authenticated'}), 401
    try:
        query = request.args.get('q', '')
        if not query: return jsonify([])
        service = get_drive_service()
        if not service: return jsonify({'error': 'Drive service unavailable'}), 500
        results = service.files().list(
            q=f"name contains '{query}' and trashed=false",
            pageSize=20, fields="files(id,name,mimeType,webViewLink,iconLink)").execute()
        return jsonify(results.get('files', []))
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/drive/upload', methods=['POST'])
@login_required
def drive_upload():
    if 'drive_creds' not in session: return jsonify({'error': 'Not authenticated'}), 401
    try:
        file        = request.files.get('file')
        folder_id   = request.form.get('folder_id', 'root')
        make_public = request.form.get('make_public', 'false') == 'true'
        if not file: return jsonify({'error': 'No file provided'}), 400
        service = get_drive_service()
        if not service: return jsonify({'error': 'Drive service unavailable'}), 500
        file_metadata = {'name': secure_filename(file.filename), 'parents': [folder_id]}
        file_content  = file.read()
        media         = MediaIoBaseUpload(BytesIO(file_content),
                                          mimetype=file.mimetype or 'application/octet-stream',
                                          resumable=True)
        file_obj = service.files().create(body=file_metadata, media_body=media,
                                          fields='id,name,webViewLink').execute()
        result = {
            'file_id':   file_obj['id'],
            'file_name': file_obj['name'],
            'web_link':  file_obj.get('webViewLink', f"https://drive.google.com/file/d/{file_obj['id']}/view")
        }
        if make_public:
            if make_file_public(service, file_obj['id']):
                result['public_link'] = f"https://drive.google.com/file/d/{file_obj['id']}/view"
                db.public_files.insert_one({
                    'file_id': file_obj['id'], 'name': file_obj['name'],
                    'uploader_email': session['email'], 'web_link': result['public_link'],
                    'uploaded_at': get_indian_time()
                })
        db.user_files.insert_one({
            'user_email': session['email'], 'file_name': file_obj['name'],
            'original_filename': file_obj['name'], 'drive_file_id': file_obj['id'],
            'drive_link': result['web_link'], 'is_public': make_public,
            'source': 'drive', 'uploaded_at': get_indian_time()
        })
        return jsonify(result)
    except Exception as e:
        logger.error(f"drive_upload error: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/drive/create-folder', methods=['POST'])
@login_required
def drive_create_folder():
    if 'drive_creds' not in session: return jsonify({'error': 'Not authenticated'}), 401
    try:
        data        = request.get_json(force=True) or {}
        folder_name = data.get('folder_name')
        parent_id   = data.get('parent_id', 'root')
        if not folder_name: return jsonify({'error': 'Folder name required'}), 400
        service = get_drive_service()
        if not service: return jsonify({'error': 'Drive service unavailable'}), 500
        folder = service.files().create(body={
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id]
        }, fields='id,name').execute()
        return jsonify({'folder_id': folder['id'], 'folder_name': folder['name']})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ══════════════════════════════════════════════════════════════════════
#  FILE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════
@app.route('/my_files')
@login_required
def my_files():
    try:
        return render_template('my_files.html',
            user_files=list(db.user_files.find({'user_email':session['email']}).sort('uploaded_at',-1)),
            drive_connected='drive_creds' in session,
            notifications=get_user_notifications())
    except Exception as e:
        logger.error(f"my_files error: {e}")
        flash('Error loading files', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    try:
        file        = request.files.get('file')
        file_name   = request.form.get('file_name', '')
        description = request.form.get('description', '')
        if not file: return jsonify({'error': 'No file provided', 'success': False}), 400
        if not allowed_file(file.filename): return jsonify({'error': 'File type not allowed', 'success': False}), 400
        filename = secure_filename(file.filename)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        n, e = os.path.splitext(filename)
        ufn  = f"{n}_{ts}{e}"
        fp   = os.path.join(app.config['UPLOAD_FOLDER'], ufn)
        file.save(fp)
        file_doc = {
            'user_email': session['email'], 'file_name': file_name or filename,
            'original_filename': filename, 'stored_filename': ufn,
            'description': description, 'file_path': fp,
            'file_size': os.path.getsize(fp),
            'file_type': e.lstrip('.').lower(), 'source': 'local',
            'uploaded_at': get_indian_time()
        }
        result = db.user_files.insert_one(file_doc)
        return jsonify({'success': True, 'message': 'File uploaded',
                        'file_id': str(result.inserted_id), 'file_name': file_doc['file_name']})
    except Exception as e:
        logger.error(f"upload_file error: {e}")
        return jsonify({'error': str(e), 'success': False}), 400

@app.route('/edit_file/<file_id>', methods=['POST'])
@login_required
def edit_file(file_id):
    try:
        data   = request.get_json(force=True) or {}
        result = db.user_files.update_one(
            {'_id':ObjectId(file_id),'user_email':session['email']},
            {'$set':{'file_name':data.get('file_name',''),'description':data.get('description',''),
                     'updated_at':get_indian_time()}})
        if result.modified_count > 0:
            return jsonify({'success': True, 'message': 'File updated'})
        return jsonify({'error': 'File not found or unauthorized'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/delete_file/<file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        file_doc = db.user_files.find_one({'_id':ObjectId(file_id),'user_email':session['email']})
        if not file_doc: return jsonify({'error': 'File not found'}), 404
        if file_doc.get('source') == 'local' and file_doc.get('file_path') and os.path.exists(file_doc['file_path']):
            os.remove(file_doc['file_path'])
        elif file_doc.get('source') == 'drive' and file_doc.get('drive_file_id'):
            service = get_drive_service()
            if service: delete_drive_file(service, file_doc['drive_file_id'])
        db.user_files.delete_one({'_id': ObjectId(file_id)})
        db.public_files.delete_one({'file_id': file_doc.get('drive_file_id')})
        return jsonify({'success': True, 'message': 'File deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/download_file/<file_id>')
@login_required
def download_file(file_id):
    try:
        file_doc = db.user_files.find_one({'_id':ObjectId(file_id),'user_email':session['email']})
        if not file_doc or file_doc.get('source') != 'local':
            flash('File not found or not locally stored', 'error')
            return redirect(url_for('my_files'))
        return send_from_directory(os.path.dirname(file_doc['file_path']),
                                   os.path.basename(file_doc['file_path']), as_attachment=True)
    except Exception as e:
        logger.error(f"download_file error: {e}")
        flash('Error downloading file', 'error')
        return redirect(url_for('my_files'))

@app.route('/link_drive_file', methods=['POST'])
@login_required
def link_drive_file():
    try:
        data          = request.get_json(force=True) or {}
        drive_file_id = data.get('drive_file_id')
        if not drive_file_id: return jsonify({'error': 'Drive file ID required'}), 400
        service = get_drive_service()
        if not service: return jsonify({'error': 'Drive not connected'}), 400
        file_metadata = service.files().get(fileId=drive_file_id,
                                            fields='id,name,mimeType,size,webViewLink').execute()
        file_doc = {
            'user_email': session['email'], 'file_name': data.get('file_name') or file_metadata['name'],
            'original_filename': file_metadata['name'], 'description': data.get('description',''),
            'drive_file_id': drive_file_id, 'drive_link': file_metadata.get('webViewLink'),
            'file_type': file_metadata.get('mimeType',''), 'source': 'drive',
            'uploaded_at': get_indian_time()
        }
        result = db.user_files.insert_one(file_doc)
        return jsonify({'success': True, 'message': 'Drive file linked', 'file_id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ══════════════════════════════════════════════════════════════════════
#  PUBLIC FILE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════
@app.route('/manage_public_files')
@login_required
def manage_public_files():
    try:
        public_files    = []
        drive_connected = 'drive_creds' in session
        if drive_connected:
            try:
                service = get_drive_service()
                if service:
                    db_public_files = list(db.public_files.find({'uploader_email':session['email']}).sort('uploaded_at',-1))
                    for f in db_public_files:
                        try:
                            dm = service.files().get(fileId=f['file_id'], fields='id,name,mimeType,size,webViewLink').execute()
                            f['drive_metadata'] = dm
                        except:
                            f['drive_metadata'] = {'name': f.get('name','Unknown')}
                        public_files.append(f)
            except:
                drive_connected = False
        return render_template('manage_public_files.html', public_files=public_files,
                               drive_connected=drive_connected, notifications=get_user_notifications())
    except Exception as e:
        logger.error(f"manage_public_files error: {e}")
        return render_template('manage_public_files.html', public_files=[], drive_connected=False, notifications=[])

@app.route('/make_file_private/<file_id>', methods=['POST'])
@login_required
def make_file_private_api(file_id):
    try:
        service  = get_drive_service()
        if not service: return jsonify({'error': 'Drive not connected'}), 400
        file_doc = db.public_files.find_one({'file_id':file_id,'uploader_email':session['email']})
        if not file_doc: return jsonify({'error': 'File not found or unauthorized'}), 404
        if make_file_private(service, file_id):
            db.public_files.delete_one({'file_id': file_id})
            db.user_files.update_one({'drive_file_id':file_id,'user_email':session['email']},
                                     {'$set':{'is_public':False,'updated_at':get_indian_time()}})
            return jsonify({'success': True, 'message': 'File made private'})
        return jsonify({'error': 'Failed to make file private'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/delete_public_file/<file_id>', methods=['DELETE'])
@login_required
def delete_public_file(file_id):
    try:
        service  = get_drive_service()
        if not service: return jsonify({'error': 'Drive not connected'}), 400
        file_doc = db.public_files.find_one({'file_id':file_id,'uploader_email':session['email']})
        if not file_doc: return jsonify({'error': 'File not found or unauthorized'}), 404
        if delete_drive_file(service, file_id):
            db.public_files.delete_one({'file_id': file_id})
            db.user_files.delete_one({'drive_file_id':file_id,'user_email':session['email']})
            return jsonify({'success': True, 'message': 'Public file deleted'})
        return jsonify({'error': 'Failed to delete file'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ══════════════════════════════════════════════════════════════════════
#  REMINDERS & SUBSCRIPTIONS
# ══════════════════════════════════════════════════════════════════════
@app.route('/set_reminder', methods=['POST'])
@login_required
def set_reminder():
    try:
        data          = request.get_json(force=True) or {}
        event_id      = data.get('event_id')
        reminder_date = data.get('reminder_date')
        reminder_time = data.get('reminder_time')
        if not all([event_id, reminder_date, reminder_time]):
            return jsonify({'error': 'Missing required fields', 'success': False}), 400
        event = db.events.find_one({'_id': ObjectId(event_id)})
        if not event: return jsonify({'error': 'Event not found', 'success': False}), 404
        user = db.users.find_one({'email': session['email']})
        if not user: return jsonify({'error': 'User not found', 'success': False}), 404
        if '-' in reminder_date and len(reminder_date.split('-')[0]) == 2:
            d, m, y = reminder_date.split('-')
            if len(y) == 4: reminder_date = f"{y}-{m}-{d}"
        if len(reminder_time.split(':')) == 2:
            reminder_time = f"{reminder_time}:00"
        reminder_datetime = IST.localize(datetime.strptime(f"{reminder_date} {reminder_time}", '%Y-%m-%d %H:%M:%S'))
        reminder_datetime_naive = make_timezone_naive(reminder_datetime)
        if reminder_datetime <= get_indian_time_aware():
            return jsonify({'error': 'Reminder time must be in the future', 'success': False}), 400
        existing = db.event_reminders.find_one({'user_id':user['_id'],'event_id':event['_id']})
        if existing:
            db.event_reminders.update_one({'_id':existing['_id']},
                {'$set':{'reminder_datetime':reminder_datetime_naive,'sent':False,'updated_at':get_indian_time()}})
            message = 'Reminder updated successfully'
        else:
            db.event_reminders.insert_one({
                'user_id': user['_id'], 'event_id': event['_id'],
                'reminder_datetime': reminder_datetime_naive, 'sent': False,
                'created_at': get_indian_time(), 'attempt_count': 0
            })
            message = 'Reminder set successfully'
        try:
            msg = Message(subject=f"✅ Reminder Set: {event['event_name']}",
                          sender=app.config['MAIL_USERNAME'], recipients=[user['email']])
            msg.body = (f"Reminder set for {event['event_name']}\n"
                        f"Scheduled: {reminder_datetime.strftime('%d %B %Y at %I:%M %p')} IST")
            mail.send(msg)
        except:
            pass
        return jsonify({'success': True, 'message': f"{message}! Confirmation email sent."})
    except Exception as e:
        logger.error(f"set_reminder error: {e}", exc_info=True)
        return jsonify({'error': f'Server error: {str(e)}', 'success': False}), 500

@app.route('/subscribe_to_event', methods=['POST'])
@login_required
def subscribe_to_event():
    try:
        data     = request.get_json(force=True) or {}
        event_id = data.get('event_id')
        if not event_id: return jsonify({'error': 'Event ID required'}), 400
        event = db.events.find_one({'_id': ObjectId(event_id)})
        if not event: return jsonify({'error': 'Event not found'}), 404
        user = db.users.find_one({'email': session['email']})
        existing = db.event_subscriptions.find_one({'user_id':user['_id'],'event_id':event['_id']})
        if existing: return jsonify({'success': True, 'message': 'Already subscribed'})
        db.event_subscriptions.insert_one({
            'user_id': user['_id'], 'event_id': event['_id'],
            'event_name': event['event_name'], 'subscribed_at': get_indian_time()
        })
        return jsonify({'success': True, 'message': 'Successfully subscribed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/unsubscribe_from_event/<event_id>', methods=['DELETE'])
@login_required
def unsubscribe_from_event(event_id):
    try:
        user   = db.users.find_one({'email': session['email']})
        result = db.event_subscriptions.delete_one({'user_id':user['_id'],'event_id':ObjectId(event_id)})
        if result.deleted_count > 0:
            return jsonify({'success': True, 'message': 'Unsubscribed'})
        return jsonify({'error': 'Subscription not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/my_reminders')
@login_required
def my_reminders():
    try:
        user = db.users.find_one({'email': session['email']})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('user_dashboard'))
        reminders = list(db.event_reminders.find({'user_id':user['_id']}).sort('reminder_datetime',1))
        for reminder in reminders:
            event = db.events.find_one({'_id': reminder['event_id']})
            if event: reminder['event'] = event
        return render_template('my_reminders.html', reminders=reminders,
                               notifications=get_user_notifications())
    except Exception as e:
        logger.error(f"my_reminders error: {e}")
        flash('Error loading reminders', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/delete_reminder/<reminder_id>', methods=['DELETE'])
@login_required
def delete_reminder(reminder_id):
    try:
        user   = db.users.find_one({'email': session['email']})
        result = db.event_reminders.delete_one({'_id':ObjectId(reminder_id),'user_id':user['_id']})
        if result.deleted_count > 0:
            return jsonify({'success': True, 'message': 'Reminder deleted'})
        return jsonify({'error': 'Reminder not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/subscribe', methods=['POST'])
def subscribe():
    try:
        data  = request.get_json(force=True) or {}
        email = data.get('email')
        if not email: return jsonify({"message": "Email is required"}), 400
        db.subscribers.update_one({"email": email},
            {"$set": {"school": data.get('school',''), "subscribed_at": datetime.now()}}, upsert=True)
        return jsonify({"message": "Subscribed successfully"}), 200
    except Exception as e:
        return jsonify({"message": "Subscription failed"}), 500

# ══════════════════════════════════════════════════════════════════════
#  USER PREFERENCES
# ══════════════════════════════════════════════════════════════════════
@app.route('/user_preferences', methods=['GET', 'POST'])
@login_required
def user_preferences():
    if request.method == 'POST':
        try:
            data = request.get_json(force=True) or {}
            db.user_preferences.update_one({'email': session['email']},
                {'$set': {'email_notifications': data.get('email_notifications', True),
                          'reminder_notifications': data.get('reminder_notifications', True),
                          'event_updates': data.get('event_updates', True),
                          'preferred_schools': data.get('preferred_schools', []),
                          'updated_at': get_indian_time()}}, upsert=True)
            return jsonify({'success': True, 'message': 'Preferences updated'})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    try:
        preferences = db.user_preferences.find_one({'email': session['email']}) or {
            'email_notifications': True, 'reminder_notifications': True,
            'event_updates': True, 'preferred_schools': []
        }
        return render_template('user_preferences.html', preferences=preferences,
                               notifications=get_user_notifications())
    except Exception as e:
        flash('Error loading preferences', 'error')
        return redirect(url_for('user_dashboard'))

# ══════════════════════════════════════════════════════════════════════
#  ADMIN DASHBOARD
# ══════════════════════════════════════════════════════════════════════
@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('home'))
    search      = request.args.get('search', '').strip()
    type_filter = request.args.get('type_filter', '').strip()
    role_filter = request.args.get('role_filter', '').strip()
    dept_filter = request.args.get('dept_filter', '').strip()
    query = {}
    if search:      query['email'] = {'$regex': search, '$options': 'i'}
    if type_filter: query['user_type'] = type_filter
    if role_filter == 'none': query['special_role'] = {'$in': [None, '', 'none']}
    elif role_filter:         query['special_role'] = role_filter
    if dept_filter:
        query['$or'] = [
            {'department': {'$regex': dept_filter, '$options': 'i'}},
            {'profile.department': {'$regex': dept_filter, '$options': 'i'}},
        ]
    users_raw = list(db.users.find(query).sort('created_at', -1))
    now = datetime.utcnow()
    users = []
    for u in users_raw:
        u['_id'] = str(u['_id'])
        last_seen  = u.get('last_seen')
        is_active  = bool(last_seen and isinstance(last_seen, datetime) and (now - last_seen).total_seconds() < 900)
        u['is_active_now'] = is_active
        profile = u.get('profile', {}) or {}
        u['dept_display']     = u.get('department') or profile.get('department') or '—'
        u['location_display'] = u.get('location')   or profile.get('location')   or '—'
        u['last_login_display'] = (u['last_login'].strftime('%d %b %Y, %H:%M')
                                   if isinstance(u.get('last_login'), datetime) else '—')
        u['last_seen_display']  = (last_seen.strftime('%d %b %Y, %H:%M')
                                   if isinstance(last_seen, datetime) else '—')
        u['changes_made']  = u.get('changes_made', 0)
        u['total_logins']  = u.get('total_logins', 0)
        if u.get('special_role') == 'leader':               u['display_type'] = 'Leader'
        elif u.get('special_role') == 'office_barrier' or u.get('user_type') == 'core': u['display_type'] = 'Core Team'
        else:                                                u['display_type'] = 'Faculty'
        users.append(u)
    all_departments = sorted(set(
        d for d in (db.users.distinct('department') + db.users.distinct('profile.department')) if d
    ))
    return render_template(
        'admin_dashboard.html', users=users,
        total_users=db.users.count_documents({}),
        pending_users=db.users.count_documents({'approved':{'$ne':True}}),
        approved_users=db.users.count_documents({'approved':True}),
        active_now=sum(1 for u in users if u['is_active_now']),
        pre_assigned_leaders=list(db.pre_assigned_roles.find({'role':'leader'}).sort('assigned_at',-1)),
        pre_assigned_core=list(db.pre_assigned_roles.find({'role':'core'}).sort('assigned_at',-1)),
        all_departments=all_departments, **_get_user_info()
    )

@app.route('/admin/users')
def view_users():
    if session.get('role') != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('login'))
    try:
        return render_template('admin_view_users.html', users=list(db.users.find()))
    except Exception as e:
        logger.error(f"view_users error: {e}")
        return render_template('admin_view_users.html', users=[])

@app.route('/update_user/<user_id>', methods=['POST'])
def update_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    try:
        email        = request.form['email']
        role         = request.form.get('role', 'user')
        user_type    = request.form.get('user_type', 'faculty')
        special_role = request.form.get('special_role', '') or None
        approved     = request.form.get('approved', 'false') == 'true'
        if role not in ['user','admin']:           role = 'user'
        if user_type not in ['faculty','core']:    user_type = 'faculty'
        if special_role and special_role not in ['office_barrier','leader']: special_role = None
        if special_role == 'office_barrier': user_type = 'core'
        elif special_role == 'leader':       user_type = 'faculty'
        elif user_type == 'core':            special_role = 'office_barrier'
        db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {
            'email': email, 'role': role, 'user_type': user_type,
            'special_role': special_role, 'approved': approved, 'updated_at': get_indian_time()
        }})
        core_chat = db.chat_groups.find_one({'group_type': 'core_team'})
        if user_type == 'core' or special_role == 'office_barrier':
            if core_chat:
                db.chat_groups.update_one({'_id':core_chat['_id']},{'$addToSet':{'members':ObjectId(user_id)}})
            else:
                db.chat_groups.insert_one({'name':'Core Team Chat','group_type':'core_team',
                    'description':'Automatic group','created_at':get_indian_time(),
                    'members':[ObjectId(user_id)],'created_by':ObjectId(user_id)})
        else:
            if core_chat:
                db.chat_groups.update_one({'_id':core_chat['_id']},{'$pull':{'members':ObjectId(user_id)}})
        if approved:
            try:
                role_msg = ("You are now a Leader." if special_role=='leader' else
                            "You are now a Core Team member." if special_role=='office_barrier' else
                            "You now have full access.")
                msg = Message(subject="✅ Account Updated",
                              sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f"Your account has been updated.\n\n{role_msg}\n\nLogin: {request.url_root}login"
                mail.send(msg)
            except Exception as e:
                logger.error(f"Update email error: {e}")
        flash('✅ User updated successfully.', 'success')
    except Exception as e:
        logger.error(f"update_user error: {e}", exc_info=True)
        flash(f'Error: {str(e)[:100]}', 'error')
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
            flash('Cannot delete your own account', 'error')
            return redirect(url_for('admin_dashboard'))
        user_email = user['email']
        db.users.delete_one({'_id': ObjectId(user_id)})
        db.user_files.delete_many({'user_email': user_email})
        db.event_reminders.delete_many({'user_id': ObjectId(user_id)})
        db.event_subscriptions.delete_many({'user_id': ObjectId(user_id)})
        db.office_documents.delete_many({'user_id': ObjectId(user_id)})
        db.chat_groups.update_many({'members':ObjectId(user_id)},{'$pull':{'members':ObjectId(user_id)}})
        db.user_preferences.delete_many({'email': user_email})
        db.user_navbars.delete_many({'user_email': user_email})
        db.activity_logs.delete_many({'user_id': ObjectId(user_id)})
        db.direct_messages.delete_many({'$or':[{'sender_id':ObjectId(user_id)},{'receiver_id':ObjectId(user_id)}]})
        flash(f'✅ User {user_email} deleted.', 'success')
    except Exception as e:
        logger.error(f"delete_user error: {e}")
        flash('Error deleting user', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/pre_assign_leader', methods=['POST'])
def pre_assign_leader():
    if session.get('role') != 'admin': return jsonify({'error': 'Access denied'}), 403
    try:
        data   = request.get_json(force=True) or {}
        email  = data.get('email')
        school = data.get('school', '')
        if not email or not email.endswith('@jainuniversity.ac.in'):
            return jsonify({'error': 'Valid @jainuniversity.ac.in email required'}), 400
        if db.users.find_one({'email': email}):
            return jsonify({'error': 'User already registered'}), 400
        if db.pre_assigned_leaders.find_one({'email': email}):
            return jsonify({'message': 'Already pre-assigned'}), 200
        db.pre_assigned_leaders.insert_one({'email':email,'school':school,
            'assigned_by':session['email'],'assigned_at':get_indian_time()})
        try:
            msg = Message(subject="🎓 You've been assigned as Leader - Jain University",
                          sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"You have been assigned as a LEADER.\n\nRegister at: {request.url_root}register\nUse email: {email}"
            mail.send(msg)
        except:
            pass
        return jsonify({'success': True, 'message': 'Leader assigned successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/pre_assign_core', methods=['POST'])
def pre_assign_core():
    if session.get('role') != 'admin': return jsonify({'error': 'Access denied'}), 403
    try:
        data       = request.get_json(force=True) or {}
        email      = data.get('email')
        department = data.get('department', '')
        if not email or not email.endswith('@jainuniversity.ac.in'):
            return jsonify({'error': 'Valid @jainuniversity.ac.in email required'}), 400
        if db.users.find_one({'email': email}):
            return jsonify({'error': 'User already registered'}), 400
        if db.pre_assigned_core.find_one({'email': email}):
            return jsonify({'message': 'Already pre-assigned'}), 200
        db.pre_assigned_core.insert_one({'email':email,'department':department,
            'assigned_by':session['email'],'assigned_at':get_indian_time()})
        try:
            msg = Message(subject="🔷 You've been assigned as Core Team Member - Jain University",
                          sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"You have been assigned as a CORE TEAM MEMBER.\n\nRegister at: {request.url_root}register\nUse email: {email}"
            mail.send(msg)
        except:
            pass
        return jsonify({'success': True, 'message': 'Core member assigned'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/remove_pre_assigned/<type>/<email>', methods=['DELETE'])
def remove_pre_assigned(type, email):
    if session.get('role') != 'admin': return jsonify({'error': 'Access denied'}), 403
    try:
        if type == 'leader':  db.pre_assigned_leaders.delete_one({'email': email})
        elif type == 'core':  db.pre_assigned_core.delete_one({'email': email})
        else: return jsonify({'error': 'Invalid type'}), 400
        return jsonify({'success': True, 'message': 'Removed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ══════════════════════════════════════════════════════════════════════
#  EVENTS MANAGEMENT
# ══════════════════════════════════════════════════════════════════════
@app.route("/admin/events")
def admin_events():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        events = list(db.events.find().sort('event_date', -1))
        for e in events: e["_id"] = str(e["_id"])
        return render_template("admin_events.html", events=events)
    except Exception as e:
        return render_template("admin_events.html", events=[])

@app.route("/add_event", methods=["POST"])
def add_event():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        data       = request.form.to_dict()
        image_file = request.files.get("image")
        pdf_file   = request.files.get("pdf")
        image_path = None; pdf_path = None
        if image_file and image_file.filename:
            fn = secure_filename(image_file.filename)
            ip = os.path.join(app.config["UPLOAD_FOLDER"], fn)
            image_file.save(ip)
            image_path = "/" + ip.replace("\\", "/")
        if pdf_file and pdf_file.filename:
            fn = secure_filename(pdf_file.filename)
            pp = os.path.join(app.config["UPLOAD_FOLDER"], fn)
            pdf_file.save(pp)
            pdf_path = "/" + pp.replace("\\", "/")
        db.events.insert_one({
            "event_name": data.get("event_name"), "description": data.get("description"),
            "school": data.get("school"), "department": data.get("department"),
            "event_action": data.get("event_action"), "event_type": data.get("event_type"),
            "venue": data.get("venue"), "event_date": data.get("event_date"),
            "end_date": data.get("end_date"), "event_time": data.get("event_time","All Day"),
            "image": image_path, "pdf": pdf_path, "created_at": get_indian_time()
        })
        flash('✅ Event added!', 'success')
    except Exception as e:
        logger.error(f"add_event error: {e}")
        flash('Error adding event', 'error')
    return redirect(url_for('admin_events'))

@app.route("/delete_event/<event_id>")
def delete_event(event_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        db.events.delete_one({"_id": ObjectId(event_id)})
        flash('✅ Event deleted!', 'success')
    except:
        flash('Error deleting event', 'error')
    return redirect(url_for('admin_events'))

@app.route("/edit_event/<event_id>", methods=["GET"])
def edit_event(event_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        event = db.events.find_one({"_id": ObjectId(event_id)})
        if not event:
            flash('Event not found.', 'error')
            return redirect(url_for('admin_events'))
        event["_id"] = str(event["_id"])
        return render_template("edit_event.html", event=event)
    except:
        flash('Error loading event', 'error')
        return redirect(url_for('admin_events'))

@app.route("/update_event/<event_id>", methods=["POST"])
def update_event(event_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        data       = request.form.to_dict()
        image_file = request.files.get("image")
        pdf_file   = request.files.get("pdf")
        update_data = {
            "event_name": data.get("event_name"), "description": data.get("description"),
            "school": data.get("school"), "department": data.get("department"),
            "event_action": data.get("event_action"), "event_type": data.get("event_type"),
            "venue": data.get("venue"), "event_date": data.get("event_date"),
            "end_date": data.get("end_date"), "event_time": data.get("event_time","All Day"),
            "updated_at": get_indian_time()
        }
        if image_file and image_file.filename:
            fn = secure_filename(image_file.filename)
            ip = os.path.join(app.config["UPLOAD_FOLDER"], fn)
            image_file.save(ip)
            update_data["image"] = "/" + ip.replace("\\", "/")
        if pdf_file and pdf_file.filename:
            fn = secure_filename(pdf_file.filename)
            pp = os.path.join(app.config["UPLOAD_FOLDER"], fn)
            pdf_file.save(pp)
            update_data["pdf"] = "/" + pp.replace("\\", "/")
        db.events.update_one({"_id": ObjectId(event_id)}, {"$set": update_data})
        flash('✅ Event updated!', 'success')
    except:
        flash('Error updating event', 'error')
    return redirect(url_for('admin_events'))

# ══════════════════════════════════════════════════════════════════════
#  UGC / MONTHLY ENGAGEMENT / NEWSLETTER
# ══════════════════════════════════════════════════════════════════════
@app.route('/edit_ugc', methods=['GET', 'POST'])
def edit_ugc():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            text_data           = request.form.get('text_data')
            external_link       = request.form.get('external_link')
            selected_categories = request.form.getlist('categories')
            uploaded_files      = []
            for file in request.files.getlist('files'):
                if file and allowed_file(file.filename):
                    fn = secure_filename(file.filename)
                    fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
                    file.save(fp)
                    uploaded_files.append(fn)
            db.ugc_data.insert_one({
                "admin_email": session['email'], "uploaded_at": get_indian_time(),
                "categories": selected_categories, "text_data": text_data,
                "external_link": external_link, "files": uploaded_files
            })
            flash('✅ UGC data uploaded.', 'success')
            return redirect(url_for('edit_ugc'))
        except Exception as e:
            flash('Error uploading data', 'error')
    try:
        return render_template('edit_ugc.html', records=list(db.ugc_data.find().sort('uploaded_at',-1)))
    except:
        return render_template('edit_ugc.html', records=[])

@app.route('/edit_ugc_record/<record_id>', methods=['GET', 'POST'])
def edit_ugc_record(record_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        record = db.ugc_data.find_one({'_id': ObjectId(record_id)})
        if not record:
            flash('Record not found', 'error')
            return redirect(url_for('edit_ugc'))
        if request.method == 'POST':
            text_data           = request.form.get('text_data')
            external_link       = request.form.get('external_link')
            selected_categories = request.form.getlist('categories')
            updated_files       = record.get('files', [])
            for file in request.files.getlist('files'):
                if file and allowed_file(file.filename):
                    fn = secure_filename(file.filename)
                    fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
                    file.save(fp)
                    updated_files.append(fn)
            db.ugc_data.update_one({'_id':ObjectId(record_id)},
                {'$set':{'text_data':text_data,'external_link':external_link,
                          'categories':selected_categories,'files':updated_files}})
            flash('✅ UGC record updated.', 'success')
            return redirect(url_for('edit_ugc'))
        return render_template('edit_ugc_record.html', record=record)
    except Exception as e:
        flash('Error processing request', 'error')
        return redirect(url_for('edit_ugc'))

@app.route('/delete_ugc/<record_id>', methods=['GET'])
def delete_ugc(record_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        db.ugc_data.delete_one({'_id': ObjectId(record_id)})
        flash('✅ UGC record deleted.', 'success')
    except:
        flash('Error deleting record', 'error')
    return redirect(url_for('edit_ugc'))

@app.route('/edit_monthly', methods=['GET', 'POST'])
def edit_monthly():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            heading     = request.form.get('heading','').strip()
            description = request.form.get('description','').strip()
            school      = request.form.get('school','')
            department  = request.form.get('department','')
            tags        = request.form.getlist('tags')
            uploaded_files = []
            for file in [request.files.get('image_file'), request.files.get('pdf_file')]:
                if file and file.filename and allowed_file(file.filename):
                    fn = secure_filename(file.filename)
                    fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
                    file.save(fp)
                    uploaded_files.append(fn)
            db.monthly_engagement.insert_one({
                "admin_email": session.get('email'), "uploaded_at": get_indian_time(),
                "heading": heading, "description": description, "school": school,
                "department": department, "tags": tags, "files": uploaded_files
            })
            flash('✅ Monthly engagement uploaded.', 'success')
            return redirect(url_for('edit_monthly'))
        except:
            flash('Error uploading data', 'error')
    try:
        return render_template('edit_monthly.html', records=list(db.monthly_engagement.find().sort('uploaded_at',-1)))
    except:
        return render_template('edit_monthly.html', records=[])

@app.route('/edit_record/<record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        record = db.monthly_engagement.find_one({'_id': ObjectId(record_id)})
        if not record:
            flash('Record not found', 'error')
            return redirect(url_for('edit_monthly'))
        if request.method == 'POST':
            updated = {}
            for field in ['heading','description','school','department']:
                if field in request.form:
                    updated[field] = request.form.get(field,'').strip()
            if 'tags' in request.form:
                updated['tags'] = request.form.getlist('tags')
            if updated:
                db.monthly_engagement.update_one({'_id':ObjectId(record_id)},{'$set':updated})
                flash('✅ Record updated.', 'success')
            return redirect(url_for('edit_monthly'))
        return render_template('edit_record.html', record=record)
    except:
        flash('Error processing request', 'error')
        return redirect(url_for('edit_monthly'))

@app.route('/delete_record/<record_id>', methods=['POST'])
def delete_record(record_id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        record = db.monthly_engagement.find_one({'_id': ObjectId(record_id)})
        if record and 'files' in record:
            for fn in record['files']:
                fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
                if os.path.exists(fp): os.remove(fp)
        db.monthly_engagement.delete_one({'_id': ObjectId(record_id)})
        flash('✅ Record deleted.', 'success')
    except:
        flash('Error deleting record', 'error')
    return redirect(url_for('edit_monthly'))

@app.route('/usernewsletters')
def usernewsletters():
    try:
        return render_template('user_newsletters.html', records=list(db.newsletters.find().sort('uploaded_at',-1)))
    except:
        return render_template('user_newsletters.html', records=[])

@app.route('/newsletter', methods=['GET', 'POST'])
def newsletter():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            title               = request.form.get('title')
            description         = request.form.get('description')
            tags                = request.form.getlist('tags')
            image_file          = request.files.get('image')
            recipient_email_raw = request.form.get('recipient_email','').strip()
            email_list = []
            def is_valid_email(e):
                return re.match(r"[^@]+@[^@]+\.[^@]+", e)
            try:
                parsed = json.loads(recipient_email_raw)
                email_list = [e['value'].strip() for e in parsed if 'value' in e and is_valid_email(e['value'].strip())]
            except:
                email_list = [e.strip() for e in recipient_email_raw.split(',') if is_valid_email(e.strip())]
            if not email_list:
                flash("❌ No valid email addresses.", "error")
                return redirect(url_for('newsletter'))
            image_filename = None
            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            db.newsletters.insert_one({
                "admin_email": session['email'], "uploaded_at": get_indian_time(),
                "title": title, "description": description, "tags": tags,
                "image": image_filename, "recipients": email_list
            })
            send_newsletter_email(title, description, image_filename, email_list)
            flash('✅ Newsletter sent.', 'success')
            return redirect(url_for('newsletter'))
        except Exception as e:
            logger.error(f"newsletter POST error: {e}")
            flash('Error creating newsletter', 'error')
    try:
        return render_template('admin_newsletter.html', records=list(db.newsletters.find().sort('uploaded_at',-1)))
    except:
        return render_template('admin_newsletter.html', records=[])

@app.route('/edit_newsletter/<id>', methods=['GET'])
def edit_newsletter(id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        record = db.newsletters.find_one({'_id': ObjectId(id)})
        if not record:
            flash('Newsletter not found.', 'error')
            return redirect(url_for('newsletter'))
        return render_template('edit_newsletter.html', record=record)
    except:
        flash('Error loading newsletter', 'error')
        return redirect(url_for('newsletter'))

@app.route('/update_newsletter/<id>', methods=['POST'])
def update_newsletter(id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        record = db.newsletters.find_one({'_id': ObjectId(id)})
        if not record:
            flash('Newsletter not found.', 'error')
            return redirect(url_for('newsletter'))
        title      = request.form.get('title')
        description= request.form.get('description')
        tags       = request.form.getlist('tags')
        recipients = [e.strip() for e in request.form.get('recipient_email','').split(',') if e.strip()]
        image_file = request.files.get('image')
        image_filename = record.get('image')
        if image_file and image_file.filename:
            image_filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        db.newsletters.update_one({'_id':ObjectId(id)},
            {'$set':{'title':title,'description':description,'tags':tags,
                     'recipients':recipients,'image':image_filename,'updated_at':get_indian_time()}})
        flash('✅ Newsletter updated!', 'success')
        return redirect(url_for('newsletter'))
    except:
        flash('Error updating newsletter', 'error')
        return redirect(url_for('newsletter'))

@app.route('/newsletter/delete/<id>')
def delete_newsletter(id):
    if session.get('role') != 'admin': return redirect(url_for('login'))
    try:
        db.newsletters.delete_one({"_id": ObjectId(id)})
        flash("✅ Newsletter deleted.", 'success')
    except:
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
            db.subscribers.insert_one({'email': email, 'subscribed_at': get_indian_time()})
            try:
                msg = Message(subject="🎉 Subscribed to Jain University Newsletter",
                              sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = "Thank you for subscribing! You'll receive updates from Jain University."
                mail.send(msg)
                flash("✅ Subscribed successfully!", "success")
            except:
                flash("Subscribed, but confirmation email failed.", "warning")
        return redirect(request.referrer or url_for('jainevents'))
    except:
        flash('Error processing subscription', 'error')
        return redirect(request.referrer or url_for('jainevents'))

@app.route('/newsletter_view/<newsletter_id>')
def newsletter_view(newsletter_id):
    try:
        news = db.newsletters.find_one({'_id': ObjectId(newsletter_id)})
        if not news:
            flash('Newsletter not found', 'error')
            return redirect(url_for('newsletter_page'))
        news['_id'] = str(news['_id'])
        news['formatted_date'] = news['uploaded_at'].strftime('%B %d, %Y') if isinstance(news.get('uploaded_at'), datetime) else str(news.get('uploaded_at',''))
        return render_template('newsletter_detail.html', news=news,
                               user_logged_in='email' in session,
                               user_email=session.get('email'),
                               user_navbar=get_user_navbar(session.get('email','')) if session.get('email') else [])
    except Exception as e:
        logger.error(f"newsletter_view error: {e}", exc_info=True)
        flash('Error loading newsletter', 'error')
        return redirect(url_for('newsletter_page'))

@app.route('/newsletters')
def newsletter_page():
    try:
        records = list(db.newsletters.find().sort('uploaded_at', -1))
        for article in records:
            article['_id'] = str(article['_id'])
            article['formatted_date'] = article['uploaded_at'].strftime('%B %d, %Y') if isinstance(article.get('uploaded_at'), datetime) else str(article.get('uploaded_at',''))
        return render_template('newsletter_page.html', records=records,
                               user_logged_in='email' in session,
                               user_email=session.get('email'),
                               user_navbar=get_user_navbar(session.get('email','')) if session.get('email') else [])
    except Exception as e:
        logger.error(f"newsletter_page error: {e}", exc_info=True)
        return render_template('newsletter_page.html', records=[], user_logged_in='email' in session, user_email=session.get('email'))

# ══════════════════════════════════════════════════════════════════════
#  API ENDPOINTS — EVENTS
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/events')
def get_events():
    try:
        current_date = datetime.now().strftime('%Y-%m-%d')
        events = list(db.events.find(
            {"$or":[{"event_date":{"$gte":current_date}},{"end_date":{"$gte":current_date}}]}
        ).sort("event_date", 1))
        return jsonify([{
            'id': str(e['_id']), 'event_name': e.get('event_name',''),
            'event_date': e.get('event_date',''), 'end_date': e.get('end_date',''),
            'event_time': e.get('event_time','All Day'), 'venue': e.get('venue','TBA'),
            'description': e.get('description',''), 'event_type': e.get('event_type',''),
            'school': e.get('school',''), 'department': e.get('department',''),
            'image': e.get('image',''), 'pdf': e.get('pdf','')
        } for e in events])
    except:
        return jsonify([])

@app.route('/api/events/<event_id>')
def get_event(event_id):
    try:
        event = db.events.find_one({"_id": ObjectId(event_id)})
        if not event: return jsonify({'error': 'Event not found'}), 404
        return jsonify({'id': str(event['_id']), 'event_name': event.get('event_name',''),
                        'event_date': event.get('event_date',''), 'end_date': event.get('end_date',''),
                        'event_time': event.get('event_time','All Day'), 'venue': event.get('venue','TBA'),
                        'description': event.get('description',''), 'event_type': event.get('event_type',''),
                        'school': event.get('school',''), 'department': event.get('department',''),
                        'image': event.get('image',''), 'pdf': event.get('pdf','')})
    except:
        return jsonify({'error': 'Event not found'}), 404

@app.route("/api/events/today")
def get_today_events():
    try:
        today = get_today_ist_string()
        events_data = []
        for event in list(db.events.find({})):
            event_date = normalize_date(event.get("event_date",""))
            end_date   = normalize_date(event.get("end_date","")) if event.get("end_date") else ""
            if event_date == today or (end_date and event_date <= today <= end_date):
                events_data.append({
                    "id": str(event["_id"]), "event_name": event.get("event_name",""),
                    "event_date": event_date, "event_time": event.get("event_time","All Day"),
                    "venue": event.get("venue","TBA")
                })
        return jsonify(events_data)
    except:
        return jsonify([])

@app.route('/api/events/filter')
def filter_events():
    try:
        query = {}
        department = request.args.get('department')
        school     = request.args.get('school')
        start_date = request.args.get('start_date')
        end_date   = request.args.get('end_date')
        event_type = request.args.get('event_type')
        if department: query['department'] = department
        if school:     query['school']     = school
        if event_type: query['event_type'] = event_type
        if start_date and end_date: query['event_date'] = {'$gte':start_date,'$lte':end_date}
        elif start_date:            query['event_date'] = {'$gte':start_date}
        elif end_date:              query['event_date'] = {'$lte':end_date}
        events = list(db.events.find(query).sort('event_date', 1))
        return jsonify([{'id':str(e['_id']),'event_name':e.get('event_name',''),
                         'event_date':e.get('event_date',''),'end_date':e.get('end_date',''),
                         'event_time':e.get('event_time','All Day'),'venue':e.get('venue',''),
                         'description':e.get('description',''),'event_type':e.get('event_type',''),
                         'school':e.get('school',''),'department':e.get('department',''),
                         'image':e.get('image',''),'pdf':e.get('pdf','')} for e in events])
    except:
        return jsonify([])

@app.route('/api/departments')
def get_departments():
    try: return jsonify(sorted([d for d in db.events.distinct('department') if d]))
    except: return jsonify([])

@app.route('/api/schools')
def get_schools():
    try: return jsonify(sorted([s for s in db.events.distinct('school') if s]))
    except: return jsonify([])

# ══════════════════════════════════════════════════════════════════════
#  NOTIFICATIONS API
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/notifications')
@login_required
def api_notifications():
    try:
        notifications = get_user_notifications()
        return jsonify({'success': True, 'notifications': notifications, 'count': len(notifications)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/mark_notification_read/<notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    return jsonify({'success': True})

# ══════════════════════════════════════════════════════════════════════
#  DEPARTMENT REPOSITORY
# ══════════════════════════════════════════════════════════════════════
@app.route('/dept_repo')
@login_required
def dept_repo():
    ui = _get_user_info()
    if not ui['approved']:
        flash('Your account is pending approval.', 'warning')
        return redirect(url_for('home'))
    _track_activity()
    today_str   = date.today().isoformat()
    user_dept   = session.get('user_department', '')
    docs        = list(db.dept_repo_docs.find({'departments':user_dept}).sort('uploaded_at',-1)) if user_dept else []
    for d in docs: d['_id'] = str(d['_id'])
    recent_count  = sum(1 for d in docs if isinstance(d.get('uploaded_at'), datetime) and (datetime.utcnow()-d['uploaded_at']).days<=30)
    faculty_count = sum(1 for d in docs if d.get('source') == 'faculty')
    return render_template('dept_repo.html', docs=docs, today_str=today_str,
                           recent_count=recent_count, faculty_count=faculty_count, **ui)

@app.route('/faculty_upload', methods=['POST'])
@login_required
def faculty_upload():
    if not session.get('approved'): return jsonify({'success':False,'error':'Account not approved'}), 403
    user = db.users.find_one({'email': session['email']})
    if not user: return jsonify({'success':False,'error':'User not found'}), 404
    title       = request.form.get('title','').strip()
    description = request.form.get('description','').strip()
    doc_date    = request.form.get('doc_date','').strip()
    uploaded_files = []
    file = request.files.get('file')
    if file and file.filename:
        if not allowed_file(file.filename):
            flash('File type not allowed.', 'error')
            return redirect(url_for('dept_repo'))
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        ufn  = f"{base}_{int(datetime.utcnow().timestamp())}{ext}"
        fp   = os.path.join(app.config.get('UPLOAD_FOLDER','static/uploads'), ufn)
        file.save(fp)
        uploaded_files.append(ufn)
    user_dept = session.get('user_department', (user.get('profile',{}) or {}).get('department',''))
    db.dept_repo_docs.insert_one({
        'title': title or None, 'description': description or None,
        'departments': [user_dept] if user_dept else [],
        'doc_date': doc_date or None, 'files': uploaded_files,
        'uploaded_by': session['email'], 'uploaded_by_dept': user_dept,
        'source': 'faculty', 'uploaded_at': datetime.utcnow()
    })
    flash('✅ Document submitted and visible to the core team.', 'success')
    return redirect(url_for('dept_repo'))

@app.route('/core_repo')
@_core_required
def core_repo():
    ui        = _get_user_info()
    today_str = date.today().isoformat()
    _track_activity()
    repo_docs = list(db.dept_repo_docs.find({}).sort('uploaded_at',-1))
    for d in repo_docs: d['_id'] = str(d['_id'])
    faculty_submissions = [d for d in repo_docs if d.get('source') == 'faculty']
    core_uploads        = [d for d in repo_docs if d.get('source') != 'faculty']
    seen, all_depts_with_docs = set(), []
    for d in repo_docs:
        for dept in (d.get('departments') or []):
            if dept not in seen:
                seen.add(dept)
                all_depts_with_docs.append(dept)
    return render_template('core_repo.html', repo_docs=repo_docs,
                           faculty_submissions=faculty_submissions, core_uploads=core_uploads,
                           today_str=today_str, all_depts_with_docs=all_depts_with_docs,
                           faculty_count=len(faculty_submissions), **ui)

@app.route('/core_repo_upload', methods=['POST'])
@_core_required
def core_repo_upload():
    title       = request.form.get('title','').strip()
    description = request.form.get('description','').strip()
    doc_date    = request.form.get('doc_date','').strip()
    end_date    = request.form.get('end_date','').strip()
    departments = request.form.getlist('departments')
    if not departments:
        flash('Please select at least one department.', 'error')
        return redirect(url_for('core_repo'))
    uploaded_files = []
    file = request.files.get('file')
    if file and file.filename:
        if not _allowed(file.filename):
            flash('File type not allowed.', 'error')
            return redirect(url_for('core_repo'))
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        ufn  = f"{base}_{int(datetime.utcnow().timestamp())}{ext}"
        fp   = os.path.join(app.config.get('UPLOAD_FOLDER','uploads'), ufn)
        file.save(fp)
        uploaded_files.append(ufn)
    db.dept_repo_docs.insert_one({
        'title': title or None, 'description': description or None,
        'departments': departments, 'doc_date': doc_date or None,
        'end_date': end_date or None, 'files': uploaded_files,
        'uploaded_by': session.get('email',''), 'source': 'core',
        'uploaded_at': datetime.utcnow()
    })
    dept_label = ', '.join(d.replace('Department of ','') for d in departments[:3])
    if len(departments) > 3: dept_label += f' +{len(departments)-3} more'
    _track_activity(f"Core upload: {title or 'Untitled'} → {dept_label}")
    flash(f'✅ Document uploaded to: {dept_label}', 'success')
    return redirect(url_for('core_repo'))

@app.route('/core_repo_delete', methods=['POST'])
@_core_required
def core_repo_delete():
    data   = request.get_json(force=True) or {}
    doc_id = data.get('doc_id')
    if not doc_id: return jsonify({'success': False, 'error': 'Missing document ID'})
    try:
        doc    = db.dept_repo_docs.find_one({'_id': ObjectId(doc_id)})
        result = db.dept_repo_docs.delete_one({'_id': ObjectId(doc_id)})
        if result.deleted_count:
            _track_activity(f"Deleted doc: {doc.get('title','Untitled') if doc else doc_id}")
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Document not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ══════════════════════════════════════════════════════════════════════
#  UTILITY / DEBUG ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route('/init_core_chat')
@login_required
def init_core_chat():
    if session.get('role') != 'admin': return jsonify({'error': 'Access denied'}), 403
    try:
        existing = db.chat_groups.find_one({'group_type': 'core_team'})
        if existing:
            return jsonify({'message': 'Core team chat already exists', 'group_id': str(existing['_id'])})
        core_members = list(db.users.find({'$or':[{'user_type':'core'},{'special_role':'office_barrier'}],'approved':True}))
        group_id = db.chat_groups.insert_one({
            'name': 'Core Team Chat', 'group_type': 'core_team',
            'description': 'Automatic chat group', 'created_at': get_indian_time(),
            'created_by': None, 'members': [m['_id'] for m in core_members]
        }).inserted_id
        return jsonify({'success': True, 'message': 'Core team chat created',
                        'group_id': str(group_id), 'members_added': len(core_members)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/my-session')
@login_required
def debug_my_session():
    try:
        user = db.users.find_one({'email': session['email']})
        if not user: return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'session':  {'email':session.get('email'),'role':session.get('role'),
                         'user_type':session.get('user_type'),'special_role':session.get('special_role'),
                         'approved':session.get('approved')},
            'database': {'email':user.get('email'),'role':user.get('role'),
                         'user_type':user.get('user_type'),'special_role':user.get('special_role'),
                         'approved':user.get('approved')},
            'is_leader':     is_leader(),
            'is_core_member':is_core_member()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/check-collections')
@login_required
def debug_check_collections():
    try:
        return jsonify({
            'collections':  db.list_collection_names(),
            'users_count':  db.users.count_documents({}),
            'leaders_count':db.users.count_documents({'special_role':'leader'}),
            'core_count':   db.users.count_documents({'$or':[{'user_type':'core'},{'special_role':'office_barrier'}]}),
            'tasks_count':  db.tasks.count_documents({}),
            'docs_count':   db.office_documents.count_documents({}),
            'dm_count':     db.direct_messages.count_documents({})
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/users')
def debug_users():
    if session.get('role') != 'admin': return jsonify({'error': 'Admin access required'}), 403
    try:
        users = list(db.users.find({}))
        return jsonify({'total_users': len(users), 'users': [
            {'id':str(u.get('_id')),'email':u.get('email'),'role':u.get('role'),
             'user_type':u.get('user_type'),'special_role':u.get('special_role'),'approved':u.get('approved',False)}
            for u in users
        ]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/setup/admin')
def setup_admin():
    try:
        admin_exists = db.users.find_one({'role': 'admin'})
        if admin_exists:
            return jsonify({'message': 'Admin already exists', 'admin_email': admin_exists.get('email')})
        admin_email    = 'admin@jainuniversity.ac.in'
        admin_password = 'admin123'
        db.users.insert_one({
            'email': admin_email, 'password': generate_password_hash(admin_password),
            'role': 'admin', 'user_type': 'admin', 'special_role': None, 'approved': True,
            'is_online': True, 'last_seen': get_indian_time(), 'created_at': get_indian_time()
        })
        return jsonify({'message': 'Admin created!', 'email': admin_email, 'password': admin_password,
                        'note': 'Change the password immediately after login!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/debug/events")
def debug_events():
    try:
        today_str = get_today_ist_string()
        events    = list(db.events.find({}).limit(15))
        samples   = []
        for ev in events:
            raw  = ev.get("event_date","NO_DATE")
            norm = normalize_date(str(raw))
            samples.append({'name':ev.get("event_name",""),'raw_date':str(raw),'normalized':norm,
                            'is_today':norm==today_str,'is_future':norm>today_str if norm else False})
        return jsonify({'today_ist':today_str,'total_events':db.events.count_documents({}),'event_samples':samples})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  CRON / TEST EMAIL
# ══════════════════════════════════════════════════════════════════════
@app.route('/cron/send-reminders')
def cron_send_reminders():
    api_key = request.args.get('key')
    if api_key != os.environ.get('CRON_API_KEY', 'your-secret-key-here'):
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        with app.app_context():
            send_event_reminders()
        return jsonify({'success': True, 'message': 'Reminders sent'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/test-email')
def test_email():
    try:
        msg = Message(subject="Test Email", sender=app.config['MAIL_USERNAME'],
                      recipients=[app.config['MAIL_USERNAME']])
        msg.body = "Test email from reminder system."
        mail.send(msg)
        return jsonify({"success": True, "message": "Test email sent"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════
#  FILE SERVING
# ══════════════════════════════════════════════════════════════════════
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.error(f"File serve error {filename}: {e}")
        return "File not found", 404

# ══════════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ══════════════════════════════════════════════════════════════════════
@app.errorhandler(401)
def unauthorized(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    return redirect(url_for('home'))

@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'File too large. Maximum size is 50MB.'}), 413
    flash('File too large. Maximum size is 50MB.', 'error')
    return redirect(request.referrer or url_for('home'))

# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    create_indexes()
    is_local = os.environ.get('FLASK_ENV', 'production') == 'development'
    if is_local:
        scheduler = BackgroundScheduler(timezone=IST)
        @scheduler.scheduled_job('interval', seconds=30, id='reminder_check')
        def scheduled_reminders():
            with app.app_context():
                try:
                    send_event_reminders()
                except Exception as e:
                    logger.error(f"[SCHEDULER ERROR] {e}")
        scheduler.start()
        logger.info("✅ Scheduler started (DEV)")
    else:
        logger.info("⚠️ Production — use /cron/send-reminders instead of APScheduler")
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=is_local, use_reloader=False)