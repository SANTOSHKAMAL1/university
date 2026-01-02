import re
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask, json, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson import ObjectId
from datetime import datetime, timedelta
from config import Config
from utils import get_indian_time
from flask_mail import Mail, Message
import random
from apscheduler.schedulers.background import BackgroundScheduler
import pandas as pd
from io import StringIO, BytesIO
import logging
import requests
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_proto=1,
    x_host=1
)
# Google OAuth imports
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize app
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'your_secret_key_here_change_in_production'

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

# Allowed file type check
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'info.loginpanel@gmail.com'
app.config['MAIL_PASSWORD'] = 'wedbfepklgtwtugf'
mail = Mail(app)

# Google OAuth Scopes
DRIVE_SCOPES = [
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive'
]
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# ===================== HELPER FUNCTIONS =====================
def get_drive_service():
    """Get authenticated Google Drive service"""
    if 'drive_creds' not in session:
        return None
    
    creds_data = session['drive_creds']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret'],
        scopes=creds_data['scopes']
    )
    
    return build('drive', 'v3', credentials=creds)

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
        return True
    except Exception as e:
        logger.error(f"Error making file public: {e}")
        return False

def get_drive_stats():
    """Get Drive statistics for user dashboard"""
    try:
        service = get_drive_service()
        if not service:
            return {'total_files': 0, 'recent_uploads': []}
        
        # Get recent uploads (last 7 days)
        seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat() + 'Z'
        recent = service.files().list(
            q=f"createdTime >= '{seven_days_ago}' and trashed=false",
            pageSize=10,
            orderBy="createdTime desc",
            fields="files(id, name, mimeType, createdTime, parents, webViewLink)"
        ).execute()
        
        recent_files = recent.get('files', [])
        
        # Get folder names for recent files
        for file in recent_files:
            if file.get('parents'):
                try:
                    folder = service.files().get(
                        fileId=file['parents'][0],
                        fields='name'
                    ).execute()
                    file['folder_name'] = folder.get('name', 'Root')
                except:
                    file['folder_name'] = 'Root'
            else:
                file['folder_name'] = 'Root'
        
        # Get total count
        all_files = service.files().list(
            q="trashed=false",
            pageSize=1000,
            fields="files(id)"
        ).execute()
        
        return {
            'total_files': len(all_files.get('files', [])),
            'recent_uploads': recent_files
        }
        
    except Exception as e:
        logger.error(f"Error getting drive stats: {e}")
        return {'total_files': 0, 'recent_uploads': []}

def get_user_navbar(email):
    """Get user's custom navbar items"""
    nav = db.user_navbars.find_one({"user_email": email})
    return nav.get('items', []) if nav else []

# FIXED CONTEXT PROCESSOR - ONLY ONE VERSION
@app.context_processor
def inject_user_navbar():
    """Inject user navbar into all templates - FIXED to prevent recursion"""
    if 'email' in session and session.get('role') == 'user':
        try:
            navbar = get_user_navbar(session['email'])
            return dict(user_navbar=navbar)
        except Exception as e:
            logger.error(f"Error injecting navbar: {e}")
            return dict(user_navbar=[])
    return dict(user_navbar=[])

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
            'created_at': datetime.now()
        }
        
        cleaned_records.append(clean_record)
    
    if errors:
        return False, errors, None
    
    return True, [], cleaned_records

# ===================== SCHEDULED TASKS =====================
def send_event_reminders():
    """Send event reminders based on user preferences"""
    try:
        now = datetime.now()
        
        reminders = list(db.event_reminders.find({
            'reminder_datetime': {'$lte': now},
            'sent': False
        }))
        
        for reminder in reminders:
            try:
                event = db.events.find_one({'_id': reminder['event_id']})
                if not event:
                    continue
                
                user = db.users.find_one({'_id': reminder['user_id']})
                if not user:
                    continue
                
                msg = Message(
                    subject=f"🔔 Event Reminder: {event['event_name']}",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[user['email']]
                )
                
                msg.html = f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #04043a;">⏰ Event Reminder</h2>
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
                        <h3 style="color: #04043a; margin-top: 0;">{event['event_name']}</h3>
                        <p><strong>📅 Date:</strong> {event['event_date']}</p>
                        <p><strong>⏰ Time:</strong> {event.get('event_time', 'All Day')}</p>
                        <p><strong>📍 Venue:</strong> {event['venue']}</p>
                        <p><strong>🏢 Department:</strong> {event.get('department', 'N/A')}</p>
                        <p><strong>📝 Description:</strong> {event.get('description', '')}</p>
                    </div>
                    <p>This is your scheduled reminder for the upcoming event!</p>
                    <hr>
                    <small style="color: #666;">Jain University Portal - Office of Academics</small>
                </div>
                """
                
                mail.send(msg)
                
                db.event_reminders.update_one(
                    {'_id': reminder['_id']},
                    {'$set': {'sent': True, 'sent_at': now}}
                )
                
                logger.info(f"Sent reminder to {user['email']} for event {event['event_name']}")
                
            except Exception as e:
                logger.error(f"Error sending reminder: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Error in send_event_reminders: {e}")

def send_daily_event_emails():
    """Send daily digest of upcoming events to subscribers"""
    today = datetime.today().strftime("%Y-%m-%d")
    upcoming = (datetime.today() + timedelta(days=7)).strftime("%Y-%m-%d")
    
    subscribers = list(db.subscribers.find())
    events = list(db.events.find({
        "event_date": {"$gte": today, "$lte": upcoming}
    }))
    
    for sub in subscribers:
        try:
            msg = Message(
                "Upcoming University Events", 
                sender=app.config['MAIL_USERNAME'], 
                recipients=[sub['email']]
            )
            body = "Hello,\n\nHere are today's and upcoming events:\n\n"
            for e in events:
                if not sub.get('school') or e.get('school') == sub.get('school'):
                    body += f"- {e['event_name']} on {e['event_date']} at {e['venue']}\n"
            msg.body = body
            mail.send(msg)
        except Exception as e:
            logger.error(f"Error sending daily email to {sub['email']}: {e}")

# ===================== EXCEL UPLOAD WITH VALIDATION =====================
@app.route("/upload_events_excel", methods=["POST"])
def upload_events_excel():
    """Upload and process Excel file with events"""
    if session.get('role') != 'admin':
        flash("Access denied. Admin only.", "error")
        return redirect(url_for('login'))

    file = request.files.get("excel_file")
    if not file or file.filename == '':
        flash("❌ No file selected. Please choose an Excel file.", "error")
        return redirect(url_for('admin_events'))

    # Validate file extension
    if not allowed_file(file.filename):
        flash("❌ Invalid file type. Please upload .xlsx, .xls, or .csv file.", "error")
        return redirect(url_for('admin_events'))

    try:
        # Read Excel/CSV file
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file, sheet_name=0)
        
        if df.empty:
            flash("❌ Excel file is empty.", "error")
            return redirect(url_for('admin_events'))

        # Validate data
        is_valid, errors, cleaned_records = validate_excel_data(df)
        
        if not is_valid:
            error_msg = "❌ Validation errors:\n" + "\n".join(errors[:10])
            if len(errors) > 10:
                error_msg += f"\n... and {len(errors) - 10} more errors"
            flash(error_msg, "error")
            return redirect(url_for('admin_events'))

        # Insert into MongoDB
        if cleaned_records:
            result = db.events.insert_many(cleaned_records)
            flash(f"✅ Success! Added {len(result.inserted_ids)} events to the database.", "success")
            logger.info(f"Uploaded {len(result.inserted_ids)} events from Excel file")
        else:
            flash("❌ No valid records found in the file.", "error")

    except pd.errors.EmptyDataError:
        flash("❌ Excel file is empty.", "error")
    except Exception as e:
        logger.error(f"Error uploading Excel: {str(e)}")
        flash(f"❌ Error processing file: {str(e)}", "error")

    return redirect(url_for('admin_events'))

@app.route("/validate_excel_preview", methods=["POST"])
def validate_excel_preview():
    """Preview and validate Excel before uploading"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    file = request.files.get("excel_file")
    if not file:
        return jsonify({'error': 'No file provided'}), 400

    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file, sheet_name=0)
        
        is_valid, errors, cleaned_records = validate_excel_data(df)
        
        # Prepare preview data (first 5 records)
        preview_data = []
        if cleaned_records:
            for record in cleaned_records[:5]:
                preview_data.append({
                    'event_name': record['event_name'],
                    'event_date': record['event_date'],
                    'school': record['school'],
                    'department': record['department']
                })
        
        return jsonify({
            'valid': is_valid,
            'total_rows': len(df),
            'valid_records': len(cleaned_records) if cleaned_records else 0,
            'errors': errors[:10],
            'error_count': len(errors),
            'preview': preview_data
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400

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
            
            msg = Message('Your OTP for Registration', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Your OTP is: {otp}\nPlease use this to complete your registration.'
            mail.send(msg)
            
            session['step'] = 2
            flash('OTP sent to your email. Please check and enter it.', 'info')
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

@app.route('/disconnect-google')
def disconnect_google():
    """Completely disconnect all Google OAuth connections"""
    if 'role' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'drive_creds' in session:
            try:
                creds_data = session['drive_creds']
                requests.post(
                    'https://oauth2.googleapis.com/revoke',
                    params={'token': creds_data['token']},
                    headers={'content-type': 'application/x-www-form-urlencoded'}
                )
            except Exception as e:
                logger.warning(f"Could not revoke Drive token: {e}")

        session.pop('drive_creds', None)
        session.pop('gmail_creds', None)
        session.modified = True

        flash('✅ All Google connections have been disconnected.', 'success')
        return redirect(url_for('user_dashboard'))

    except Exception as e:
        logger.error(f"Error disconnecting Google: {e}")
        flash('Error disconnecting Google services', 'error')
        return redirect(url_for('user_dashboard'))

# ===================== MAIN PAGES =====================
@app.route('/')
def home():
    records = list(db.ugc_data.find().sort('uploaded_at', -1))
    monthly_records = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    newsletter_records = list(db.newsletters.find().sort('uploaded_at', -1))
    events = list(db.events.find().sort('event_date', 1))
    public_files = list(db.public_files.find().sort('uploaded_at', -1).limit(20))
    
    today = datetime.now().date()
    
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

@app.route('/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    email = data.get('email')
    school = data.get('school', '')

    if not email:
        return jsonify({"message": "Email is required"}), 400

    db.subscribers.update_one(
        {"email": email},
        {"$set": {"school": school}},
        upsert=True
    )

    return jsonify({"message": "Subscribed successfully"}), 200

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/monthlyengagement')
def monthlyengagement():
    events = list(db.monthly_engagement.find())
    return render_template('monthly.html', monthly_records=events)

@app.route('/ugc')
def ugc():
    return render_template('ugc.html')

@app.route('/base_user.html')
def base_user():
    return render_template('base_user.html')

@app.route('/jainevents')
def jainevents():
    events = list(db.events.find().sort('event_date', 1))
    return render_template('jainevents.html', events=events)

# ===================== DASHBOARDS =====================
@app.route('/user')
@app.route('/user_dashboard')
def user_dashboard():
    """User dashboard with proper error handling"""
    if 'role' not in session or session['role'] != 'user':
        flash('Please log in to access the dashboard', 'error')
        logger.warning(f"Unauthorized access attempt to user_dashboard")
        return redirect(url_for('login'))
    
    try:
        logger.info(f"Loading dashboard for user: {session.get('email')}")
        
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        next_week = today + timedelta(days=7)
        today_str = today.strftime('%Y-%m-%d')
        
        logger.info(f"Fetching today's events for date: {today_str}")
        
        # Get today's events
        today_events = list(db.events.find({
            "$or": [
                {"event_date": today_str},
                {"end_date": today_str}
            ]
        }).sort('event_date', 1))
        
        logger.info(f"Found {len(today_events)} events for today")
        
        # Get upcoming events
        upcoming_events = list(db.events.find({
            "event_date": {
                "$gte": (today + timedelta(days=1)).strftime('%Y-%m-%d'),
                "$lte": next_week.strftime('%Y-%m-%d')
            }
        }).sort('event_date', 1))
        
        logger.info(f"Found {len(upcoming_events)} upcoming events")
        
        # Get drive stats
        drive_stats = {'total_files': 0, 'recent_uploads': []}
        drive_connected = False
        if 'drive_creds' in session:
            try:
                logger.info("Fetching Drive stats...")
                drive_stats = get_drive_stats()
                drive_connected = True
                logger.info(f"Drive connected. Total files: {drive_stats.get('total_files', 0)}")
            except Exception as e:
                logger.error(f"Error getting drive stats: {e}", exc_info=True)
        else:
            logger.info("Drive not connected")
        
        # Get public files
        logger.info("Fetching public files...")
        public_files = list(db.public_files.find().sort('uploaded_at', -1).limit(20))
        logger.info(f"Found {len(public_files)} public files")
        
        # Get user navbar for sidebar
        logger.info("Fetching user navbar...")
        user_navbar = get_user_navbar(session['email'])
        logger.info(f"User has {len(user_navbar) if user_navbar else 0} navbar items")
        
        # Get Gmail connection status
        gmail_connected = 'gmail_creds' in session
        logger.info(f"Gmail connected: {gmail_connected}")
        
        logger.info("Rendering user_dashboard.html...")
        
        return render_template(
            'user_dashboard.html',
            today_events=today_events,
            upcoming_events=upcoming_events,
            drive_stats=drive_stats,
            drive_connected=drive_connected,
            gmail_connected=gmail_connected,
            public_files=public_files,
            user_navbar=user_navbar
        )
    except Exception as e:
        logger.error(f"CRITICAL ERROR in user_dashboard: {str(e)}", exc_info=True)
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Session data: {dict(session)}")
        flash('Error loading dashboard. Please try again.', 'error')
        # Return minimal dashboard on error
        return render_template(
            'user_dashboard.html',
            today_events=[],
            upcoming_events=[],
            drive_stats={'total_files': 0, 'recent_uploads': []},
            drive_connected=False,
            gmail_connected=False,
            public_files=[],
            user_navbar=[]
        )
@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('login'))
    
    users = list(db.users.find())
    return render_template('admin_dashboard.html', users=users)

# ===================== GOOGLE OAUTH =====================
@app.route('/connect-drive')
def connect_drive():
    if 'role' not in session:
        return redirect(url_for('login'))

    try:
        session.pop('drive_creds', None)
        session.pop('drive_state', None)

        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=DRIVE_SCOPES,
            redirect_uri=url_for('drive_callback', _external=True)
        )

        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='false',
            prompt='consent'
        )

        session['drive_state'] = state
        logger.info("Starting Drive OAuth")

        return redirect(auth_url)

    except Exception as e:
        logger.error(f"Drive connection error: {e}", exc_info=True)
        flash('Error initiating Google Drive connection', 'error')
        return redirect(url_for('user_dashboard'))


@app.route('/drive/callback')
def drive_callback():
    try:
        if session.get('drive_state') != request.args.get('state'):
            flash('State mismatch. Authorization failed.', 'error')
            return redirect(url_for('user_dashboard'))

        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=DRIVE_SCOPES,
            redirect_uri=url_for('drive_callback', _external=True)
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

        flash('Google Drive connected successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    except Exception as e:
        logger.error(f"Drive callback error: {e}")
        flash('Error connecting to Google Drive', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/connect-gmail')
def connect_gmail():
    """Initiate Gmail OAuth connection"""
    if 'role' not in session:
        return redirect(url_for('login'))
    
    try:
        session.pop('gmail_creds', None)
        session.pop('gmail_state', None)
        
        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=GMAIL_SCOPES,
            redirect_uri="http://localhost:5000/gmail/callback"
        )
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='false',
            prompt='consent'
        )
        session['gmail_state'] = state
        logger.info(f"Starting Gmail OAuth")
        return redirect(auth_url)
    
    except Exception as e:
        logger.error(f"Gmail connection error: {e}", exc_info=True)
        flash(f'Error initiating Gmail connection', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/gmail/callback')
def gmail_callback():
    """Handle Gmail OAuth callback"""
    try:
        if session.get('gmail_state') != request.args.get('state'):
            flash('State mismatch. Authorization failed.', 'error')
            return redirect(url_for('user_dashboard'))

        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=GMAIL_SCOPES,
            redirect_uri="http://localhost:5000/gmail/callback"
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

        flash('✅ Gmail connected successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    except Exception as e:
        logger.error(f"Gmail callback error: {e}")
        flash(f'Error connecting to Gmail', 'error')
        return redirect(url_for('user_dashboard'))

# ===================== DRIVE OPERATIONS =====================
@app.route('/drive/files')
def drive_files():
    if 'drive_creds' not in session:
        flash('Please connect your Google Drive first.', 'error')
        return redirect(url_for('connect_drive'))

    try:
        service = get_drive_service()
        
        # Fetch folders
        results = service.files().list(
            q="trashed=false and mimeType='application/vnd.google-apps.folder'",
            pageSize=50,
            fields="files(id, name, mimeType, createdTime, webViewLink, iconLink)",
            orderBy="name"
        ).execute()

        folders = results.get('files', [])

        logger.info(f"Found {len(folders)} folders for user {session['email']}")

        # Get user's saved folders
        user_folders = db.user_navbars.find_one({'user_email': session['email']})
        saved_folder_ids = [item['ref_id'] for item in user_folders['items']] if user_folders and 'items' in user_folders else []

        # Add webViewLink if missing
        for folder in folders:
            if 'webViewLink' not in folder:
                folder['webViewLink'] = f"https://drive.google.com/drive/folders/{folder['id']}"

        logger.info(f"User has {len(saved_folder_ids)} saved folders")

        return render_template('drive_files.html',
                             folders=folders,
                             saved_folder_ids=saved_folder_ids,
                             total_folders=len(folders))

    except Exception as e:
        logger.error(f"Error fetching Drive folders: {str(e)}")
        flash(f'Error connecting to Google Drive', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/api/drive/folder/<folder_id>')
def get_drive_folder_contents(folder_id):
    """Get contents of a specific folder - PRIVATE to logged-in user"""
    if 'drive_creds' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        service = get_drive_service()
        
        results = service.files().list(
            q=f"'{folder_id}' in parents and trashed=false",
            pageSize=100,
            fields="files(id, name, mimeType, size, createdTime, webViewLink)"
        ).execute()

        files = results.get('files', [])
        return jsonify(files)

    except Exception as e:
        logger.error(f"Error fetching folder contents: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/drive/search')
def search_drive_files():
    """Search Drive files/folders for the logged-in user"""
    if 'drive_creds' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify([])

        service = get_drive_service()
        
        # Search for files and folders
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
def drive_upload():
    """Upload file to Google Drive"""
    if 'drive_creds' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        file = request.files.get('file')
        folder_id = request.form.get('folder_id', 'root')
        make_public = request.form.get('make_public', 'false') == 'true'
        
        if not file:
            return jsonify({'error': 'No file provided'}), 400
        
        service = get_drive_service()
        
        # Create file metadata
        file_metadata = {
            'name': secure_filename(file.filename),
            'parents': [folder_id]
        }
        
        # Upload file
        file_content = file.read()
        media = MediaIoBaseUpload(
            BytesIO(file_content),
            mimetype=file.mimetype,
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
        
        # Make public if requested
        if make_public:
            if make_file_public(service, file_obj['id']):
                result['public_link'] = f"https://drive.google.com/file/d/{file_obj['id']}/view"
        
        # Store in database if public
        if make_public:
            db.public_files.insert_one({
                'file_id': file_obj['id'],
                'name': file_obj['name'],
                'uploader_email': session['email'],
                'web_link': result['public_link'],
                'uploaded_at': datetime.now()
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error uploading to Drive: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/drive/create-folder', methods=['POST'])
def drive_create_folder():
    """Create folder in Google Drive"""
    if 'drive_creds' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        folder_name = data.get('folder_name')
        parent_id = data.get('parent_id', 'root')
        
        if not folder_name:
            return jsonify({'error': 'Folder name required'}), 400
        
        service = get_drive_service()
        
        file_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id]
        }
        
        folder = service.files().create(
            body=file_metadata,
            fields='id, name'
        ).execute()
        
        return jsonify({
            'folder_id': folder['id'],
            'folder_name': folder['name']
        })
        
    except Exception as e:
        logger.error(f"Error creating folder: {e}")
        return jsonify({'error': str(e)}), 400

# ===================== NAVBAR MANAGEMENT =====================
@app.route('/user/navbar/add-folder', methods=['POST'])
def add_folder_to_navbar():
    """Add Google Drive folder to user's personal navbar"""
    if session.get('role') != 'user':
        return redirect(url_for('login'))

    try:
        folder_id = request.form['folder_id']
        folder_name = request.form['folder_name']
        email = session['email']

        # Verify folder exists in user's Drive
        service = get_drive_service()
        file_metadata = service.files().get(fileId=folder_id, fields='id, name').execute()

        if not file_metadata:
            flash('Folder not found in your Drive', 'error')
            return redirect(request.referrer)

        # Add to user's navbar (PRIVATE - only this user can see)
        db.user_navbars.update_one(
            {"user_email": email},
            {
                "$addToSet": {
                    "items": {
                        "_id": ObjectId(),
                        "type": "drive_folder",
                        "label": folder_name,
                        "ref_id": folder_id,
                        "added_at": datetime.now()
                    }
                }
            },
            upsert=True
        )

        # Send confirmation email
        try:
            msg = Message(
                subject="📁 Folder Added to Your University Portal",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.html = f"""
            <h3>Folder Successfully Added!</h3>
            <p>You've added "<strong>{folder_name}</strong>" to your personal navigation.</p>
            <p>You can now quickly access this folder from your dashboard sidebar.</p>
            <p>This folder is private and visible only to you.</p>
            <hr>
            <small>Jain University Portal</small>
            """
            mail.send(msg)
        except Exception as e:
            logger.error(f"Error sending email: {e}")

        flash(f'✅ Folder "{folder_name}" added to your navigation!', 'success')
        return redirect(request.referrer or url_for('drive_files'))

    except Exception as e:
        logger.error(f"Error adding folder: {e}")
        flash('Error adding folder', 'error')
        return redirect(request.referrer or url_for('drive_files'))

@app.route('/user/navbar/remove-folder/<folder_id>', methods=['POST'])
def remove_folder_from_navbar(folder_id):
    """Remove folder from user's navbar"""
    if session.get('role') != 'user':
        return redirect(url_for('login'))

    try:
        email = session['email']
        db.user_navbars.update_one(
            {"user_email": email},
            {"$pull": {"items": {"ref_id": folder_id}}}
        )

        flash('✅ Folder removed from your navigation', 'success')
        return redirect(request.referrer or url_for('drive_files'))

    except Exception as e:
        logger.error(f"Error removing folder: {e}")
        flash('Error removing folder', 'error')
        return redirect(request.referrer or url_for('drive_files'))

# ===================== ADMIN USER CONTROLS =====================
@app.route('/admin/users')
def view_users():
    if session.get('role') != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    users = list(db.users.find())
    return render_template('admin_view_users.html', users=users)

@app.route('/update_user/<user_id>', methods=['POST'])
def update_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    email = request.form['email']
    role = request.form['role']

    db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'email': email, 'role': role}})
    flash('✅ User updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<user_id>')
def delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    db.users.delete_one({'_id': ObjectId(user_id)})
    flash('✅ User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# ===================== UGC UPLOAD =====================
@app.route('/edit_ugc', methods=['GET', 'POST'])
def edit_ugc():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
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

        flash('✅ UGC/University Notice data uploaded successfully.')
        return redirect(url_for('edit_ugc'))

    records = list(db.ugc_data.find().sort('uploaded_at', -1))
    return render_template('edit_ugc.html', records=records)

@app.route('/edit_ugc_record/<record_id>', methods=['GET', 'POST'])
def edit_ugc_record(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    record = db.ugc_data.find_one({'_id': ObjectId(record_id)})

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

        flash('✅ UGC/University Notice data updated successfully.')
        return redirect(url_for('edit_ugc'))

    return render_template('edit_ugc_record.html', record=record)

@app.route('/delete_ugc/<record_id>', methods=['GET'])
def delete_ugc(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    db.ugc_data.delete_one({'_id': ObjectId(record_id)})
    flash('✅ UGC record deleted successfully.')
    return redirect(url_for('edit_ugc'))

# ===================== MONTHLY ENGAGEMENT =====================
@app.route('/edit_monthly', methods=['GET', 'POST'])
def edit_monthly():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
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
            "uploaded_at": datetime.utcnow(),
            "heading": heading,
            "description": description,
            "school": school,
            "department": department,
            "tags": tags,
            "files": uploaded_files
        })

        flash('✅ Monthly engagement data uploaded successfully.')
        return redirect(url_for('edit_monthly'))

    records = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    return render_template('edit_monthly.html', records=records)

@app.route('/edit_record/<record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    collection = db.monthly_engagement
    record = collection.find_one({'_id': ObjectId(record_id)})

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

        return redirect(url_for('edit_monthly'))

    return render_template('edit_record.html', record=record)

@app.route('/delete_record/<record_id>', methods=['POST'])
def delete_record(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    collection = db.monthly_engagement
    record = collection.find_one({'_id': ObjectId(record_id)})

    if record and 'files' in record:
        for filename in record['files']:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)

    collection.delete_one({'_id': ObjectId(record_id)})
    return redirect(url_for('edit_monthly'))

# ===================== NEWSLETTER =====================
@app.route('/usernewsletters')
def usernewsletters():
    newsletters = list(db.newsletters.find().sort('uploaded_at', -1))
    return render_template('user_newsletters.html', records=newsletters)

@app.route('/newsletter', methods=['GET', 'POST'])
def newsletter():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
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

        flash('✅ Newsletter uploaded and emailed successfully.')
        return redirect(url_for('newsletter'))

    records = list(db.newsletters.find().sort('uploaded_at', -1))
    return render_template('admin_newsletter.html', records=records)

@app.route('/edit_newsletter/<id>', methods=['GET'])
def edit_newsletter(id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    record = db.newsletters.find_one({'_id': ObjectId(id)})
    if not record:
        flash('Newsletter not found.', 'error')
        return redirect(url_for('newsletter'))

    return render_template('edit_newsletter.html', record=record)

@app.route('/update_newsletter/<id>', methods=['POST'])
def update_newsletter(id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

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
                'image': image_filename
            }
        }
    )

    flash('✅ Newsletter updated successfully!', 'success')
    return redirect(url_for('newsletter'))

@app.route('/newsletter/delete/<id>')
def delete_newsletter(id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    db.newsletters.delete_one({"_id": ObjectId(id)})
    flash("✅ Newsletter deleted.")
    return redirect(url_for('newsletter'))

def send_newsletter_email(title, content, image_filename, recipients):
    msg = Message(subject=title, sender=app.config['MAIL_USERNAME'], recipients=recipients)
    msg.html = content

    if image_filename:
        with app.open_resource(os.path.join(app.config['UPLOAD_FOLDER'], image_filename)) as img:
            msg.attach(image_filename, "image/jpeg", img.read())

    mail.send(msg)

@app.route('/subscribe_newsletter', methods=['POST'])
def subscribe_newsletter():
    email = request.form.get('email')
    
    if not email:
        flash("Email is required.", "error")
        return redirect(request.referrer or url_for('jainevents'))

    if db.subscribers.find_one({'email': email}):
        flash("You are already subscribed!", "info")
    else:
        db.subscribers.insert_one({
            'email': email,
            'subscribed_at': datetime.now()
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

# ===================== EVENTS MANAGEMENT =====================
@app.route("/admin/events")
def admin_events():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    events = list(db.events.find())
    for e in events:
        e["_id"] = str(e["_id"])
    return render_template("admin_events.html", events=events)

@app.route("/add_event", methods=["POST"])
def add_event():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

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
        "image": image_path,
        "pdf": pdf_path,
        "created_at": datetime.now()
    }

    db.events.insert_one(event)
    flash('✅ Event added successfully!', 'success')
    return redirect(url_for('admin_events'))

@app.route("/delete_event/<event_id>")
def delete_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    db.events.delete_one({"_id": ObjectId(event_id)})
    flash('✅ Event deleted successfully!', 'success')
    return redirect(url_for('admin_events'))

@app.route("/edit_event/<event_id>", methods=["GET"])
def edit_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    event = db.events.find_one({"_id": ObjectId(event_id)})
    if not event:
        flash('Event not found.', 'error')
        return redirect(url_for('admin_events'))

    event["_id"] = str(event["_id"])
    return render_template("edit_event.html", event=event)

@app.route("/update_event/<event_id>", methods=["POST"])
def update_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

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
        "updated_at": datetime.now()
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
    return redirect(url_for('admin_events'))

# ===================== EVENT REMINDER ENDPOINTS =====================
@app.route('/api/events/set-reminder', methods=['POST'])
def set_event_reminder():
    """Set a reminder for an event"""
    if session.get('role') != 'user':
        return jsonify({'error': 'Access denied'}), 403

    try:
        data = request.get_json()
        event_id = data.get('event_id')
        reminder_minutes = int(data.get('reminder_minutes', 60))
        
        # NEW: Get custom reminder date/time if provided
        reminder_date = data.get('reminder_date')
        reminder_time = data.get('reminder_time')
        
        event = db.events.find_one({'_id': ObjectId(event_id)})
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        user = db.users.find_one({'email': session['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Calculate reminder datetime
        if reminder_date and reminder_time:
            # User provided custom date/time
            reminder_datetime = datetime.strptime(f"{reminder_date} {reminder_time}", '%Y-%m-%d %H:%M')
        else:
            # Calculate from event date
            event_date = datetime.strptime(event['event_date'], '%Y-%m-%d') if isinstance(event['event_date'], str) else event['event_date']
            # Add default time if not specified
            if event.get('event_time') and event['event_time'] != 'All Day':
                try:
                    time_parts = event['event_time'].split(':')
                    event_date = event_date.replace(hour=int(time_parts[0]), minute=int(time_parts[1]))
                except:
                    event_date = event_date.replace(hour=9, minute=0)  # Default to 9 AM
            else:
                event_date = event_date.replace(hour=9, minute=0)  # Default to 9 AM
            
            reminder_datetime = event_date - timedelta(minutes=reminder_minutes)
        
        # Check if reminder already exists
        existing = db.event_reminders.find_one({
            'user_id': user['_id'],
            'event_id': event['_id']
        })
        
        if existing:
            db.event_reminders.update_one(
                {'_id': existing['_id']},
                {'$set': {
                    'reminder_datetime': reminder_datetime,  # FIXED: Use reminder_datetime
                    'reminder_minutes': reminder_minutes,
                    'sent': False
                }}
            )
        else:
            db.event_reminders.insert_one({
                'user_id': user['_id'],
                'event_id': event['_id'],
                'reminder_datetime': reminder_datetime,  # FIXED: Use reminder_datetime
                'reminder_minutes': reminder_minutes,
                'sent': False,
                'created_at': datetime.now()
            })
        
        return jsonify({
            'success': True,
            'message': f"Reminder set for {reminder_datetime.strftime('%Y-%m-%d %H:%M')}"
        })
        
    except Exception as e:
        logger.error(f"Error setting reminder: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/events/subscribe', methods=['POST'])
def subscribe_to_event():
    """Subscribe to event notifications"""
    if session.get('role') != 'user':
        return jsonify({'error': 'Access denied'}), 403

    try:
        data = request.get_json()
        event_id = data.get('event_id')
        
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
            return jsonify({'message': 'Already subscribed'}), 200
        
        # Subscribe user
        db.event_subscriptions.insert_one({
            'user_id': user['_id'],
            'event_id': event['_id'],
            'subscribed_at': datetime.now()
        })
        
        # Send confirmation email
        msg = Message(
            subject=f"✅ Subscribed to Event: {event['event_name']}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[user['email']]
        )
        
        msg.html = f"""
        <h2>Event Subscription Confirmed</h2>
        <p>You have successfully subscribed to:</p>
        <h3>{event['event_name']}</h3>
        <p><strong>Date:</strong> {event['event_date']}</p>
        <p><strong>Venue:</strong> {event['venue']}</p>
        <p>You will receive updates and reminders about this event.</p>
        """
        
        mail.send(msg)
        
        return jsonify({'success': True, 'message': 'Subscribed successfully'})
        
    except Exception as e:
        logger.error(f"Error subscribing to event: {e}")
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
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/newsletter_view/<newsletter_id>')
def newsletter_view(newsletter_id):
    news = db.newsletters.find_one({'_id': ObjectId(newsletter_id)})
    if not news:
        return "Newsletter not found", 404
    news['_id'] = str(news['_id'])
    return render_template('newsletter_detail.html', news=news)

# ===================== RUN APP =====================
if __name__ == '__main__':
    scheduler = BackgroundScheduler()

    @scheduler.scheduled_job('interval', minutes=1)
    def scheduled_send_event_reminders():
        with app.app_context():
            send_event_reminders()

    @scheduler.scheduled_job('cron', hour=7)
    def scheduled_send_daily_event_emails():
        with app.app_context():
            send_daily_event_emails()

    scheduler.start()

    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)