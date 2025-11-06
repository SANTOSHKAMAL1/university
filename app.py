import re
from flask import Flask, json, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson import ObjectId
from datetime import datetime, timedelta
import os
from config import Config
from utils import get_indian_time
from flask_mail import Mail, Message
import random
from apscheduler.schedulers.background import BackgroundScheduler
import pandas as pd
from io import StringIO
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize app
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'your_secret_key_here'

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

def send_daily_event_emails():
    today = datetime.today().strftime("%Y-%m-%d")
    upcoming = (datetime.today() + timedelta(days=7)).strftime("%Y-%m-%d")

    subscribers = list(mongo.db.subscribers.find())
    events = list(mongo.db.events.find({
        "event_date": {"$gte": today, "$lte": upcoming}
    }))

    for sub in subscribers:
        msg = Message("Upcoming University Events", sender=app.config['MAIL_USERNAME'], recipients=[sub['email']])
        body = "Hello,\n\nHere are today's and upcoming events:\n\n"
        for e in events:
            if not sub.get('school') or e['school'] == sub['school']:
                body += f"- {e['event_name']} on {e['event_date']} at {e['venue']}\n"
        msg.body = body
        mail.send(msg)

scheduler = BackgroundScheduler()
scheduler.add_job(send_daily_event_emails, 'cron', hour=7)
scheduler.start()

# ===================== EXCEL UPLOAD WITH VALIDATION =====================

def validate_excel_data(df):
    """
    Validate Excel data before insertion
    Returns: (is_valid, error_messages, cleaned_data)
    """
    errors = []
    required_columns = ['event_name', 'description', 'school', 'department', 'event_type', 'venue', 'event_date']
    
    # Check required columns
    missing_cols = [col for col in required_columns if col not in df.columns]
    if missing_cols:
        return False, [f"Missing required columns: {', '.join(missing_cols)}"], None
    
    cleaned_records = []
    
    for idx, row in df.iterrows():
        record_errors = []
        
        # Validate event_name
        if pd.isna(row.get('event_name')) or str(row['event_name']).strip() == '':
            record_errors.append(f"Row {idx+2}: event_name is required")
            continue
        
        # Validate description
        if pd.isna(row.get('description')) or str(row['description']).strip() == '':
            record_errors.append(f"Row {idx+2}: description is required")
            continue
        
        # Validate school
        if pd.isna(row.get('school')) or str(row['school']).strip() == '':
            record_errors.append(f"Row {idx+2}: school is required")
            continue
        
        # Validate department
        if pd.isna(row.get('department')) or str(row['department']).strip() == '':
            record_errors.append(f"Row {idx+2}: department is required")
            continue
        
        # Validate event_type
        if pd.isna(row.get('event_type')) or str(row['event_type']).strip() == '':
            record_errors.append(f"Row {idx+2}: event_type is required")
            continue
        
        # Validate venue
        if pd.isna(row.get('venue')) or str(row['venue']).strip() == '':
            record_errors.append(f"Row {idx+2}: venue is required")
            continue
        
        # Validate event_date (must be valid date format)
        try:
            event_date = pd.to_datetime(row['event_date']).strftime('%Y-%m-%d')
        except Exception as e:
            record_errors.append(f"Row {idx+2}: Invalid event_date format (use YYYY-MM-DD)")
            continue
        
        # Optional: Validate end_date if provided
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
        
        # Create clean record
        clean_record = {
            'event_name': str(row['event_name']).strip(),
            'description': str(row['description']).strip(),
            'school': str(row['school']).strip(),
            'department': str(row['department']).strip(),
            'event_type': str(row['event_type']).strip(),
            'venue': str(row['venue']).strip(),
            'event_date': event_date,
            'end_date': end_date,
            'event_action': str(row.get('event_action', '')).strip() or None,
            'image': None,
            'pdf': None,
            'created_at': datetime.now()
        }
        
        cleaned_records.append(clean_record)
    
    if errors:
        return False, errors, None
    
    return True, [], cleaned_records


@app.route("/upload_events_excel", methods=["POST"])
def upload_events_excel():
    """
    Upload and process Excel file with events
    """
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
            df = pd.read_excel(file, sheet_name=0)  # Read first sheet
        
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
            result = mongo.db.events.insert_many(cleaned_records)
            flash(f"✅ Success! Added {len(result)} events to the database.", "success")
            logger.info(f"Uploaded {len(result)} events from Excel file")
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
    """
    Preview and validate Excel before uploading
    """
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
            'errors': errors[:10],  # Show first 10 errors
            'error_count': len(errors),
            'preview': preview_data
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ===================== Pages =====================
from datetime import datetime

@app.route('/')
def home():
    records = list(db.ugc_data.find().sort('uploaded_at', -1))
    monthly_records = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    newsletter_records = list(db.newsletters.find().sort('uploaded_at', -1))
    events = list(db.events.find().sort('event_date', 1))
    
    today = datetime.now().date()
    
    for event in events:
        if isinstance(event['event_date'], str):
            event['event_date'] = datetime.strptime(event['event_date'], '%Y-%m-%d')
    
    return render_template(
        'home.html',
        records=records,
        monthly_records=monthly_records,
        newsletter_records=newsletter_records,
        events=events,
        today=today
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
    events = list(mongo.db.monthly_engagement.find())
    return render_template('monthly.html', monthly_records=events)

@app.route('/ugc')
def ugc():
    return render_template('ugc.html')

@app.route('/jainevents')
def jainevents():
    events = list(mongo.db.events.find())
    return render_template('jainevents.html', events=events)


# ===================== UGC Upload =====================

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

        flash('UGC/University Notice data uploaded successfully.')
        return redirect(url_for('edit_ugc'))

    records = list(db.ugc_data.find().sort('uploaded_at', -1))
    return render_template('edit_ugc.html', records=records)

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

    flash('Newsletter updated successfully!', 'success')
    return redirect(url_for('newsletter'))


@app.route('/newsletter/delete/<id>')
def delete_newsletter(id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    db.newsletters.delete_one({"_id": ObjectId(id)})
    flash("Newsletter deleted.")
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
            flash("Subscribed successfully! A confirmation email has been sent.", "success")
        except Exception as e:
            flash("Subscribed, but failed to send confirmation email.", "warning")
            logger.error(f"Email send error: {e}")

    return redirect(request.referrer or url_for('jainevents'))


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

        flash('UGC/University Notice data updated successfully.')
        return redirect(url_for('edit_ugc'))

    return render_template('edit_ugc_record.html', record=record)


@app.route('/delete_ugc/<record_id>', methods=['GET'])
def delete_ugc(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    db.ugc_data.delete_one({'_id': ObjectId(record_id)})
    flash('UGC record deleted successfully.')
    return redirect(url_for('edit_ugc'))


# ===================== Monthly Engagement =====================

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

        flash('Monthly engagement data uploaded successfully.')
        return redirect(url_for('edit_monthly'))

    records = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    return render_template('edit_monthly.html', records=records)


@app.route('/edit_record/<record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    collection = mongo.db.monthly_engagement
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

    collection = mongo.db.monthly_engagement
    record = collection.find_one({'_id': ObjectId(record_id)})

    if record and 'files' in record:
        for filename in record['files']:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)

    collection.delete_one({'_id': ObjectId(record_id)})
    return redirect(url_for('edit_monthly'))


# ===================== Authentication =====================

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

            flash('Registration complete! You can now log in.', 'success')
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
        flash('Admin registered successfully. Please log in.', 'success')
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
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# ===================== Dashboards =====================

@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    users = list(db.users.find())
    return render_template('admin_dashboard.html', users=users)


@app.route('/user')
def user_dashboard():
    if session.get('role') != 'user':
        return redirect(url_for('login'))

    return render_template('user_dashboard.html')


# ===================== Admin User Controls =====================

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
    flash('User updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_user/<user_id>')
def delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    db.users.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


# ===================== File Serving =====================

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


# ===================== Events Management =====================

@app.route("/admin/events")
def admin_events():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    events = list(mongo.db.events.find())
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

    mongo.db.events.insert_one(event)
    flash('✅ Event added successfully!', 'success')
    return redirect(url_for('admin_events'))


@app.route("/delete_event/<event_id>")
def delete_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    mongo.db.events.delete_one({"_id": ObjectId(event_id)})
    flash('✅ Event deleted successfully!', 'success')
    return redirect(url_for('admin_events'))


@app.route("/edit_event/<event_id>", methods=["GET"])
def edit_event(event_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
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

    mongo.db.events.update_one({"_id": ObjectId(event_id)}, {"$set": update_data})
    flash('✅ Event updated successfully!', 'success')
    return redirect(url_for('admin_events'))


# ===================== API Endpoints =====================

@app.route('/api/events')
def get_events():
    try:
        current_date = datetime.now().strftime('%Y-%m-%d')
        
        events = list(mongo.db.events.find({
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
        event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
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
        events = list(mongo.db.events.find({
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


# ===================== Run App =====================

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)