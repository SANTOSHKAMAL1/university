import re
from flask import Flask, json, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson import ObjectId
from datetime import datetime
import os
from config import Config
from utils import get_indian_time # MongoDB URI in config.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash
import random

# Initialize app
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'your_secret_key_here'

# Upload folder settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize MongoDB
mongo = PyMongo(app)
db = mongo.db

# Allowed file type check
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Mail Config (use your Gmail + app password)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'info.loginpanel@gmail.com'
app.config['MAIL_PASSWORD'] = 'wedbfepklgtwtugf'  # no spaces

mail = Mail(app)
def send_newsletter_email(title, content, image_filename, recipients):
    msg = Message(subject=title, sender=app.config['MAIL_USERNAME'], recipients=recipients)
    msg.html = content

    if image_filename:
        with app.open_resource(os.path.join(app.config['UPLOAD_FOLDER'], image_filename)) as img:
            msg.attach(image_filename, "image/jpeg", img.read())

    mail.send(msg)


# ===================== Pages =====================
@app.route('/')
def home():
    records = list(db.ugc_data.find().sort('uploaded_at', -1))
    monthly_records = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    newsletter_records = list(db.newsletters.find().sort('uploaded_at', -1))
    return render_template(
        'home.html',
        records=records,
        monthly_records=monthly_records,
        newsletter_records=newsletter_records
    )




@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/monthlyengagement')
def monthlyengagement():
    return render_template('monthly.html')

@app.route('/ugc')
def ugc():
    return render_template('ugc.html')

@app.route('/jainevents')
def jainevents():
    return render_template('jainevents.html')

# ===================== UGC Upload =====================

@app.route('/edit_ugc', methods=['GET', 'POST'])
def edit_ugc():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        text_data = request.form.get('text_data')
        external_link = request.form.get('external_link')
        selected_categories = request.form.getlist('categories')  # ✅ collect selected checkboxes
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
            "categories": selected_categories,  # ✅ store categories
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
        description = request.form.get('description')  # Rich text HTML
        tags = request.form.getlist('tags')
        image_file = request.files.get('image')
        recipient_email_raw = request.form.get('recipient_email', '').strip()

        # ✅ Initialize email_list before using it
        email_list = []

        # ✅ Email Parsing and Validation
        def is_valid_email(email):
            return re.match(r"[^@]+@[^@]+\.[^@]+", email)

        try:
            # Handle Tagify JSON input
            parsed = json.loads(recipient_email_raw)
            email_list = [e['value'].strip() for e in parsed if 'value' in e and is_valid_email(e['value'].strip())]
        except:
            # Fallback: comma-separated
            email_list = [e.strip() for e in recipient_email_raw.split(',') if is_valid_email(e.strip())]

        if not email_list:
            flash("❌ No valid email addresses provided.", "error")
            return redirect(url_for('newsletter'))

        # Save image file
        image_filename = None
        if image_file and allowed_file(image_file.filename):
            image_filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)

        # ✅ Save to MongoDB (AFTER email_list is ready)
        newsletter_data = {
            "admin_email": session['email'],
            "uploaded_at": get_indian_time(),
            "title": title,
            "description": description,
            "tags": tags,
            "image": image_filename,
            "recipients": email_list  # now this works fine
        }
        db.newsletters.insert_one(newsletter_data)

        # ✅ Send Emails
        send_newsletter_email(title, description, image_filename, email_list)

        flash('✅ Newsletter uploaded and emailed successfully.')
        return redirect(url_for('newsletter'))

    # GET method – show newsletter list
    records = list(db.newsletters.find().sort('uploaded_at', -1))
    return render_template('admin_newsletter.html', records=records)

from bson import ObjectId

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

    # Get form data
    title = request.form.get('title')
    description = request.form.get('description')
    tags = request.form.getlist('tags')
    recipient_emails = request.form.get('recipient_email', '').split(',')

    # Clean recipient emails
    recipient_emails = [email.strip() for email in recipient_emails if email.strip()]

    # Handle image upload
    image_file = request.files.get('image')
    image_filename = record.get('image')  # keep old image if none uploaded

    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)
        image_filename = filename

    # Update document
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




from flask_mail import Message

@app.route('/subscribe_newsletter', methods=['POST'])
def subscribe_newsletter():
    email = request.form.get('email')
    
    if not email:
        flash("Email is required.", "error")
        return redirect(request.referrer or url_for('public_newsletters'))

    # Check if already subscribed
    if db.subscribers.find_one({'email': email}):
        flash("You are already subscribed!", "info")
    else:
        db.subscribers.insert_one({
            'email': email,
            'subscribed_at': datetime.now()
        })

        # ✅ Send confirmation email
        try:
            msg = Message(
                subject="🎉 You're Subscribed to Our University Newsletter!",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.html = f"""
            <h2>Thank you for subscribing!</h2>
            <p>You’ll now receive updates, articles, and event highlights directly to your inbox.</p>
            <p>If you did not request this, please ignore this message.</p>
            <br><hr>
            <small>This is an automated message from Jain University Newsletter system.</small>
            """
            mail.send(msg)
            flash("Subscribed successfully! A confirmation email has been sent.", "success")
        except Exception as e:
            flash("Subscribed, but failed to send confirmation email.", "warning")
            print(e)

    return redirect(request.referrer or url_for('public_newsletters'))




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

        updated_files = record.get('files', [])  # Keep existing files

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                updated_files.append(filename)

        # ✅ Update the record, don’t insert new
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



from bson.objectid import ObjectId

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
        tags = request.form.getlist('tags')  # Checkboxes

       
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

        # Only include fields if they exist in the form
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

        # Only update if there's something to update
        if updated_data:
            collection.update_one({'_id': ObjectId(record_id)}, {'$set': updated_data})

        return redirect(url_for('edit_monthly'))

    return render_template('edit_record.html', record=record)

from bson import ObjectId
@app.route('/delete_record/<record_id>', methods=['POST'])
def delete_record(record_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    collection = mongo.db.monthly_engagement
    record = collection.find_one({'_id': ObjectId(record_id)})

    # Delete uploaded files from disk
    if record and 'files' in record:
        for filename in record['files']:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)

    # Delete record from MongoDB
    collection.delete_one({'_id': ObjectId(record_id)})

    return redirect(url_for('edit_monthly'))

# ===================== Authentication =====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'step' not in session:
        session['step'] = 1

    if request.method == 'POST':
        # Step 1: Email input and OTP send
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

        # Step 2: OTP Verification
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

        # Step 3: Set password
        elif session['step'] == 3:
            password = request.form.get('password')
            hashed_pw = generate_password_hash(password)
            db.users.insert_one({'email': session['email'], 'password': hashed_pw, 'role': 'user'})

            # Clear session
            session.pop('email', None)
            session.pop('otp', None)
            session.pop('step', None)
            session.pop('otp_verified', None)

            flash('Registration complete! You can now log in.', 'success')
            return redirect(url_for('login'))

    # For GET or re-render
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

# ===================== Run App =====================
from flask import send_from_directory
import os

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/newsletter_view/<newsletter_id>')
def newsletter_view(newsletter_id):
    news = db.newsletters.find_one({'_id': ObjectId(newsletter_id)})
    if not news:
        os.abort(404)
    news['_id'] = str(news['_id'])
    return render_template('newsletter_detail.html', news=news)
import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

