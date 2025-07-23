from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
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

# ===================== Pages =====================

@app.route('/')
def home():
    records = list(db.ugc_data.find().sort('uploaded_at', -1))
    monthly_records = list(db.monthly_engagement.find().sort('uploaded_at', -1))
    return render_template('home.html', records=records, monthly_records=monthly_records)


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
        updated_data = {
            'heading': request.form.get('heading', '').strip(),
            'description': request.form.get('description', '').strip(),
            'school': request.form.get('school', ''),
            'department': request.form.get('department', ''),
            'tags': request.form.getlist('tags'),
        }

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



if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
