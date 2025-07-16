from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson import ObjectId
from datetime import datetime
import os
from config import Config  # MongoDB URI in config.py

# Initialize app
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'your_secret_key_here'

# Upload settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize MongoDB
mongo = PyMongo(app)
db = mongo.db

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

from bson.json_util import dumps  # At the top of your file

from flask import render_template
from bson.json_util import dumps  # Optional for debug

@app.route('/')
def home():
    records = list(db.ugc_data.find().sort('uploaded_at', -1))
    print("Fetched records:", dumps(records, indent=2))  # Debug print

    return render_template('home.html', records=records)







# About
@app.route('/about')
def about():
    return render_template('about.html')

# Contact
@app.route('/contact')
def contact():
    return render_template('contact.html')

# Monthly Engagement
@app.route('/monthly')
def monthly():
    return render_template('monthly.html')

# UGC Static Page
@app.route('/ugc')
def ugc():
    return render_template('ugc.html')


# ===================== UGC Editor =====================
@app.route('/edit_ugc', methods=['GET', 'POST'])
def edit_ugc():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        text_data = request.form.get('text_data')
        files = request.files.getlist('files')

        uploaded_files = []
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                uploaded_files.append(filename)

        # Save to MongoDB
        db.ugc_data.insert_one({
            "admin_email": session['email'],
            "uploaded_at": datetime.utcnow(),
            "text_data": text_data,
            "files": uploaded_files
        })

        flash('UGC data and files uploaded successfully.')
        return redirect(url_for('edit_ugc'))

    # GET: fetch previously uploaded entries
    records = list(db.ugc_data.find().sort('uploaded_at', -1))
    return render_template('edit_ugc.html', records=records)

# ===================== Authentication =====================

# Register - Users
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email.endswith('@jainuniversity.ac.in'):
            flash('Only @jainuniversity.ac.in emails allowed', 'error')
            return redirect(url_for('register'))

        if db.users.find_one({'email': email}):
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        db.users.insert_one({'email': email, 'password': hashed_pw, 'role': 'user'})
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# Register - Admin
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


# Login
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


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# ===================== Dashboards =====================

# Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    users = list(db.users.find())
    return render_template('admin_dashboard.html', users=users)


# User Dashboard
@app.route('/user')
def user_dashboard():
    if session.get('role') != 'user':
        return redirect(url_for('login'))

    return render_template('user_dashboard.html')


# ===================== Admin Controls =====================

# View All Users
@app.route('/admin/users')
def view_users():
    if session.get('role') != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    users = list(db.users.find())
    return render_template('admin_view_users.html', users=users)

# Update User Role/Email
@app.route('/update_user/<user_id>', methods=['POST'])
def update_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    email = request.form['email']
    role = request.form['role']

    db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'email': email, 'role': role}})
    flash('User updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# Delete User
@app.route('/delete_user/<user_id>')
def delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    db.users.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


# ===================== Run =====================
if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True, use_reloader=False)
