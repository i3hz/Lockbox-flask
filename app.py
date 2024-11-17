from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from bcrypt import hashpw, gensalt, checkpw
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Encryption key
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

# Models
class MasterPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(50), nullable=False)
    encrypted_password = db.Column(db.String(256), nullable=False)

# Initialize the database
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/set_master_password', methods=['GET', 'POST'])
def set_master_password():
    if MasterPassword.query.first():
        flash('Master password is already set. Please log in.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        master_password = request.form.get('master_password')
        if not master_password:
            flash('Master password is required!', 'error')
            return redirect(url_for('set_master_password'))

        hashed_pw = hashpw(master_password.encode(), gensalt())
        db.session.add(MasterPassword(password_hash=hashed_pw.decode()))
        db.session.commit()
        flash('Master password set successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('set_master_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        master_password = request.form.get('master_password')
        master_password_entry = MasterPassword.query.first()

        if not master_password_entry or not checkpw(master_password.encode(), master_password_entry.password_hash.encode()):
            flash('Invalid master password!', 'error')
            return redirect(url_for('login'))

        session['logged_in'] = True
        session['master_password'] = master_password
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        service_name = request.form.get('service_name')
        password = request.form.get('password')

        if not service_name or not password:
            flash('Service name and password are required!', 'error')
            return redirect(url_for('dashboard'))

        encrypted_password = fernet.encrypt(password.encode()).decode()
        db.session.add(PasswordEntry(service_name=service_name, encrypted_password=encrypted_password))
        db.session.commit()
        flash(f'Password for {service_name} added successfully!', 'success')

    passwords = PasswordEntry.query.all()
    decrypted_passwords = [
        {'service_name': entry.service_name,
         'password': fernet.decrypt(entry.encrypted_password.encode()).decode()}
        for entry in passwords
    ]
    return render_template('dashboard.html', passwords=decrypted_passwords)

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
