"""
Vintage Authentication System
Flask Backend with SQLite Database (Local Development Version)
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
import bcrypt
import jwt
import datetime
import os
import re
import sqlite3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-vintage-secret-key-2024')

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-jwt-secret-key-vintage')
JWT_EXPIRATION_HOURS = 24

# Database Configuration
DATABASE = 'vintage_auth.db'

# ============================================
# DATABASE SETUP
# ============================================

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            display_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            bio TEXT DEFAULT '',
            avatar_url TEXT DEFAULT ''
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✓ Database initialized successfully!")

# Initialize database on startup
init_db()

# ============================================
# UTILITY FUNCTIONS
# ============================================

def hash_password(password):
    """
    Hash password using bcrypt
    Returns: hashed password as string
    """
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password, hashed_password):
    """
    Verify password against stored hash
    Returns: Boolean
    """
    return bcrypt.checkpw(
        password.encode('utf-8'), 
        hashed_password.encode('utf-8')
    )

def generate_jwt_token(user_id, username):
    """
    Generate JWT token for authenticated user
    Returns: JWT token string
    """
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def decode_jwt_token(token):
    """
    Decode and verify JWT token
    Returns: payload dict or None
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """
    Validate password strength
    Requirements: 8+ chars, 1 uppercase, 1 lowercase, 1 number
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def validate_username(username):
    """Validate username format"""
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 30:
        return False, "Username must be less than 30 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, "Username is valid"

# ============================================
# DATABASE FUNCTIONS
# ============================================

def get_user_by_email(email):
    """
    Retrieve user from database by email
    Returns: user dict or None
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ? LIMIT 1', (email.lower(),))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None

def get_user_by_username(username):
    """
    Retrieve user from database by username
    Returns: user dict or None
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? LIMIT 1', (username.lower(),))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None

def get_user_by_id(user_id):
    """
    Retrieve user from database by ID
    Returns: user dict or None
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ? LIMIT 1', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None

def create_user(username, email, password):
    """
    Create new user in database
    Returns: (success: bool, message: str, user_id: int or None)
    """
    try:
        # Hash password
        hashed_password = hash_password(password)
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (username, email, password, display_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            username.lower(),
            email.lower(),
            hashed_password,
            username,
            datetime.datetime.utcnow(),
            datetime.datetime.utcnow()
        ))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return True, "Account created successfully", user_id
        
    except sqlite3.IntegrityError as e:
        return False, f"User already exists", None
    except Exception as e:
        return False, f"Error creating account: {str(e)}", None

def update_last_login(user_id):
    """Update user's last login timestamp"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET last_login = ? WHERE id = ?
        ''', (datetime.datetime.utcnow(), user_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error updating last login: {e}")

# ============================================
# AUTHENTICATION DECORATOR
# ============================================

def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session
        if 'user_id' not in session:
            # Check for JWT token in header
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                payload = decode_jwt_token(token)
                if payload:
                    return f(*args, **kwargs)
            
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# ROUTES
# ============================================

@app.route('/')
def home():
    """Home route - redirect to login or dashboard"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication"""
    # Redirect if already logged in
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Get form data
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'
        
        # Validate input
        if not identifier or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('login.html')
        
        # Find user by email or username
        user = None
        if validate_email(identifier):
            user = get_user_by_email(identifier)
        else:
            user = get_user_by_username(identifier)
        
        # Check if user exists
        if not user:
            flash('Invalid credentials. Please try again.', 'error')
            return render_template('login.html')
        
        # Check if account is active
        if not user.get('is_active', True):
            flash('This account has been deactivated.', 'error')
            return render_template('login.html')
        
        # Verify password
        if not verify_password(password, user['password']):
            flash('Invalid credentials. Please try again.', 'error')
            return render_template('login.html')
        
        # Authentication successful
        session['user_id'] = user['id']
        session['username'] = user['display_name']
        session['email'] = user['email']
        
        # Set session permanence
        if remember_me:
            session.permanent = True
            app.permanent_session_lifetime = datetime.timedelta(days=30)
        
        # Update last login
        update_last_login(user['id'])
        
        # Generate JWT token
        token = generate_jwt_token(user['id'], user['username'])
        session['jwt_token'] = token
        
        flash(f'Welcome back, {user["display_name"]}!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page and registration"""
    # Redirect if already logged in
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate all fields are filled
        if not all([username, email, password, confirm_password]):
            flash('Please fill in all fields.', 'error')
            return render_template('signup.html')
        
        # Validate username
        valid_username, username_msg = validate_username(username)
        if not valid_username:
            flash(username_msg, 'error')
            return render_template('signup.html')
        
        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('signup.html')
        
        # Validate password
        valid_password, password_msg = validate_password(password)
        if not valid_password:
            flash(password_msg, 'error')
            return render_template('signup.html')
        
        # Check passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')
        
        # Check if email already exists
        if get_user_by_email(email):
            flash('An account with this email already exists.', 'error')
            return render_template('signup.html')
        
        # Check if username already exists
        if get_user_by_username(username):
            flash('This username is already taken.', 'error')
            return render_template('signup.html')
        
        # Create user
        success, message, user_id = create_user(username, email, password)
        
        if success:
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
            return render_template('signup.html')
    
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Protected dashboard page"""
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         email=session.get('email'))

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# ============================================
# API ROUTES (For AJAX/Fetch requests)
# ============================================

@app.route('/api/login', methods=['POST'])
def api_login():
    """API endpoint for login"""
    data = request.get_json()
    
    identifier = data.get('identifier', '').strip()
    password = data.get('password', '')
    
    if not identifier or not password:
        return jsonify({'success': False, 'message': 'Please fill in all fields.'}), 400
    
    # Find user
    user = None
    if validate_email(identifier):
        user = get_user_by_email(identifier)
    else:
        user = get_user_by_username(identifier)
    
    if not user or not verify_password(password, user['password']):
        return jsonify({'success': False, 'message': 'Invalid credentials.'}), 401
    
    # Generate token
    token = generate_jwt_token(user['id'], user['username'])
    update_last_login(user['id'])
    
    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email']
        }
    }), 200

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """API endpoint for signup"""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    
    # Validations
    if not all([username, email, password, confirm_password]):
        return jsonify({'success': False, 'message': 'Please fill in all fields.'}), 400
    
    valid_username, username_msg = validate_username(username)
    if not valid_username:
        return jsonify({'success': False, 'message': username_msg}), 400
    
    if not validate_email(email):
        return jsonify({'success': False, 'message': 'Invalid email format.'}), 400
    
    valid_password, password_msg = validate_password(password)
    if not valid_password:
        return jsonify({'success': False, 'message': password_msg}), 400
    
    if password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match.'}), 400
    
    if get_user_by_email(email):
        return jsonify({'success': False, 'message': 'Email already registered.'}), 409
    
    if get_user_by_username(username):
        return jsonify({'success': False, 'message': 'Username already taken.'}), 409
    
    success, message, user_id = create_user(username, email, password)
    
    if success:
        return jsonify({'success': True, 'message': message, 'user_id': user_id}), 201
    else:
        return jsonify({'success': False, 'message': message}), 500

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    """Verify JWT token"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'valid': False, 'message': 'No token provided'}), 401
    
    token = auth_header.split(' ')[1]
    payload = decode_jwt_token(token)
    
    if payload:
        return jsonify({'valid': True, 'user': payload}), 200
    else:
        return jsonify({'valid': False, 'message': 'Invalid or expired token'}), 401

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(e):
    flash('Page not found.', 'error')
    return redirect(url_for('login'))

@app.errorhandler(500)
def server_error(e):
    flash('Internal server error. Please try again.', 'error')
    return redirect(url_for('login'))

# ============================================
# RUN APPLICATION
# ============================================

if __name__ == '__main__':
    print("\n" + "="*50)
    print("   🍷 VINTAGE AUTH SERVER")
    print("="*50)
    print("   Running at: http://localhost:5000")
    print("   Database: SQLite (vintage_auth.db)")
    print("="*50 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)