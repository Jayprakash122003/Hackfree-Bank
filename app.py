import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from functools import wraps
from models import db, User, Transaction, LoginAttempt
from forms import (RegistrationForm, LoginForm, TwoFactorForm, DepositForm, 
                  WithdrawalForm, SetupTwoFactorForm, ChangePasswordForm)
from utils.logger import log_login_attempt, log_security_event, log_transaction
from utils.security import rate_limiter, ip_blocker
from utils.two_factor import (mail, generate_totp_secret, get_totp_uri, verify_totp, 
                            generate_qr_code, generate_email_otp, send_otp_email)
from dotenv import load_dotenv
import re
import json
import traceback

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-for-testing')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure template and static folders
app.template_folder = os.path.join(os.path.dirname(__file__), 'frontend/templates')
app.static_folder = os.path.join(os.path.dirname(__file__), 'frontend/static')

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Initialize extensions
db.init_app(app)
mail.init_app(app)

# Ensure logs directory exists
logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

# Create security.log if it doesn't exist
security_log_path = os.path.join(logs_dir, 'security.log')
if not os.path.exists(security_log_path):
    with open(security_log_path, 'w') as f:
        f.write("# HackfreeBank Security Log\n")
        f.write("# Format: [TIMESTAMP] - IP:PORT - ACTION - DATA\n\n")

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create database tables if they don't exist
with app.app_context():
    db.create_all()


# Custom decorator for requiring 2FA
def two_factor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in but hasn't completed 2FA
        if current_user.is_authenticated:
            if current_user.totp_enabled and not session.get('verified_2fa', False):
                return redirect(url_for('two_factor_verify'))
        return f(*args, **kwargs)
    return decorated_function


# Route for the home page
@app.route('/')
def index():
    return render_template('index.html', title='Welcome to HackFreeBank')


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check if user is already authenticated
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if username or email already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already taken. Please choose another.', 'danger')
            return render_template('register.html', title='Register', form=form)
            
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            flash('Email already registered. Please use a different email or login.', 'danger')
            return render_template('register.html', title='Register', form=form)
        
        # Create new user
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        log_security_event('USER_REGISTERED', f'New user registered with email {form.email.data}')
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', title='Register', form=form)


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if user is already authenticated
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Get client IP address
    ip_address = request.remote_addr
    
    # Check if IP is blocked
    if ip_blocker.is_blocked(ip_address):
        flash('Too many failed login attempts. Please try again later.', 'danger')
        return render_template('locked.html', title='Account Locked')
    
    # Check rate limiting
    if not rate_limiter.consume():
        flash('Too many requests. Please try again later.', 'warning')
        return render_template('error.html', title='Rate Limited', error='Too many requests')
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            # Record successful login attempt
            login_attempt = LoginAttempt(user_id=user.id, ip_address=ip_address, success=True)
            db.session.add(login_attempt)
            db.session.commit()
            
            # Update user's last login time
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log successful login
            log_login_attempt(user.username, ip_address, True)
            ip_blocker.record_successful_attempt(ip_address)
            
            # Log in the user with Flask-Login
            login_user(user, remember=form.remember.data)
            
            # If 2FA is enabled for this user, redirect to verification
            if user.totp_enabled:
                session['verified_2fa'] = False
                return redirect(url_for('two_factor_verify'))
            else:
                session['verified_2fa'] = True
                
            # Redirect to the dashboard or the page they were trying to access
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            # Record failed login attempt
            if user:
                login_attempt = LoginAttempt(user_id=user.id, ip_address=ip_address, success=False)
            else:
                login_attempt = LoginAttempt(user_id=None, ip_address=ip_address, success=False)
            db.session.add(login_attempt)
            db.session.commit()
            
            # Log failed login
            log_login_attempt(form.username.data, ip_address, False)
            ip_blocker.record_failed_attempt(ip_address)
            
            flash('Login failed. Please check your username and password.', 'danger')
    
    return render_template('login.html', title='Login', form=form)


# Two-factor verification route
@app.route('/two-factor', methods=['GET', 'POST'])
@login_required
def two_factor_verify():
    if not current_user.totp_enabled:
        session['verified_2fa'] = True
        return redirect(url_for('dashboard'))
        
    if session.get('verified_2fa'):
        return redirect(url_for('dashboard'))
        
    form = TwoFactorForm()
    
    if form.validate_on_submit():
        if verify_totp(current_user.totp_secret, form.token.data):
            session['verified_2fa'] = True
            log_security_event('2FA_SUCCESS', 'Two-factor authentication successful', current_user.username)
            return redirect(url_for('dashboard'))
        else:
            log_security_event('2FA_FAILED', 'Two-factor authentication failed', current_user.username)
            flash('Invalid verification code. Please try again.', 'danger')
    
    return render_template('two_factor.html', title='Two-Factor Authentication', form=form)


# Logout route
@app.route('/logout')
@login_required
def logout():
    log_security_event('USER_LOGOUT', f'User logged out', current_user.username)
    logout_user()
    session.pop('verified_2fa', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# Dashboard route
@app.route('/dashboard')
@login_required
@two_factor_required
def dashboard():
    # Get recent transactions for the user
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).limit(5).all()
    
    # Read intrusion log data from both JSON and text sources
    json_stats = get_intrusion_stats_from_json()
    text_stats = get_intrusion_stats_from_text()
    
    # Use text stats if they have data and JSON doesn't, or if text has more data
    if (text_stats['total_attempts'] > 0 and json_stats['total_attempts'] == 0) or \
       (text_stats['total_attempts'] > json_stats['total_attempts']):
        intrusion_stats = text_stats
    else:
        intrusion_stats = json_stats
    
    return render_template('dashboard.html', 
                          title='Dashboard', 
                          user=current_user, 
                          transactions=transactions, 
                          intrusion_stats=intrusion_stats)


# Helper function to parse intrusion log lines in different formats
def parse_intrusion_log_line(line):
    """Parse intrusion log lines in different possible formats"""
    
    # Try format from monitor.py: [YYYY-MM-DD HH:MM:SS] Connection attempt from IP:PORT - Message
    match = re.match(r'\[(.*?)\] Connection attempt from (.*?) - (.*)', line.strip())
    if match:
        timestamp, ip_port, message = match.groups()
        # Split IP:PORT if it contains a port
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
        else:
            ip = ip_port
            port = ""
        return {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'message': message,
            'action': message,
            'location': 'Unknown'
        }
    
    # Try general format: [YYYY-MM-DD HH:MM:SS] Connection attempt from IP:PORT
    match = re.match(r'\[(.*?)\] Connection attempt from (.*)', line.strip())
    if match:
        timestamp, ip_port = match.groups()
        # Split IP:PORT if it contains a port
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
        else:
            ip = ip_port
            port = ""
        return {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'message': "Connection attempt",
            'action': "Connection attempt",
            'location': 'Unknown'
        }
    
    # Try format: [YYYY-MM-DD HH:MM:SS] Data received from IP:PORT
    match = re.match(r'\[(.*?)\] Data received from (.*)', line.strip())
    if match:
        timestamp, ip_port = match.groups()
        # Split IP:PORT if it contains a port
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
        else:
            ip = ip_port
            port = ""
        return {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'message': "Data received",
            'action': "Data received",
            'location': 'Unknown'
        }
    
    # Try format: [YYYY-MM-DD HH:MM:SS] Warning sent to IP:PORT
    match = re.match(r'\[(.*?)\] (Warning sent to) (.*)', line.strip())
    if match:
        timestamp, action, ip_port = match.groups()
        # Split IP:PORT if it contains a port
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
        else:
            ip = ip_port
            port = ""
        return {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'message': action,
            'action': action,
            'location': 'Unknown'
        }
    
    # Try format: [YYYY-MM-DD HH:MM:SS] Connection closed from IP:PORT
    match = re.match(r'\[(.*?)\] Connection closed from (.*)', line.strip())
    if match:
        timestamp, ip_port = match.groups()
        # Split IP:PORT if it contains a port
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
        else:
            ip = ip_port
            port = ""
        return {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'message': "Connection closed",
            'action': "Connection closed",
            'location': 'Unknown'
        }
    
    # Try format: [YYYY-MM-DD HH:MM:SS] Connection timed out from IP:PORT
    match = re.match(r'\[(.*?)\] Connection timed out from (.*)', line.strip())
    if match:
        timestamp, ip_port = match.groups()
        # Split IP:PORT if it contains a port
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
        else:
            ip = ip_port
            port = ""
        return {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'message': "Connection timed out",
            'action': "Connection timed out",
            'location': 'Unknown'
        }
    
    # Try format for intrusion_log.txt: [YYYY-MM-DD HH:MM:SS] Connection attempt from IP:PORT - Message
    match = re.match(r'\[(.*?)\] .*? from (.*?) - (.*)', line.strip())
    if match:
        timestamp, ip_port, message = match.groups()
        # Split IP:PORT if it contains a port
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
        else:
            ip = ip_port
            port = ""
        return {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'message': message,
            'action': message,
            'location': 'Unknown'
        }
    
    # Generic format: [YYYY-MM-DD HH:MM:SS] Action from IP:PORT
    # This should catch any other format following the pattern
    match = re.match(r'\[(.*?)\] (.*?) from (.*)', line.strip())
    if match:
        timestamp, action, ip_port = match.groups()
        
        # Split IP:PORT if it contains a port
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
        else:
            ip = ip_port
            port = ""
        
        return {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'message': action,
            'location': 'Unknown',  # Default location
            'action': action  # Include action directly
        }
        
    return None  # Return None if no format matches


# Transaction history route
@app.route('/transactions')
@login_required
@two_factor_required
def transactions():
    page = request.args.get('page', 1, type=int)
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(
        Transaction.timestamp.desc()
    ).paginate(page=page, per_page=10)
    
    return render_template('transactions.html', title='Transaction History', transactions=transactions)


# Deposit route
@app.route('/deposit', methods=['GET', 'POST'])
@login_required
@two_factor_required
def deposit():
    form = DepositForm()
    
    if form.validate_on_submit():
        amount = round(form.amount.data, 2)  # Round to 2 decimal places
        
        # Create transaction
        transaction = Transaction(
            user_id=current_user.id,
            amount=amount,
            transaction_type='deposit',
            description=form.description.data
        )
        
        # Update user balance
        current_user.balance += amount
        
        # Save changes
        db.session.add(transaction)
        db.session.commit()
        
        # Log transaction
        log_transaction(current_user.username, 'deposit', amount)
        
        flash(f'Deposit of ${amount:.2f} successful.', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('deposit.html', title='Make a Deposit', form=form)


# Withdrawal route
@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
@two_factor_required
def withdraw():
    form = WithdrawalForm()
    
    if form.validate_on_submit():
        amount = round(form.amount.data, 2)  # Round to 2 decimal places
        
        # Check if user has sufficient balance
        if amount > current_user.balance:
            flash('Insufficient funds for this withdrawal.', 'danger')
            return render_template('withdraw.html', title='Make a Withdrawal', form=form)
            
        # Create transaction
        transaction = Transaction(
            user_id=current_user.id,
            amount=amount,
            transaction_type='withdrawal',
            description=form.description.data
        )
        
        # Update user balance
        current_user.balance -= amount
        
        # Save changes
        db.session.add(transaction)
        db.session.commit()
        
        # Log transaction
        log_transaction(current_user.username, 'withdrawal', amount)
        
        flash(f'Withdrawal of ${amount:.2f} successful.', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('withdraw.html', title='Make a Withdrawal', form=form)


# Profile route
@app.route('/profile')
@login_required
@two_factor_required
def profile():
    return render_template('profile.html', title='My Profile', user=current_user)


# Setup two-factor authentication route
@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_two_factor():
    form = SetupTwoFactorForm()
    
    # Generate a new secret if it doesn't exist
    if not current_user.totp_secret:
        current_user.totp_secret = generate_totp_secret()
        db.session.commit()
    
    # Generate QR code
    totp_uri = get_totp_uri(current_user.totp_secret, current_user.username)
    qr_code = generate_qr_code(totp_uri)
    
    if form.validate_on_submit():
        current_user.totp_enabled = form.enable.data
        db.session.commit()
        
        if form.enable.data:
            log_security_event('2FA_ENABLED', 'Two-factor authentication enabled', current_user.username)
            flash('Two-factor authentication has been enabled for your account.', 'success')
        else:
            log_security_event('2FA_DISABLED', 'Two-factor authentication disabled', current_user.username)
            flash('Two-factor authentication has been disabled for your account.', 'info')
            
        return redirect(url_for('profile'))
        
    # Initialize form with current setting
    form.enable.data = current_user.totp_enabled
    
    return render_template('setup_2fa.html', title='Setup Two-Factor Authentication', 
                          form=form, qr_code=qr_code, secret=current_user.totp_secret)


# Change password route
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
@two_factor_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html', title='Change Password', form=form)
            
        # Set new password
        current_user.set_password(form.new_password.data)
        db.session.commit()
        
        log_security_event('PASSWORD_CHANGED', 'User changed their password', current_user.username)
        flash('Your password has been updated.', 'success')
        return redirect(url_for('profile'))
        
    return render_template('change_password.html', title='Change Password', form=form)


# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', title='Page Not Found', error='The page you requested was not found.'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', title='Server Error', error='An internal server error occurred.'), 500


# Add context processor for the current year
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


# Add this API endpoint for intrusion log data
@app.route('/api/attack-log', methods=['GET'])
def attack_log_api():
    """API endpoint to get intrusion log data in JSON format"""
    # Check if we should use the JSON file
    json_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.json')
    log_data = []
    
    if os.path.exists(json_log_path) and os.path.getsize(json_log_path) > 2:
        try:
            with open(json_log_path, 'r', encoding='utf-8') as f:
                intrusion_data = json.load(f)
                
                # Convert to expected format if needed
                for entry in intrusion_data:
                    formatted_entry = {
                        'timestamp': entry.get('timestamp', ''),
                        'ip': entry.get('ip', 'unknown'),
                        'port': '',  # Port may be part of the IP string
                        'action': entry.get('event', ''),
                        'message': entry.get('event', ''),
                        'event': entry.get('event', '')  # Include event field directly
                    }
                    log_data.append(formatted_entry)
                
                # Sort by timestamp (most recent first)
                log_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                
                if log_data:
                    return jsonify(log_data)
                
        except Exception as e:
            app.logger.error(f"Error reading JSON intrusion log: {e}")
    
    # Fallback to text file if JSON file is empty or not found
    intrusion_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.txt')
    
    if os.path.exists(intrusion_log_path):
        try:
            with open(intrusion_log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    # Skip header/comment lines
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    # Parse the line using the helper function
                    entry = parse_intrusion_log_line(line)
                    if entry:
                        log_data.append(entry)
                
                # Sort by timestamp (most recent first)
                log_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                        
        except Exception as e:
            app.logger.error(f"Error reading intrusion log: {e}")
            return jsonify({'error': 'Failed to read intrusion log', 'details': str(e)}), 500
    
    return jsonify(log_data)


# Add monitor data endpoint to include data from monitor.py
@app.route('/api/monitor-log', methods=['GET'])
def monitor_log_api():
    """API endpoint to get monitor log data in JSON format"""
    # Check if we should use the JSON file
    json_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.json')
    log_data = []
    
    # Try the JSON file first
    if os.path.exists(json_log_path) and os.path.getsize(json_log_path) > 2:
        try:
            with open(json_log_path, 'r', encoding='utf-8') as f:
                intrusion_data = json.load(f)
                
                # Convert to expected format if needed
                for entry in intrusion_data:
                    # Parse timestamp to get hour for hourly grouping
                    try:
                        dt = datetime.strptime(entry.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
                        hour = dt.strftime('%Y-%m-%d %H:00')
                    except (ValueError, TypeError):
                        hour = entry.get('timestamp', '').split(' ')[0]  # Fallback to just the date
                    
                    formatted_entry = {
                        'timestamp': entry.get('timestamp', ''),
                        'ip': entry.get('ip', 'unknown'),
                        'port': '',  # Port may be part of the IP string
                        'message': entry.get('event', ''),
                        'hour': hour,
                        'action': entry.get('event', '')
                    }
                    log_data.append(formatted_entry)
                
                # Sort by timestamp, most recent first
                log_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                
                if log_data:
                    return jsonify(log_data)
                
        except Exception as e:
            app.logger.error(f"Error reading JSON intrusion log: {e}")
    
    # Fallback to text file if JSON file is empty or not found
    intrusion_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.txt')
    
    try:
        # Check if log file exists
        if os.path.exists(intrusion_log_path):
            with open(intrusion_log_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                for line in lines:
                    # Skip header/comment lines
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    # Parse the log entry using the helper function
                    entry = parse_intrusion_log_line(line)
                    if entry:
                        # Parse timestamp to get hour for hourly grouping
                        try:
                            dt = datetime.strptime(entry['timestamp'], '%Y-%m-%d %H:%M:%S')
                            hour = dt.strftime('%Y-%m-%d %H:00')
                        except ValueError:
                            hour = entry['timestamp'].split(' ')[0]  # Fallback to just the date
                        
                        log_entry = {
                            "timestamp": entry['timestamp'],
                            "ip": entry['ip'],
                            "port": entry.get('port', ''),
                            "message": entry.get('message', ''),
                            "hour": hour,
                            "action": entry.get('action', entry.get('message', ''))
                        }
                        log_data.append(log_entry)
            
            # Sort by timestamp, most recent first
            log_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify(log_data)
    
    except Exception as e:
        app.logger.error(f"Error reading text intrusion log: {e}")
        return jsonify({"error": str(e), "data": []}), 500


# Intrusion dashboard route
@app.route('/intrusion-dashboard')
@login_required
@two_factor_required
def intrusion_dashboard():
    """Render the intrusion dashboard page"""
    # Check if we have any data before rendering the dashboard
    json_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.json')
    text_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.txt')
    
    has_data = False
    
    # Check JSON file
    if os.path.exists(json_log_path) and os.path.getsize(json_log_path) > 2:  # "{}" size is 2
        try:
            with open(json_log_path, 'r') as f:
                data = json.load(f)
                if data and len(data) > 0:
                    has_data = True
        except:
            pass
    
    # Check text file if no JSON data
    if not has_data and os.path.exists(text_log_path):
        try:
            with open(text_log_path, 'r') as f:
                lines = [l for l in f if not l.startswith('#') and l.strip()]
                if lines and len(lines) > 0:
                    has_data = True
        except:
            pass
    
    return render_template('Intrusion dashboard.html', title='Intrusion Dashboard', has_data=has_data)


# Add API endpoint for dashboard security stats
@app.route('/api/dashboard-security-stats', methods=['GET'])
@login_required
@two_factor_required
def dashboard_security_stats():
    """API endpoint to get security statistics for the dashboard"""
    # Try to get stats from both sources and use the most populated one
    json_stats = get_intrusion_stats_from_json()
    text_stats = get_intrusion_stats_from_text()
    
    # If both sources have errors, log them
    if json_stats.get('error') and text_stats.get('error'):
        app.logger.warning(f"JSON stats error: {json_stats.get('error')}")
        app.logger.warning(f"Text stats error: {text_stats.get('error')}")
    
    # Use text stats if they have data and JSON doesn't, or if text has more data
    if (text_stats['total_attempts'] > 0 and json_stats['total_attempts'] == 0) or \
       (text_stats['total_attempts'] > json_stats['total_attempts']):
        return jsonify(text_stats)
    
    return jsonify(json_stats)


# Helper function to get intrusion statistics from JSON log file
def get_intrusion_stats_from_json():
    """Read and process the intrusion JSON log file to get statistics"""
    intrusion_stats = {
        'total_attempts': 0,
        'unique_ips': set(),
        'ip_counts': {},
        'recent_intrusions': [],
        'top_ips': {},
        'unique_ip_count': 0,
        'last_attack': None,
        'attacks_by_day': {},
        'timestamps': [],
        'error': None
    }
    
    json_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.json')
    
    if not os.path.exists(json_log_path):
        intrusion_stats['error'] = "JSON log file not found"
        return intrusion_stats
    
    if os.path.getsize(json_log_path) == 0:
        intrusion_stats['error'] = "JSON log file is empty"
        return intrusion_stats
    
    try:
        with open(json_log_path, 'r', encoding='utf-8') as f:
            try:
                intrusion_data = json.load(f)
                
                if not intrusion_data:
                    intrusion_stats['error'] = "No data in JSON log file"
                    return intrusion_stats
                
                # Count total attempts
                intrusion_stats['total_attempts'] = len(intrusion_data)
                
                # Process each intrusion entry
                for entry in intrusion_data:
                    try:
                        ip = entry.get('ip', 'unknown')
                        timestamp = entry.get('timestamp', '')
                        
                        # Add timestamp to list for time-based analysis
                        intrusion_stats['timestamps'].append(timestamp)
                        
                        # Add IP to unique set
                        intrusion_stats['unique_ips'].add(ip)
                        
                        # Increment count for this IP
                        intrusion_stats['ip_counts'][ip] = intrusion_stats['ip_counts'].get(ip, 0) + 1
                        
                        # Aggregate attacks by day for charting
                        try:
                            # Parse the timestamp and get the date part
                            date_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                            day_key = date_obj.strftime("%Y-%m-%d")
                            
                            # Increment the count for this day
                            intrusion_stats['attacks_by_day'][day_key] = intrusion_stats['attacks_by_day'].get(day_key, 0) + 1
                        except (ValueError, TypeError) as e:
                            app.logger.warning(f"Error parsing timestamp {timestamp}: {e}")
                    except Exception as e:
                        app.logger.error(f"Error processing JSON entry: {entry}: {e}")
                        continue
                
                # Convert entries to a format similar to what the template expects
                formatted_entries = []
                for entry in intrusion_data:
                    try:
                        formatted_entry = {
                            'timestamp': entry.get('timestamp', ''),
                            'ip': entry.get('ip', 'unknown'),
                            'port': '',  # Port is now part of the IP string
                            'message': entry.get('event', ''),
                            'location': 'Unknown',  # Default location
                            'event': entry.get('event', '')  # Include event field directly
                        }
                        formatted_entries.append(formatted_entry)
                    except Exception as e:
                        app.logger.error(f"Error formatting JSON entry: {entry}: {e}")
                        continue
                
                # Sort by timestamp (most recent first)
                formatted_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                
                # Set the last attack (most recent)
                if formatted_entries:
                    intrusion_stats['last_attack'] = formatted_entries[0]
                
                # Take the 10 most recent intrusions for display
                intrusion_stats['recent_intrusions'] = formatted_entries[:10]
                
                # Get the top 5 IPs by attack count for chart
                top_ips = sorted(
                    intrusion_stats['ip_counts'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
                
                intrusion_stats['top_ips'] = {ip: count for ip, count in top_ips}
                
                # Sort the attacks_by_day for chronological display
                intrusion_stats['attacks_by_day'] = dict(sorted(
                    intrusion_stats['attacks_by_day'].items(),
                    key=lambda x: x[0]
                ))
                
            except json.JSONDecodeError as e:
                app.logger.error(f"JSON decode error: {e}")
                intrusion_stats['error'] = f"Invalid JSON format: {str(e)}"
                return intrusion_stats
                
    except Exception as e:
        app.logger.error(f"Error reading intrusion JSON log: {e}")
        intrusion_stats['error'] = f"Error reading log: {str(e)}"
        traceback.print_exc()
    
    # Convert the set to len for template
    intrusion_stats['unique_ip_count'] = len(intrusion_stats['unique_ips'])
    
    # Convert set to list for JSON serialization
    intrusion_stats['unique_ips'] = list(intrusion_stats['unique_ips'])
    
    return intrusion_stats


# Helper function to get intrusion statistics from text log file
def get_intrusion_stats_from_text():
    """Read and process the intrusion text log file to get statistics"""
    intrusion_stats = {
        'total_attempts': 0,
        'unique_ips': set(),
        'ip_counts': {},
        'recent_intrusions': [],
        'top_ips': {},
        'unique_ip_count': 0,
        'last_attack': None,
        'attacks_by_day': {},
        'timestamps': [],
        'error': None
    }
    
    # Look for the log file in the app's directory
    intrusion_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.txt')
    
    if not os.path.exists(intrusion_log_path):
        intrusion_stats['error'] = "Intrusion log file not found"
        return intrusion_stats
    
    try:
        with open(intrusion_log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
            # Skip header/comment lines
            data_lines = [line for line in lines if not line.startswith('#') and line.strip()]
            
            if not data_lines:
                intrusion_stats['error'] = "No data in intrusion log file"
                return intrusion_stats
            
            # Count total attempts
            intrusion_stats['total_attempts'] = len(data_lines)
            
            # Process data from text file
            formatted_entries = []
            
            for line in data_lines:
                try:
                    # Parse the log entry
                    entry = parse_intrusion_log_line(line)
                    if entry:
                        ip = entry.get('ip', 'unknown')
                        timestamp = entry.get('timestamp', '')
                        
                        # Add to timestamps list for time-based analysis
                        intrusion_stats['timestamps'].append(timestamp)
                        
                        # Add IP to unique set
                        intrusion_stats['unique_ips'].add(ip)
                        
                        # Increment count for this IP
                        intrusion_stats['ip_counts'][ip] = intrusion_stats['ip_counts'].get(ip, 0) + 1
                        
                        # Add to formatted entries
                        formatted_entries.append(entry)
                        
                        # Aggregate attacks by day for charting
                        try:
                            # Parse the timestamp and get the date part
                            date_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                            day_key = date_obj.strftime("%Y-%m-%d")
                            
                            # Increment the count for this day
                            intrusion_stats['attacks_by_day'][day_key] = intrusion_stats['attacks_by_day'].get(day_key, 0) + 1
                        except (ValueError, TypeError) as e:
                            app.logger.warning(f"Error parsing timestamp {timestamp}: {e}")
                except Exception as e:
                    app.logger.error(f"Error processing log line: {line.strip()}: {e}")
                    # Continue processing other lines
                    continue
            
            if formatted_entries:
                # Sort by timestamp (most recent first)
                formatted_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                
                # Set the last attack (most recent)
                intrusion_stats['last_attack'] = formatted_entries[0]
                
                # Take the 10 most recent intrusions for display
                intrusion_stats['recent_intrusions'] = formatted_entries[:10]
                
                # Get the top 5 IPs by attack count for chart
                top_ips = sorted(
                    intrusion_stats['ip_counts'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
                
                intrusion_stats['top_ips'] = {ip: count for ip, count in top_ips}
                
                # Sort the attacks_by_day for chronological display
                intrusion_stats['attacks_by_day'] = dict(sorted(
                    intrusion_stats['attacks_by_day'].items(),
                    key=lambda x: x[0]
                ))
                
    except Exception as e:
        app.logger.error(f"Error reading intrusion log file: {e}")
        intrusion_stats['error'] = f"Error reading log: {str(e)}"
        traceback.print_exc()
    
    # Convert the set to len for template
    intrusion_stats['unique_ip_count'] = len(intrusion_stats['unique_ips'])
    
    # Convert set to list for JSON serialization
    intrusion_stats['unique_ips'] = list(intrusion_stats['unique_ips'])
    
    return intrusion_stats


# Add a route to validate log files
@app.route('/api/validate-logs', methods=['GET'])
@login_required
@two_factor_required
def validate_logs():
    """Check if log files exist and are being written to correctly"""
    results = {
        'intrusion_log_txt': {
            'exists': False,
            'writable': False,
            'size': 0,
            'last_modified': None,
            'example_line': None
        },
        'intrusion_log_json': {
            'exists': False,
            'writable': False,
            'size': 0,
            'last_modified': None,
            'example_entry': None
        },
        'monitor_running': False,
        'recommendations': []
    }
    
    # Check text log
    text_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.txt')
    
    if os.path.exists(text_log_path):
        results['intrusion_log_txt']['exists'] = True
        results['intrusion_log_txt']['size'] = os.path.getsize(text_log_path)
        results['intrusion_log_txt']['last_modified'] = datetime.fromtimestamp(
            os.path.getmtime(text_log_path)
        ).strftime("%Y-%m-%d %H:%M:%S")
        
        # Check if the file is writable
        try:
            with open(text_log_path, 'a') as f:
                results['intrusion_log_txt']['writable'] = True
        except:
            results['intrusion_log_txt']['writable'] = False
            results['recommendations'].append("The text log file exists but is not writable. Check permissions.")
        
        # Get an example line
        try:
            with open(text_log_path, 'r') as f:
                lines = f.readlines()
                data_lines = [line for line in lines if not line.startswith('#') and line.strip()]
                if data_lines:
                    results['intrusion_log_txt']['example_line'] = data_lines[-1].strip()
        except:
            results['recommendations'].append("Could not read from the text log file. Check permissions.")
    else:
        results['recommendations'].append("The text log file does not exist. Make sure monitor.py is running.")
    
    # Check JSON log
    json_log_path = os.path.join(os.path.dirname(__file__), 'intrusion_log.json')
    
    if os.path.exists(json_log_path):
        results['intrusion_log_json']['exists'] = True
        results['intrusion_log_json']['size'] = os.path.getsize(json_log_path)
        results['intrusion_log_json']['last_modified'] = datetime.fromtimestamp(
            os.path.getmtime(json_log_path)
        ).strftime("%Y-%m-%d %H:%M:%S")
        
        # Check if the file is writable
        try:
            with open(json_log_path, 'a') as f:
                results['intrusion_log_json']['writable'] = True
        except:
            results['intrusion_log_json']['writable'] = False
            results['recommendations'].append("The JSON log file exists but is not writable. Check permissions.")
        
        # Get an example entry
        try:
            with open(json_log_path, 'r') as f:
                try:
                    data = json.load(f)
                    if data and len(data) > 0:
                        results['intrusion_log_json']['example_entry'] = data[-1]
                except json.JSONDecodeError:
                    results['recommendations'].append("The JSON log file is not valid JSON. It may be corrupted.")
        except:
            results['recommendations'].append("Could not read from the JSON log file. Check permissions.")
    else:
        results['recommendations'].append("The JSON log file does not exist. Make sure monitor.py is running.")
    
    # Try to check if monitor.py is running
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'python' in proc.name().lower() and any('monitor.py' in cmd.lower() for cmd in proc.cmdline() if cmd):
                    results['monitor_running'] = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except ImportError:
        results['recommendations'].append("Could not check if monitor.py is running - psutil module not installed.")
    
    if not results['monitor_running']:
        results['recommendations'].append("The monitor.py process does not appear to be running. Start it with 'python monitor.py'.")
    
    # Add general recommendations
    if not results['intrusion_log_txt']['exists'] and not results['intrusion_log_json']['exists']:
        results['recommendations'].append("No log files exist. Run monitor.py first to create them.")
    elif results['intrusion_log_txt']['size'] == 0 and results['intrusion_log_json']['size'] == 0:
        results['recommendations'].append("Log files exist but are empty. The monitor might not have detected any intrusions yet.")
    
    return jsonify(results)


# Run the application
if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'True').lower() == 'true') 