"""
PhishGuard - A Phishing Simulation Tool for Employee Education
Author: PhishGuard Team
License: MIT
"""

import os
import json
import random
import secrets
import smtplib
import logging
import warnings
import datetime
import argparse
import sqlite3
import hashlib
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from contextlib import contextmanager

# Initialize Flask app
app = Flask(__name__)
# Never ship a hardcoded secret key: a known key lets anyone forge session
# cookies (and CSRF tokens). Use SECRET_KEY from the environment; if it is
# missing, generate a strong ephemeral key and warn (sessions then reset on
# restart, which is the safe failure mode for a security-training tool).
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    _secret_key = secrets.token_hex(32)
    warnings.warn(
        "SECRET_KEY is not set; using a random ephemeral key. Sessions will not "
        "persist across restarts. Set SECRET_KEY in the environment for production.",
        RuntimeWarning,
    )
app.config['SECRET_KEY'] = _secret_key
app.config['DATABASE'] = os.path.join(app.instance_path, 'phishguard.db')
app.config['SMTP_SERVER'] = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
app.config['SMTP_PORT'] = int(os.environ.get('SMTP_PORT', 587))
app.config['SMTP_USERNAME'] = os.environ.get('SMTP_USERNAME', '')
app.config['SMTP_PASSWORD'] = os.environ.get('SMTP_PASSWORD', '')

# Ensure the instance folder exists
os.makedirs(app.instance_path, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(app.instance_path, 'phishguard.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database helper functions
@contextmanager
def get_db_connection():
    """Create a database connection context manager"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with schema"""
    with get_db_connection() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            department TEXT NOT NULL,
            job_title TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            template_id INTEGER NOT NULL,
            created_by INTEGER NOT NULL,
            status TEXT NOT NULL,
            scheduled_at TIMESTAMP,
            completed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id),
            FOREIGN KEY (template_id) REFERENCES templates (id)
        );
        
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            phishing_type TEXT NOT NULL,
            difficulty_level TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        );
        
        CREATE TABLE IF NOT EXISTS campaign_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
            unique_token TEXT UNIQUE NOT NULL,
            email_sent_at TIMESTAMP,
            email_opened_at TIMESTAMP,
            link_clicked_at TIMESTAMP,
            reported_at TIMESTAMP,
            user_agent TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
            FOREIGN KEY (employee_id) REFERENCES employees (id)
        );
        
        CREATE TABLE IF NOT EXISTS training_modules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            content TEXT NOT NULL,
            phishing_type TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        );
        
        CREATE TABLE IF NOT EXISTS employee_training (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            training_module_id INTEGER NOT NULL,
            completed_at TIMESTAMP,
            score REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees (id),
            FOREIGN KEY (training_module_id) REFERENCES training_modules (id)
        );
        ''')
        logger.info("Database initialized successfully")

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user:
        return User(user['id'], user['username'], user['email'], user['is_admin'])
    return None

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EmployeeForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    department = StringField('Department', validators=[DataRequired()])
    job_title = StringField('Job Title')
    submit = SubmitField('Submit')

class TemplateForm(FlaskForm):
    name = StringField('Template Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    subject = StringField('Email Subject', validators=[DataRequired()])
    body = TextAreaField('Email Body (HTML)', validators=[DataRequired()])
    phishing_type = SelectField('Phishing Type', choices=[
        ('credential_harvest', 'Credential Harvesting'),
        ('malware', 'Malware Simulation'),
        ('data_theft', 'Data Theft'),
        ('spear_phishing', 'Spear Phishing'),
        ('financial', 'Financial Fraud')
    ], validators=[DataRequired()])
    difficulty_level = SelectField('Difficulty Level', choices=[
        ('easy', 'Easy - Obvious signs of phishing'),
        ('medium', 'Medium - Some identifiable signs'),
        ('hard', 'Hard - Very subtle signs'),
        ('expert', 'Expert - Nearly indistinguishable from legitimate')
    ], validators=[DataRequired()])
    submit = SubmitField('Create Template')

class CampaignForm(FlaskForm):
    name = StringField('Campaign Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    template_id = SelectField('Email Template', coerce=int, validators=[DataRequired()])
    scheduled_at = StringField('Schedule Date (YYYY-MM-DD HH:MM)', validators=[DataRequired()])
    submit = SubmitField('Create Campaign')

class TrainingModuleForm(FlaskForm):
    title = StringField('Module Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    content = TextAreaField('Content (HTML)', validators=[DataRequired()])
    phishing_type = SelectField('Related Phishing Type', choices=[
        ('credential_harvest', 'Credential Harvesting'),
        ('malware', 'Malware Simulation'),
        ('data_theft', 'Data Theft'),
        ('spear_phishing', 'Spear Phishing'),
        ('financial', 'Financial Fraud'),
        ('general', 'General Awareness')
    ], validators=[DataRequired()])
    submit = SubmitField('Create Module')

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', 
                               (form.username.data,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], form.password.data):
            user_obj = User(user['id'], user['username'], user['email'], user['is_admin'])
            login_user(user_obj)
            logger.info(f"User {user['username']} logged in")
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db_connection() as conn:
        campaigns = conn.execute('''
            SELECT c.*, t.name as template_name, u.username as creator,
                   COUNT(ct.id) as target_count,
                   SUM(CASE WHEN ct.link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as click_count
            FROM campaigns c
            JOIN templates t ON c.template_id = t.id
            JOIN users u ON c.created_by = u.id
            LEFT JOIN campaign_targets ct ON c.id = ct.campaign_id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        ''').fetchall()
        
        recent_clicks = conn.execute('''
            SELECT ct.*, e.first_name, e.last_name, e.email, e.department,
                   c.name as campaign_name
            FROM campaign_targets ct
            JOIN employees e ON ct.employee_id = e.id
            JOIN campaigns c ON ct.campaign_id = c.id
            WHERE ct.link_clicked_at IS NOT NULL
            ORDER BY ct.link_clicked_at DESC
            LIMIT 10
        ''').fetchall()
        
        stats = {
            'total_campaigns': len(campaigns),
            'active_campaigns': sum(1 for c in campaigns if c['status'] == 'active'),
            'total_employees': conn.execute('SELECT COUNT(*) FROM employees').fetchone()[0],
            'total_clicks': conn.execute('''
                SELECT COUNT(*) FROM campaign_targets 
                WHERE link_clicked_at IS NOT NULL
            ''').fetchone()[0]
        }
    
    return render_template('dashboard.html', 
                          campaigns=campaigns, 
                          recent_clicks=recent_clicks,
                          stats=stats)

@app.route('/employees', methods=['GET'])
@login_required
def list_employees():
    with get_db_connection() as conn:
        employees = conn.execute('SELECT * FROM employees ORDER BY last_name').fetchall()
    return render_template('employees/list.html', employees=employees)

@app.route('/employees/add', methods=['GET', 'POST'])
@login_required
def add_employee():
    form = EmployeeForm()
    if form.validate_on_submit():
        try:
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO employees (first_name, last_name, email, department, job_title)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    form.first_name.data,
                    form.last_name.data,
                    form.email.data,
                    form.department.data,
                    form.job_title.data
                ))
                conn.commit()
            flash('Employee added successfully', 'success')
            return redirect(url_for('list_employees'))
        except sqlite3.IntegrityError:
            flash('Email already exists', 'danger')
    
    return render_template('employees/add.html', form=form)

@app.route('/templates', methods=['GET'])
@login_required
def list_templates():
    with get_db_connection() as conn:
        templates = conn.execute('''
            SELECT t.*, u.username as creator
            FROM templates t
            JOIN users u ON t.created_by = u.id
            ORDER BY t.created_at DESC
        ''').fetchall()
    return render_template('templates/list.html', templates=templates)

@app.route('/templates/add', methods=['GET', 'POST'])
@login_required
def add_template():
    form = TemplateForm()
    if form.validate_on_submit():
        with get_db_connection() as conn:
            conn.execute('''
                INSERT INTO templates (name, description, subject, body, 
                                      phishing_type, difficulty_level, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                form.name.data,
                form.description.data,
                form.subject.data,
                form.body.data,
                form.phishing_type.data,
                form.difficulty_level.data,
                current_user.id
            ))
            conn.commit()
        flash('Template created successfully', 'success')
        return redirect(url_for('list_templates'))
    
    return render_template('templates/add.html', form=form)

@app.route('/campaigns', methods=['GET'])
@login_required
def list_campaigns():
    with get_db_connection() as conn:
        campaigns = conn.execute('''
            SELECT c.*, t.name as template_name, u.username as creator,
                   COUNT(ct.id) as target_count,
                   SUM(CASE WHEN ct.email_sent_at IS NOT NULL THEN 1 ELSE 0 END) as sent_count,
                   SUM(CASE WHEN ct.link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as click_count,
                   SUM(CASE WHEN ct.reported_at IS NOT NULL THEN 1 ELSE 0 END) as report_count
            FROM campaigns c
            JOIN templates t ON c.template_id = t.id
            JOIN users u ON c.created_by = u.id
            LEFT JOIN campaign_targets ct ON c.id = ct.campaign_id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        ''').fetchall()
    return render_template('campaigns/list.html', campaigns=campaigns)

@app.route('/campaigns/add', methods=['GET', 'POST'])
@login_required
def add_campaign():
    form = CampaignForm()
    
    with get_db_connection() as conn:
        templates = conn.execute('SELECT id, name FROM templates').fetchall()
    
    form.template_id.choices = [(t['id'], t['name']) for t in templates]
    
    if form.validate_on_submit():
        with get_db_connection() as conn:
            conn.execute('''
                INSERT INTO campaigns (name, description, template_id, created_by, 
                                      status, scheduled_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                form.name.data,
                form.description.data,
                form.template_id.data,
                current_user.id,
                'scheduled',
                form.scheduled_at.data
            ))
            conn.commit()
        flash('Campaign created successfully', 'success')
        return redirect(url_for('list_campaigns'))
    
    return render_template('campaigns/add.html', form=form)

@app.route('/campaigns/<int:campaign_id>/targets', methods=['GET', 'POST'])
@login_required
def campaign_targets(campaign_id):
    with get_db_connection() as conn:
        campaign = conn.execute('SELECT * FROM campaigns WHERE id = ?', (campaign_id,)).fetchone()
        if not campaign:
            flash('Campaign not found', 'danger')
            return redirect(url_for('list_campaigns'))
        
        if request.method == 'POST':
            employee_ids = request.form.getlist('employee_ids')
            for emp_id in employee_ids:
                unique_token = str(uuid.uuid4())
                
                conn.execute('''
                    INSERT INTO campaign_targets (campaign_id, employee_id, unique_token)
                    VALUES (?, ?, ?)
                ''', (campaign_id, emp_id, unique_token))
            
            conn.commit()
            flash(f'Added {len(employee_ids)} targets to campaign', 'success')
        
        targets = conn.execute('''
            SELECT ct.*, e.first_name, e.last_name, e.email, e.department
            FROM campaign_targets ct
            JOIN employees e ON ct.employee_id = e.id
            WHERE ct.campaign_id = ?
        ''', (campaign_id,)).fetchall()
        
        existing_employee_ids = [t['employee_id'] for t in targets]
        placeholder = ','.join('?' for _ in existing_employee_ids) if existing_employee_ids else '0'
        query = f'''
            SELECT * FROM employees 
            WHERE id NOT IN ({placeholder})
            ORDER BY last_name, first_name
        '''
        available_employees = conn.execute(query, existing_employee_ids).fetchall()
    
    return render_template('campaigns/targets.html', 
                          campaign=campaign,
                          targets=targets,
                          available_employees=available_employees)

@app.route('/campaigns/<int:campaign_id>/launch', methods=['POST'])
@login_required
def launch_campaign(campaign_id):
    with get_db_connection() as conn:
        campaign = conn.execute('''
            SELECT c.*, t.subject, t.body 
            FROM campaigns c
            JOIN templates t ON c.template_id = t.id
            WHERE c.id = ?
        ''', (campaign_id,)).fetchone()
        
        if not campaign:
            flash('Campaign not found', 'danger')
            return redirect(url_for('list_campaigns'))
        
        conn.execute('''
            UPDATE campaigns SET status = 'active'
            WHERE id = ?
        ''', (campaign_id,))
        
        targets = conn.execute('''
            SELECT ct.*, e.first_name, e.last_name, e.email
            FROM campaign_targets ct
            JOIN employees e ON ct.employee_id = e.id
            WHERE ct.campaign_id = ? AND ct.email_sent_at IS NULL
        ''', (campaign_id,)).fetchall()
        
        conn.commit()
    
    for target in targets:
        try:
            tracking_url = url_for(
                'track_click', 
                token=target['unique_token'],
                _external=True
            )
            
            body = campaign['body'].replace('{FIRST_NAME}', target['first_name'])
            body = body.replace('{LAST_NAME}', target['last_name'])
            body = body.replace('{EMAIL}', target['email'])
            body = body.replace('{TRACKING_LINK}', tracking_url)
            
            subject = campaign['subject'].replace('{FIRST_NAME}', target['first_name'])
            subject = subject.replace('{LAST_NAME}', target['last_name'])
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = app.config['SMTP_USERNAME']
            msg['To'] = target['email']
            
            part = MIMEText(body, 'html')
            msg.attach(part)
            
            tracking_pixel_url = url_for(
                'track_open', 
                token=target['unique_token'],
                _external=True
            )
            pixel_html = f'<img src="{tracking_pixel_url}" width="1" height="1" />'
            pixel_part = MIMEText(pixel_html, 'html')
            msg.attach(pixel_part)
            
            with smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as server:
                server.starttls()
                server.login(app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'])
                server.sendmail(app.config['SMTP_USERNAME'], target['email'], msg.as_string())
            
            with get_db_connection() as conn:
                conn.execute('''
                    UPDATE campaign_targets SET email_sent_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (target['id'],))
                conn.commit()
            
            logger.info(f"Sent phishing email to {target['email']} for campaign {campaign_id}")
            
        except Exception as e:
            logger.error(f"Failed to send email to {target['email']}: {str(e)}")
    
    flash(f'Campaign launched! Sending {len(targets)} emails.', 'success')
    return redirect(url_for('campaign_detail', campaign_id=campaign_id))

@app.route('/track/open/<token>')
def track_open(token):
    try:
        with get_db_connection() as conn:
            target = conn.execute('''
                SELECT * FROM campaign_targets WHERE unique_token = ?
            ''', (token,)).fetchone()
            
            if target:
                conn.execute('''
                    UPDATE campaign_targets 
                    SET email_opened_at = CURRENT_TIMESTAMP
                    WHERE unique_token = ? AND email_opened_at IS NULL
                ''', (token,))
                conn.commit()
        
        return app.response_class(
            b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;',
            mimetype='image/gif'
        )
    except Exception as e:
        logger.error(f"Error tracking email open: {str(e)}")
        return app.response_class(
            b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;',
            mimetype='image/gif'
        )

@app.route('/track/click/<token>')
def track_click(token):
    try:
        with get_db_connection() as conn:
            target = conn.execute('''
                SELECT ct.*, c.id as campaign_id, tm.id as training_module_id
                FROM campaign_targets ct
                JOIN campaigns c ON ct.campaign_id = c.id
                JOIN templates t ON c.template_id = t.id
                LEFT JOIN training_modules tm ON t.phishing_type = tm.phishing_type
                WHERE ct.unique_token = ?
                ORDER BY tm.created_at DESC
                LIMIT 1
            ''', (token,)).fetchone()
            
            if target:
                conn.execute('''
                    UPDATE campaign_targets 
                    SET link_clicked_at = CURRENT_TIMESTAMP,
                        user_agent = ?,
                        ip_address = ?
                    WHERE unique_token = ?
                ''', (
                    request.user_agent.string,
                    request.remote_addr,
                    token
                ))
                conn.commit()
                
                session['phish_token'] = token
                
                if target['training_module_id']:
                    return redirect(url_for('show_training', module_id=target['training_module_id']))
                else:
                    return redirect(url_for('default_training'))
    
    except Exception as e:
        logger.error(f"Error tracking click: {str(e)}")
    
    return redirect(url_for('default_training'))

@app.route('/training/<int:module_id>')
def show_training(module_id):
    with get_db_connection() as conn:
        module = conn.execute('SELECT * FROM training_modules WHERE id = ?', (module_id,)).fetchone()
        
        if not module:
            return redirect(url_for('default_training'))
        
        if 'phish_token' in session:
            token = session['phish_token']
            target = conn.execute('''
                SELECT ct.*, e.id as employee_id
                FROM campaign_targets ct
                JOIN employees e ON ct.employee_id = e.id
                WHERE ct.unique_token = ?
            ''', (token,)).fetchone()
            
            if target:
                conn.execute('''
                    INSERT INTO employee_training (employee_id, training_module_id)
                    VALUES (?, ?)
                ''', (target['employee_id'], module_id))
                conn.commit()
    
    return render_template('training/module.html', module=module)

@app.route('/training/default')
def default_training():
    return render_template('training/default.html')

@app.route('/report/phish', methods=['POST'])
def report_phish():
    token = request.form.get('token')
    if token:
        with get_db_connection() as conn:
            conn.execute('''
                UPDATE campaign_targets 
                SET reported_at = CURRENT_TIMESTAMP
                WHERE unique_token = ?
            ''', (token,))
            conn.commit()
        
        return jsonify({'status': 'success', 'message': 'Successfully reported phishing attempt'})
    
    return jsonify({'status': 'error', 'message': 'Missing token'})

@app.route('/campaigns/<int:campaign_id>')
@login_required
def campaign_detail(campaign_id):
    with get_db_connection() as conn:
        campaign = conn.execute('''
            SELECT c.*, t.name as template_name, t.subject, t.phishing_type,
                   u.username as creator
            FROM campaigns c
            JOIN templates t ON c.template_id = t.id
            JOIN users u ON c.created_by = u.id
            WHERE c.id = ?
        ''', (campaign_id,)).fetchone()
        
        if not campaign:
            flash('Campaign not found', 'danger')
            return redirect(url_for('list_campaigns'))
        
        targets = conn.execute('''
            SELECT ct.*, e.first_name, e.last_name, e.email, e.department
            FROM campaign_targets ct
            JOIN employees e ON ct.employee_id = e.id
            WHERE ct.campaign_id = ?
        ''', (campaign_id,)).fetchall()
        
        total_targets = len(targets)
        emails_sent = sum(1 for t in targets if t['email_sent_at'] is not None)
        emails_opened = sum(1 for t in targets if t['email_opened_at'] is not None)
        links_clicked = sum(1 for t in targets if t['link_clicked_at'] is not None)
        reported = sum(1 for t in targets if t['reported_at'] is not None)
        
        metrics = {
            'total_targets': total_targets,
            'emails_sent': emails_sent,
            'emails_opened': emails_opened,
            'links_clicked': links_clicked,
            'reported': reported,
            'open_rate': (emails_opened / emails_sent * 100) if emails_sent > 0 else 0,
            'click_rate': (links_clicked / emails_opened * 100) if emails_opened > 0 else 0,
            'report_rate': (reported / emails_opened * 100) if emails_opened > 0 else 0,
            'success_rate': (reported / links_clicked * 100) if links_clicked > 0 else 0
        }
        
        departments = {}
        for target in targets:
            dept = target['department']
            if dept not in departments:
                departments[dept] = {
                    'total': 0,
                    'opened': 0,
                    'clicked': 0,
                    'reported': 0
                }
            
            departments[dept]['total'] += 1
            if target['email_opened_at']:
                departments[dept]['opened'] += 1
            if target['link_clicked_at']:
                departments[dept]['clicked'] += 1
            if target['reported_at']:
                departments[dept]['reported'] += 1
    
    return render_template('campaigns/detail.html',
                          campaign=campaign,
                          targets=targets,
                          metrics=metrics,
                          departments=departments)

@app.route('/reports')
@login_required
def reports():
    with get_db_connection() as conn:
        overall = conn.execute('''
            SELECT 
                COUNT(DISTINCT c.id) as total_campaigns,
                COUNT(DISTINCT ct.employee_id) as total_employees,
                SUM(CASE WHEN ct.email_sent_at IS NOT NULL THEN 1 ELSE 0 END) as total_emails_sent,
                SUM(CASE WHEN ct.email_opened_at IS NOT NULL THEN 1 ELSE 0 END) as total_emails_opened,
                SUM(CASE WHEN ct.link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as total_links_clicked,
                SUM(CASE WHEN ct.reported_at IS NOT NULL THEN 1 ELSE 0 END) as total_reported
            FROM campaigns c
            LEFT JOIN campaign_targets ct ON c.id = ct.campaign_id
        ''').fetchone()
        
        departments = conn.execute('''
            SELECT 
                e.department,
                COUNT(DISTINCT e.id) as total_employees,
                COUNT(DISTINCT ct.id) as total_targeted,
                SUM(CASE WHEN ct.link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as clicked,
                SUM(CASE WHEN ct.reported_at IS NOT NULL THEN 1 ELSE 0 END) as reported
            FROM employees e
            LEFT JOIN campaign_targets ct ON e.id = ct.employee_id
            GROUP BY e.department
            ORDER BY clicked DESC
        ''').fetchall()
        
        campaigns = conn.execute('''
            SELECT 
                c.id, c.name, c.status,
                t.phishing_type, t.difficulty_level,
                COUNT(DISTINCT ct.employee_id) as total_targets,
                SUM(CASE WHEN ct.email_sent_at IS NOT NULL THEN 1 ELSE 0 END) as emails_sent,
                SUM(CASE WHEN ct.email_opened_at IS NOT NULL THEN 1 ELSE 0 END) as emails_opened,
                SUM(CASE WHEN ct.link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as links_clicked,
                SUM(CASE WHEN ct.reported_at IS NOT NULL THEN 1 ELSE 0 END) as reported
            FROM campaigns c
            JOIN templates t ON c.template_id = t.id
            LEFT JOIN campaign_targets ct ON c.id = ct.campaign_id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        ''').fetchall()
        
        trends = conn.execute('''
            SELECT 
                strftime('%Y-%m', ct.email_sent_at) as month,
                COUNT(DISTINCT ct.id) as total_targets,
                SUM(CASE WHEN ct.email_opened_at IS NOT NULL THEN 1 ELSE 0 END) as emails_opened,
                SUM(CASE WHEN ct.link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as links_clicked,
                SUM(CASE WHEN ct.reported_at IS NOT NULL THEN 1 ELSE 0 END) as reported
            FROM campaign_targets ct
            WHERE ct.email_sent_at IS NOT NULL
            GROUP BY month
            ORDER BY month
        ''').fetchall()
        
        vulnerable_employees = conn.execute('''
            SELECT 
                e.id, e.first_name, e.last_name, e.email, e.department,
                COUNT(DISTINCT ct.campaign_id) as campaigns_targeted,
                SUM(CASE WHEN ct.link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as times_clicked,
                SUM(CASE WHEN ct.reported_at IS NOT NULL THEN 1 ELSE 0 END) as times_reported
            FROM employees e
            JOIN campaign_targets ct ON e.id = ct.employee_id
            GROUP BY e.id
            ORDER BY times_clicked DESC, campaigns_targeted DESC
            LIMIT 20
        ''').fetchall()
    
    return render_template('reports/index.html',
                          overall=overall,
                          departments=departments,
                          campaigns=campaigns,
                          trends=trends,
                          vulnerable_employees=vulnerable_employees)

@app.route('/training_modules', methods=['GET'])
@login_required
def list_training_modules():
    with get_db_connection() as conn:
        modules = conn.execute('''
            SELECT tm.*, u.username as creator
            FROM training_modules tm
            JOIN users u ON tm.created_by = u.id
            ORDER BY tm.created_at DESC
        ''').fetchall()
    return render_template('training/list.html', modules=modules)

@app.route('/training_modules/add', methods=['GET', 'POST'])
@login_required
def add_training_module():
    form = TrainingModuleForm()
    if form.validate_on_submit():
        with get_db_connection() as conn:
            conn.execute('''
                INSERT INTO training_modules (title, description, content, 
                                             phishing_type, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                form.title.data,
                form.description.data,
                form.content.data,
                form.phishing_type.data,
                current_user.id
            ))
            conn.commit()
        flash('Training module created successfully', 'success')
        return redirect(url_for('list_training_modules'))
    
    return render_template('training/add.html', form=form)

@app.route('/api/campaign/<int:campaign_id>/metrics')
@login_required
def api_campaign_metrics(campaign_id):
    with get_db_connection() as conn:
        daily_metrics = conn.execute('''
            SELECT 
                strftime('%Y-%m-%d', ct.email_sent_at) as date,
                COUNT(DISTINCT ct.id) as total_sent,
                SUM(CASE WHEN ct.email_opened_at IS NOT NULL THEN 1 ELSE 0 END) as opened,
                SUM(CASE WHEN ct.link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as clicked,
                SUM(CASE WHEN ct.reported_at IS NOT NULL THEN 1 ELSE 0 END) as reported
            FROM campaign_targets ct
            WHERE ct.campaign_id = ? AND ct.email_sent_at IS NOT NULL
            GROUP BY date
            ORDER BY date
        ''', (campaign_id,)).fetchall()
        
        result = [
            {
                'date': row['date'],
                'total_sent': row['total_sent'],
                'opened': row['opened'],
                'clicked': row['clicked'],
                'reported': row['reported']
            }
            for row in daily_metrics
        ]
    
    return jsonify(result)

@app.route('/api/employees/import', methods=['POST'])
@login_required
def api_import_employees():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'})
    
    if file and file.filename.endswith('.csv'):
        try:
            content = file.read().decode('utf-8')
            csv_data = content.splitlines()
            
            import csv
            reader = csv.DictReader(csv_data)
            
            added = 0
            duplicates = 0
            
            with get_db_connection() as conn:
                for row in reader:
                    try:
                        conn.execute('''
                            INSERT INTO employees (first_name, last_name, email, department, job_title)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            row.get('first_name', ''),
                            row.get('last_name', ''),
                            row.get('email', ''),
                            row.get('department', ''),
                            row.get('job_title', '')
                        ))
                        added += 1
                    except sqlite3.IntegrityError:
                        duplicates += 1
                
                conn.commit()
            
            return jsonify({
                'status': 'success', 
                'message': f'Imported {added} employees ({duplicates} duplicates skipped)'
            })
            
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})
    
    return jsonify({'status': 'error', 'message': 'File must be a CSV'})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        app.config['SMTP_SERVER'] = request.form.get('smtp_server')
        app.config['SMTP_PORT'] = int(request.form.get('smtp_port', 587))
        app.config['SMTP_USERNAME'] = request.form.get('smtp_username')
        
        new_password = request.form.get('smtp_password')
        if new_password:
            app.config['SMTP_PASSWORD'] = new_password
        
        flash('Settings updated successfully', 'success')
    
    return render_template('settings.html', 
                          smtp_server=app.config['SMTP_SERVER'],
                          smtp_port=app.config['SMTP_PORT'],
                          smtp_username=app.config['SMTP_USERNAME'])

@app.route('/install', methods=['GET', 'POST'])
def install():
    with get_db_connection() as conn:
        admin_exists = conn.execute('SELECT COUNT(*) FROM users WHERE is_admin = 1').fetchone()[0] > 0
    
    if admin_exists:
        flash('Installation already completed', 'info')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if not username or not password or not email:
            flash('All fields are required', 'danger')
        else:
            init_db()
            
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO users (username, password_hash, email, is_admin)
                    VALUES (?, ?, ?, 1)
                ''', (
                    username,
                    generate_password_hash(password),
                    email
                ))
                conn.commit()
            
            flash('Installation completed successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('install.html')

def create_sample_data():
    """Create sample data for testing"""
    try:
        with get_db_connection() as conn:
            if conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0:
                return
            
            conn.execute('''
                INSERT INTO users (username, password_hash, email, is_admin)
                VALUES (?, ?, ?, 1)
            ''', (
                'admin',
                generate_password_hash('admin123'),
                'admin@example.com'
            ))
            
            departments = ['IT', 'HR', 'Finance', 'Marketing', 'Sales', 'Operations']
            for i in range(50):
                dept = random.choice(departments)
                conn.execute('''
                    INSERT INTO employees (first_name, last_name, email, department, job_title)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    f'FirstName{i}',
                    f'LastName{i}',
                    f'employee{i}@example.com',
                    dept,
                    f'{dept} Specialist'
                ))
            
            phishing_types = ['credential_harvest', 'malware', 'data_theft', 'spear_phishing', 'financial']
            difficulty_levels = ['easy', 'medium', 'hard', 'expert']
            
            for i in range(5):
                phish_type = phishing_types[i % len(phishing_types)]
                difficulty = difficulty_levels[i % len(difficulty_levels)]
                
                conn.execute('''
                    INSERT INTO templates (name, description, subject, body, 
                                          phishing_type, difficulty_level, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                ''', (
                    f'Template {i+1}',
                    f'Sample phishing template {i+1}',
                    'Important: Action Required - {FIRST_NAME}',
                    '<p>Dear {FIRST_NAME},</p><p>Please review the attached document and click <a href="{TRACKING_LINK}">here</a> to confirm receipt.</p><p>Best regards,<br>IT Department</p>',
                    phish_type,
                    difficulty
                ))
            
            for i, phish_type in enumerate(phishing_types):
                conn.execute('''
                    INSERT INTO training_modules (title, description, content, 
                                                 phishing_type, created_by)
                    VALUES (?, ?, ?, ?, 1)
                ''', (
                    f'How to Identify {phish_type.replace("_", " ").title()} Attempts',
                    f'Training on recognizing and responding to {phish_type.replace("_", " ")} phishing attempts',
                    f'<h1>Recognizing {phish_type.replace("_", " ").title()} Attempts</h1><p>This module teaches you how to identify and respond to these attacks.</p>',
                    phish_type
                ))
            
            conn.commit()
            logger.info("Created sample data successfully")
    
    except Exception as e:
        logger.error(f"Error creating sample data: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='PhishGuard - Phishing Simulation Tool for Employee Education')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Host to bind (default: 127.0.0.1; use 0.0.0.0 to expose on all interfaces)')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    parser.add_argument('--sample-data', action='store_true', help='Create sample data for testing')
    
    args = parser.parse_args()
    
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        init_db()
        logger.info("Database initialized")
        
        if args.sample_data:
            create_sample_data()
    
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
    
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()