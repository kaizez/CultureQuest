import os
import uuid
import hashlib
import requests
import time
import re
import json as json_module
from flask import Flask, render_template, jsonify, request, url_for, redirect, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from models import db, Message, ChatRoom, SecurityViolation, MutedUser
from datetime import datetime
from markupsafe import escape
from dotenv import load_dotenv
from urllib.parse import urlparse

def load_env():
    """Load environment variables from .env file."""
    basedir = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(basedir, '.env')
    if os.path.exists(dotenv_path):
        print(f"Loading .env file from {dotenv_path}")
        load_dotenv(dotenv_path)
        
        # Debug: Check if API key is loaded
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if api_key:
            print(f"✅ VirusTotal API key loaded (length: {len(api_key)})")
        else:
            print("❌ VirusTotal API key not found in environment")
    else:
        print("Warning: .env file not found.")
        print(f"Looking for .env at: {dotenv_path}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Files in directory: {os.listdir('.')}")

# Load environment variables
load_env()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-long-and-random-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}

# VirusTotal configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_FILE_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_FILE_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_URL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
VIRUSTOTAL_URL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app)

# Create tables if not exist and seed default chat rooms
with app.app_context():
    db.create_all()
    
    # Create default chat rooms if they don't exist
    if ChatRoom.query.count() == 0:
        default_rooms = [
            ChatRoom(name="General Chat", description="Welcome to the general discussion room"),
            ChatRoom(name="Tech Talk", description="Discuss technology, programming, and innovation"),
            ChatRoom(name="Random", description="Talk about anything and everything"),
            ChatRoom(name="File Sharing", description="Share and discuss files securely")
        ]
        
        for room in default_rooms:
            db.session.add(room)
        db.session.commit()
        print("✅ Default chat rooms created")

# Keep all your existing helper functions (they don't need to change)
def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def extract_urls(text):
    """Extract URLs from text using regex"""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    urls = url_pattern.findall(text)
    return urls

def is_valid_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def scan_url_with_virustotal(url):
    """
    Scan URL with VirusTotal API
    Returns: (is_safe, scan_result, error_message)
    """
    if not VIRUSTOTAL_API_KEY:
        print("Warning: VirusTotal API key not configured")
        return True, None, "VirusTotal API key not configured"
    
    if not is_valid_url(url):
        return False, None, "Invalid URL format"
    
    try:
        # First, try to get existing report for the URL
        report_params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'resource': url
        }
        
        report_response = requests.get(VIRUSTOTAL_URL_REPORT_URL, params=report_params, timeout=30)
        
        if report_response.status_code == 200:
            report_data = report_response.json()
            
            if report_data['response_code'] == 1:  # Report exists
                return analyze_url_scan_result(report_data, url)
        
        # If no existing report, submit URL for scanning
        scan_params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'url': url
        }
        
        scan_response = requests.post(VIRUSTOTAL_URL_SCAN_URL, data=scan_params, timeout=30)
        
        if scan_response.status_code == 200:
            scan_data = scan_response.json()
            
            if scan_data['response_code'] == 1:
                # Wait for scan to complete and get results
                return wait_for_url_scan_result(url)
            else:
                return False, None, f"VirusTotal URL scan failed: {scan_data.get('verbose_msg', 'Unknown error')}"
        else:
            return False, None, f"VirusTotal API request failed with status {scan_response.status_code}"
                
    except requests.exceptions.Timeout:
        return False, None, "VirusTotal URL scan timed out"
    except requests.exceptions.RequestException as e:
        return False, None, f"VirusTotal API error: {str(e)}"
    except Exception as e:
        return False, None, f"Unexpected error during URL scan: {str(e)}"

def wait_for_url_scan_result(url, max_wait_time=60):
    """
    Wait for VirusTotal URL scan to complete and return results
    """
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        try:
            report_params = {
                'apikey': VIRUSTOTAL_API_KEY,
                'resource': url
            }
            
            report_response = requests.get(VIRUSTOTAL_URL_REPORT_URL, params=report_params, timeout=30)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                
                if report_data['response_code'] == 1:  # Scan complete
                    return analyze_url_scan_result(report_data, url)
                elif report_data['response_code'] == -2:  # Still scanning
                    time.sleep(5)  # Wait 5 seconds before checking again
                    continue
                else:
                    return False, report_data, f"URL scan failed: {report_data.get('verbose_msg', 'Unknown error')}"
            else:
                return False, None, f"Failed to get URL scan report: HTTP {report_response.status_code}"
                
        except Exception as e:
            return False, None, f"Error checking URL scan results: {str(e)}"
    
    return False, None, "URL scan timed out - please try again later"

def analyze_url_scan_result(report_data, url):
    """
    Analyze VirusTotal URL scan results
    Returns: (is_safe, scan_result, message)
    """
    total_scans = report_data.get('total', 0)
    positive_detections = report_data.get('positives', 0)
    
    # Consider URL safe if no engines detected it as malicious
    is_safe = positive_detections == 0
    
    scan_summary = {
        'url': url,
        'total_scans': total_scans,
        'positive_detections': positive_detections,
        'scan_date': report_data.get('scan_date'),
        'permalink': report_data.get('permalink')
    }
    
    if is_safe:
        message = f"URL is clean - scanned by {total_scans} engines with 0 detections"
    else:
        message = f"URL may be malicious - {positive_detections}/{total_scans} engines detected threats"
    
    return is_safe, scan_summary, message

def scan_file_with_virustotal(file_path):
    """
    Scan file with VirusTotal API
    Returns: (is_safe, scan_result, error_message)
    """
    if not VIRUSTOTAL_API_KEY:
        print("Warning: VirusTotal API key not configured")
        return True, None, "VirusTotal API key not configured"
    
    try:
        # First, try to get existing report using file hash
        file_hash = get_file_hash(file_path)
        
        # Check if we already have a report for this file
        report_params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'resource': file_hash
        }
        
        report_response = requests.get(VIRUSTOTAL_FILE_REPORT_URL, params=report_params)
        
        if report_response.status_code == 200:
            report_data = report_response.json()
            
            if report_data['response_code'] == 1:  # Report exists
                return analyze_file_scan_result(report_data)
        
        # If no existing report, submit file for scanning
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            params = {'apikey': VIRUSTOTAL_API_KEY}
            
            scan_response = requests.post(VIRUSTOTAL_FILE_SCAN_URL, files=files, data=params, timeout=60)
            
            if scan_response.status_code == 200:
                scan_data = scan_response.json()
                
                if scan_data['response_code'] == 1:
                    # Wait for scan to complete and get results
                    return wait_for_file_scan_result(scan_data['scan_id'])
                else:
                    return False, None, f"VirusTotal scan failed: {scan_data.get('verbose_msg', 'Unknown error')}"
            else:
                return False, None, f"VirusTotal API request failed with status {scan_response.status_code}"
                
    except requests.exceptions.Timeout:
        return False, None, "VirusTotal scan timed out"
    except requests.exceptions.RequestException as e:
        return False, None, f"VirusTotal API error: {str(e)}"
    except Exception as e:
        return False, None, f"Unexpected error during virus scan: {str(e)}"

def wait_for_file_scan_result(scan_id, max_wait_time=120):
    """
    Wait for VirusTotal file scan to complete and return results
    """
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        try:
            report_params = {
                'apikey': VIRUSTOTAL_API_KEY,
                'resource': scan_id
            }
            
            report_response = requests.get(VIRUSTOTAL_FILE_REPORT_URL, params=report_params)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                
                if report_data['response_code'] == 1:  # Scan complete
                    return analyze_file_scan_result(report_data)
                elif report_data['response_code'] == -2:  # Still scanning
                    time.sleep(10)  # Wait 10 seconds before checking again
                    continue
                else:
                    return False, report_data, f"Scan failed: {report_data.get('verbose_msg', 'Unknown error')}"
            else:
                return False, None, f"Failed to get scan report: HTTP {report_response.status_code}"
                
        except Exception as e:
            return False, None, f"Error checking scan results: {str(e)}"
    
    return False, None, "Virus scan timed out - please try again later"

def analyze_file_scan_result(report_data):
    """
    Analyze VirusTotal file scan results
    Returns: (is_safe, scan_result, message)
    """
    total_scans = report_data.get('total', 0)
    positive_detections = report_data.get('positives', 0)
    
    # Consider file safe if no engines detected it as malicious
    is_safe = positive_detections == 0
    
    scan_summary = {
        'total_scans': total_scans,
        'positive_detections': positive_detections,
        'scan_date': report_data.get('scan_date'),
        'permalink': report_data.get('permalink')
    }
    
    if is_safe:
        message = f"File is clean - scanned by {total_scans} engines with 0 detections"
    else:
        message = f"File may be malicious - {positive_detections}/{total_scans} engines detected threats"
    
    return is_safe, scan_summary, message

# Routes
@app.route('/')
def landing():
    """Landing page route"""
    return render_template('landing.html')

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard route"""
    return render_template('admin.html')

@app.route('/chat')
def chat_rooms():
    """Chat rooms menu page"""
    username = request.args.get('username', 'Guest')
    rooms = ChatRoom.query.filter_by(is_active=True).order_by(ChatRoom.created_at.desc()).all()
    return render_template('chat_rooms.html', username=escape(username), rooms=rooms)

@app.route('/chat/<int:room_id>')
def chat_session(room_id):
    """Individual chat session route"""
    room = ChatRoom.query.get_or_404(room_id)
    if not room.is_active:
        flash('This chat room is not available', 'error')
        return redirect(url_for('chat_rooms'))
    
    # Get username from query parameters or default to 'Guest'
    username = request.args.get('username', 'Guest')
    return render_template('session.html', 
                         username=escape(username), 
                         room=room,
                         room_id=room_id)

@app.route('/api/rooms', methods=['GET'])
def get_rooms():
    """API endpoint to get all active chat rooms"""
    rooms = ChatRoom.query.filter_by(is_active=True).order_by(ChatRoom.created_at.desc()).all()
    return jsonify([room.to_dict() for room in rooms])

@app.route('/api/rooms', methods=['POST'])
def create_room():
    """API endpoint to create a new chat room"""
    data = request.get_json()
    
    if not data or 'name' not in data:
        return jsonify({'error': 'Room name is required'}), 400
    
    name = data['name'].strip()
    description = data.get('description', '').strip()
    
    if len(name) > 100:
        return jsonify({'error': 'Room name too long'}), 400
    
    if len(description) > 500:
        return jsonify({'error': 'Description too long'}), 400
    
    # Check if room with same name already exists
    existing_room = ChatRoom.query.filter_by(name=name, is_active=True).first()
    if existing_room:
        return jsonify({'error': 'Room with this name already exists'}), 400
    
    new_room = ChatRoom(name=name, description=description)
    db.session.add(new_room)
    db.session.commit()
    
    return jsonify(new_room.to_dict()), 201

@app.route('/history/<int:room_id>')
def history(room_id):
    """Get chat history for a specific room"""
    room = ChatRoom.query.get_or_404(room_id)
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).all()
    return jsonify([msg.to_dict() for msg in messages])

@app.route('/api/admin/violations', methods=['GET'])
def get_violations():
    """API endpoint to get security violations with optional pagination"""
    page = request.args.get('page', type=int)
    per_page = request.args.get('per_page', type=int)
    
    violations_query = SecurityViolation.query.order_by(SecurityViolation.timestamp.desc())
    
    if page is not None and per_page is not None:
        # Paginated response
        per_page = min(per_page, 100)  # Limit per_page to prevent abuse
        violations = violations_query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        return jsonify({
            'violations': [violation.to_dict() for violation in violations.items],
            'page': page,
            'pages': violations.pages,
            'per_page': per_page,
            'total': violations.total,
            'has_next': violations.has_next,
            'has_prev': violations.has_prev
        })
    else:
        # Return all violations (for client-side pagination)
        violations = violations_query.all()
        return jsonify([violation.to_dict() for violation in violations])

@app.route('/api/admin/violations/<int:violation_id>', methods=['GET'])
def get_violation_details(violation_id):
    """API endpoint to get specific violation details"""
    violation = SecurityViolation.query.get_or_404(violation_id)
    return jsonify(violation.to_dict())

@app.route('/api/admin/violations/<int:violation_id>', methods=['DELETE'])
def delete_violation(violation_id):
    """API endpoint to delete a violation record"""
    violation = SecurityViolation.query.get_or_404(violation_id)
    db.session.delete(violation)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Violation deleted successfully'})

@app.route('/api/admin/violations/<int:violation_id>/status', methods=['PATCH'])
def update_violation_status(violation_id):
    """API endpoint to update violation status"""
    violation = SecurityViolation.query.get_or_404(violation_id)
    data = request.get_json()
    
    if 'status' in data and data['status'] in ['pending', 'handled', 'ignored']:
        violation.status = data['status']
        db.session.commit()
        return jsonify({'success': True, 'message': 'Status updated successfully'})
    
    return jsonify({'error': 'Invalid status value'}), 400

@app.route('/api/admin/mute-user', methods=['POST'])
def mute_user():
    """API endpoint to mute a user in a specific room"""
    data = request.get_json()
    
    if not data or 'user_name' not in data or 'room_id' not in data:
        return jsonify({'error': 'user_name and room_id are required'}), 400
    
    user_name = data['user_name'].strip()
    room_id = data['room_id']
    duration_hours = data.get('duration_hours', None)  # None for permanent mute
    reason = data.get('reason', 'Security violation')
    
    # Validate room exists
    room = ChatRoom.query.get(room_id)
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    try:
        # Check if user is already muted in this room
        existing_mute = MutedUser.query.filter_by(
            user_name=user_name, 
            room_id=room_id, 
            is_active=True
        ).first()
        
        if existing_mute and existing_mute.is_muted():
            return jsonify({'error': 'User is already muted in this room'}), 400
        
        # Clean up any old inactive mutes for this user/room combination
        old_mutes = MutedUser.query.filter_by(
            user_name=user_name,
            room_id=room_id,
            is_active=False
        ).all()
        
        for old_mute in old_mutes:
            db.session.delete(old_mute)
        
        if old_mutes:
            db.session.commit()
        
        # Calculate mute expiration
        muted_until = None
        if duration_hours:
            from datetime import timedelta
            muted_until = datetime.utcnow() + timedelta(hours=duration_hours)
        
        # Create mute record
        mute = MutedUser(
            user_name=user_name,
            room_id=room_id,
            muted_until=muted_until,
            reason=reason,
            muted_by_admin='Admin'  # Will be updated when auth is implemented
        )
        
        db.session.add(mute)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'User {user_name} muted in room {room.name}',
            'mute': mute.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error muting user: {e}")
        return jsonify({'error': 'Failed to mute user'}), 500

@app.route('/api/admin/unmute-user', methods=['POST'])
def unmute_user():
    """API endpoint to unmute a user in a specific room"""
    data = request.get_json()
    
    if not data or 'user_name' not in data or 'room_id' not in data:
        return jsonify({'error': 'user_name and room_id are required'}), 400
    
    user_name = data['user_name'].strip()
    room_id = data['room_id']
    
    try:
        # Find active mute
        mute = MutedUser.query.filter_by(
            user_name=user_name,
            room_id=room_id,
            is_active=True
        ).first()
        
        if not mute:
            return jsonify({'error': 'User is not muted in this room'}), 404
        
        # Delete the mute record instead of deactivating
        db.session.delete(mute)
        db.session.commit()
        
        room = ChatRoom.query.get(room_id)
        return jsonify({
            'success': True, 
            'message': f'User {user_name} unmuted in room {room.name if room else room_id}'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error unmuting user: {e}")
        return jsonify({'error': 'Failed to unmute user'}), 500

@app.route('/api/admin/muted-users', methods=['GET'])
def get_muted_users():
    """API endpoint to get all muted users"""
    muted_users = MutedUser.query.filter_by(is_active=True).order_by(MutedUser.muted_at.desc()).all()
    return jsonify([mute.to_dict() for mute in muted_users])

def is_user_muted(user_name, room_id):
    """Helper function to check if a user is muted in a specific room"""
    mute = MutedUser.query.filter_by(
        user_name=user_name,
        room_id=room_id,
        is_active=True
    ).first()
    
    if not mute:
        return False
    
    return mute.is_muted()

@app.route('/api/mute-status/<username>/<int:room_id>', methods=['GET'])
def check_mute_status(username, room_id):
    """API endpoint to check if a user is muted in a specific room"""
    mute = MutedUser.query.filter_by(
        user_name=username,
        room_id=room_id,
        is_active=True
    ).first()
    
    if not mute or not mute.is_muted():
        return jsonify({
            'is_muted': False,
            'mute_info': None
        })
    
    # Calculate remaining time for temporary mutes
    remaining_time = None
    if mute.muted_until:
        remaining_seconds = (mute.muted_until - datetime.utcnow()).total_seconds()
        if remaining_seconds > 0:
            hours = int(remaining_seconds // 3600)
            minutes = int((remaining_seconds % 3600) // 60)
            if hours > 0:
                remaining_time = f"{hours}h {minutes}m"
            else:
                remaining_time = f"{minutes}m"
        else:
            # Mute has expired, deactivate it
            mute.is_active = False
            db.session.commit()
            return jsonify({
                'is_muted': False,
                'mute_info': None
            })
    
    return jsonify({
        'is_muted': True,
        'mute_info': {
            'reason': mute.reason,
            'muted_at': mute.muted_at.strftime('%Y-%m-%d %H:%M:%S'),
            'muted_until': mute.muted_until.strftime('%Y-%m-%d %H:%M:%S') if mute.muted_until else None,
            'is_permanent': mute.muted_until is None,
            'remaining_time': remaining_time,
            'muted_by': mute.muted_by_admin
        }
    })

@app.route('/upload/<int:room_id>', methods=['POST'])
def upload_file(room_id):
    """Handle file uploads with virus scanning for a specific room"""
    room = ChatRoom.query.get_or_404(room_id)
    if not room.is_active:
        return jsonify({'error': 'Chat room is not available'}), 400
    
    try:
        user_name = request.form.get('user_name', 'Guest')
        message = request.form.get('message', '')

        # Basic input validation for user_name and message
        if len(user_name) > 50 or len(message) > 500:
            return jsonify({'error': 'Input too long'}), 400

        # Sanitize inputs
        user_name = escape(user_name)
        message = escape(message)
        
        # Check if user is muted in this room
        if is_user_muted(str(user_name), room_id):
            return jsonify({'error': 'You are muted in this room and cannot send messages or upload files.'}), 403

        # Check if file was uploaded
        if 'file' not in request.files:
            # If there's a message, treat it as a regular text message
            if message:
                new_msg = Message(user_name=user_name, message=message, 
                                timestamp=datetime.utcnow(), room_id=room_id)
                db.session.add(new_msg)
                db.session.commit()
                socketio.emit('my response', new_msg.to_dict(), room=f'room_{room_id}')
                return jsonify({'success': True, 'message': 'Message sent successfully'})
            return jsonify({'error': 'No file part in the request'}), 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an empty file without a filename.
        if file.filename == '':
            # If there's a message, treat it as a regular text message
            if message:
                new_msg = Message(user_name=user_name, message=message, 
                                timestamp=datetime.utcnow(), room_id=room_id)
                db.session.add(new_msg)
                db.session.commit()
                socketio.emit('my response', new_msg.to_dict(), room=f'room_{room_id}')
                return jsonify({'success': True, 'message': 'Message sent successfully'})
            return jsonify({'error': 'No selected file'}), 400

        if file and allowed_file(file.filename):
            # Sanitize filename
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{unique_filename}")

            # Save file temporarily for scanning
            file.save(temp_file_path)

            try:
                # Scan file with VirusTotal
                print(f"Scanning file {filename} for viruses...")
                is_safe, scan_result, scan_message = scan_file_with_virustotal(temp_file_path)
                
                print(f"Scan result for {filename}: {scan_message}")
                
                if not is_safe:
                    # Log the security violation
                    violation = SecurityViolation(
                        user_name=str(user_name),
                        violation_type='file',
                        content=filename,
                        message_content=str(message),
                        detection_details=json_module.dumps(scan_result) if scan_result else None,
                        room_id=room_id
                    )
                    db.session.add(violation)
                    db.session.commit()
                    
                    # Remove the temporary file
                    os.remove(temp_file_path)
                    return jsonify({
                        'error': f'File upload blocked: {scan_message}',
                        'scan_details': scan_result
                    }), 400

                # File is safe, move it to permanent location
                final_file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                os.rename(temp_file_path, final_file_path)

                # Create file URL
                file_url = url_for('static', filename=f'uploads/{unique_filename}')

                # Save to database with scan information based on whether scan actually occurred
                if not VIRUSTOTAL_API_KEY:
                    scan_info = "⚠️ Uploaded without virus scan (API key not configured)"
                elif scan_result is not None:
                    scan_info = f"✅ Virus scan passed: \n {scan_message}"
                else:
                    scan_info = f"⚠️ Virus scan skipped: \n {scan_message}"
                
                full_message = f"{message}\n\n{scan_info}" if message else scan_info

                new_msg = Message(
                    user_name=user_name,
                    message=full_message,
                    timestamp=datetime.utcnow(),
                    file_name=filename,
                    file_url=file_url,
                    room_id=room_id
                )
                db.session.add(new_msg)
                db.session.commit()

                # Emit message to room clients
                socketio.emit('my response', new_msg.to_dict(), room=f'room_{room_id}')

                return jsonify({
                    'success': True, 
                    'message': 'File uploaded successfully and passed virus scan',
                    'scan_details': scan_result
                })
                
            except Exception as scan_error:
                # Remove temporary file on scan error
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                print(f"Virus scan error: {scan_error}")
                return jsonify({'error': f'Virus scan failed: {str(scan_error)}'}), 500

        else:
            return jsonify({'error': 'File type not allowed'}), 400

    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'error': 'An unexpected error occurred during upload'}), 500

# SocketIO events
@socketio.on('join')
def on_join(data):
    """Handle user joining a chat room"""
    room_id = data.get('room')
    username = data.get('username', 'Guest')
    
    if room_id:
        room_name = f'room_{room_id}'
        join_room(room_name)
        print(f'{username} joined room {room_id}')

@socketio.on('leave')
def on_leave(data):
    """Handle user leaving a chat room"""
    room_id = data.get('room')
    username = data.get('username', 'Guest')
    
    if room_id:
        room_name = f'room_{room_id}'
        leave_room(room_name)
        print(f'{username} left room {room_id}')

@socketio.on('my event')
def handle_my_custom_event(json):
    room_id = json.get('room_id')
    if not room_id:
        return
    
    # Verify room exists
    room = ChatRoom.query.get(room_id)
    if not room or not room.is_active:
        return
    
    print('received message:', json)

    user_name = json.get('user_name', 'Guest')
    message = json.get('message', '')

    # Basic input validation
    if len(user_name) > 50 or len(message) > 500:
        return

    # Sanitize inputs
    user_name = escape(user_name)
    message = escape(message)
    
    # Check if user is muted in this room
    if is_user_muted(str(user_name), room_id):
        emit('mute_notification', {
            'message': 'You are muted in this room and cannot send messages.',
            'room_id': room_id
        })
        return

    # Check for URLs in the message
    urls = extract_urls(message)
    url_scan_results = []
    violations_to_add = []
    
    if urls and VIRUSTOTAL_API_KEY:
        for url in urls:
            print(f"Scanning URL: {url}")
            is_safe, scan_result, scan_message = scan_url_with_virustotal(url)
            url_scan_results.append({
                'url': url,
                'is_safe': is_safe,
                'scan_result': scan_result,
                'scan_message': scan_message
            })
            
            # Collect security violations for unsafe URLs
            if not is_safe:
                violation = SecurityViolation(
                    user_name=str(user_name),
                    violation_type='url',
                    content=url,
                    message_content=str(message),
                    detection_details=json_module.dumps(scan_result) if scan_result else None,
                    room_id=room_id
                )
                violations_to_add.append(violation)

    # Prepare the final message with URL scan results
    final_message = message
    if url_scan_results:
        final_message += "\n\n🔍 URL Scan Results:"
        for result in url_scan_results:
            if result['is_safe']:
                final_message += f"\n✅ {result['url']}: {result['scan_message']}"
            else:
                final_message += f"\n⚠️ {result['url']}: {result['scan_message']}"

    # Save message to database
    new_msg = Message(
        user_name=user_name,
        message=final_message,
        timestamp=datetime.utcnow(),
        room_id=room_id
    )
    db.session.add(new_msg)
    
    # Add any security violations to database
    for violation in violations_to_add:
        db.session.add(violation)
    
    # Commit all changes together
    db.session.commit()

    # Emit message to room including timestamp from database
    emit('my response', new_msg.to_dict(), room=f'room_{room_id}')

# Run the server
if __name__ == '__main__':
    socketio.run(app, debug=True)