import os
import uuid
import hashlib
import requests
import time
import re
import json as json_module
from flask import Blueprint, render_template, jsonify, request, url_for, redirect, flash, send_file, Response
from flask_socketio import emit, join_room, leave_room
from werkzeug.utils import secure_filename
from models import db, Message, ChatRoom, SecurityViolation, MutedUser, UploadedFile
from datetime import datetime
from markupsafe import escape
from urllib.parse import urlparse
from auth_utils import require_login, require_admin, get_current_user, get_user_id, get_username
from security import (
    SecurityMiddleware, InputValidator, CSRFProtection, RateLimiter, 
    SecurityViolation as SecViolation, validate_and_sanitize_input,
    log_security_event, SECURITY_CONFIG, AccessControl
)

chat_bp = Blueprint('chat', __name__)

# VirusTotal configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_FILE_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_FILE_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_URL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
VIRUSTOTAL_URL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

# File upload configuration
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}

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
        print(f"Invalid URL format: {url}")
        return False, None, "Invalid URL format"
    
    print(f"[DEBUG] Starting VirusTotal scan for URL: {url}")
    
    try:
        # First, try to get existing report for the URL
        report_params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'resource': url
        }
        
        print(f"[DEBUG] Checking existing report for {url}")
        report_response = requests.get(VIRUSTOTAL_URL_REPORT_URL, params=report_params, timeout=30)
        
        if report_response.status_code == 200:
            report_data = report_response.json()
            print(f"[DEBUG] Existing report response_code: {report_data.get('response_code')}")
            
            if report_data['response_code'] == 1:  # Report exists
                print(f"[DEBUG] Found existing report for {url}")
                return analyze_url_scan_result(report_data, url)
        else:
            print(f"[DEBUG] Report request failed with status {report_response.status_code}")
        
        # If no existing report, submit URL for scanning
        print(f"[DEBUG] Submitting new scan for {url}")
        scan_params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'url': url
        }
        
        scan_response = requests.post(VIRUSTOTAL_URL_SCAN_URL, data=scan_params, timeout=30)
        print(f"[DEBUG] Scan submission status: {scan_response.status_code}")
        
        if scan_response.status_code == 200:
            scan_data = scan_response.json()
            print(f"[DEBUG] Scan response_code: {scan_data.get('response_code')}")
            
            if scan_data['response_code'] == 1:
                # Wait for scan to complete and get results
                print(f"[DEBUG] Waiting for scan results for {url}")
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
    print(f"[DEBUG] Starting wait loop for {url} (max {max_wait_time}s)")
    
    while time.time() - start_time < max_wait_time:
        try:
            elapsed = time.time() - start_time
            print(f"[DEBUG] Checking scan status (elapsed: {elapsed:.1f}s)")
            
            report_params = {
                'apikey': VIRUSTOTAL_API_KEY,
                'resource': url
            }
            
            report_response = requests.get(VIRUSTOTAL_URL_REPORT_URL, params=report_params, timeout=30)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                response_code = report_data.get('response_code')
                print(f"[DEBUG] Report response_code: {response_code}")
                
                if response_code == 1:  # Scan complete
                    print(f"[DEBUG] Scan complete for {url}")
                    return analyze_url_scan_result(report_data, url)
                elif response_code == -2:  # Still scanning
                    print(f"[DEBUG] Still scanning, waiting 5s...")
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

def redirect_to_latest_chat_with_notification(user_id, message):
    """Redirect user to their latest visited chat room and queue a notification"""
    try:
        from flask import session
        
        # Store the notification message in session to show after redirect
        session['notification'] = {
            'message': message,
            'type': 'error'
        }
        
        # Get the user's most recently visited room from session
        last_visited_room = session.get('last_visited_room')
        
        if last_visited_room:
            # Verify the room still exists and is active
            room = ChatRoom.query.get(last_visited_room)
            if room and room.is_active:
                return redirect(url_for('chat.chat_session', room_id=last_visited_room))
        
        # Fallback: Find the user's most recent chat room by message activity
        latest_message = Message.query.filter_by(user_id=user_id).order_by(Message.timestamp.desc()).first()
        
        if latest_message and latest_message.room_id:
            # Verify this room is still active
            room = ChatRoom.query.get(latest_message.room_id)
            if room and room.is_active:
                return redirect(url_for('chat.chat_session', room_id=latest_message.room_id))
        
        # Final fallback to chat rooms list
        return redirect(url_for('chat.chat_rooms'))
            
    except Exception as e:
        print(f"Error in redirect_to_latest_chat_with_notification: {e}")
        # Fallback to simple redirect
        return redirect(url_for('chat.chat_rooms'))

def is_user_muted(user_name, room_id, user_id=None):
    """Helper function to check if a user is muted in a specific room"""
    if user_id:
        mute = MutedUser.query.filter_by(
            user_id=user_id,
            room_id=room_id,
            is_active=True
        ).first()
    else:
        mute = MutedUser.query.filter_by(
            user_name=user_name,
            room_id=room_id,
            is_active=True
        ).first()
    
    if not mute:
        return False
    
    return mute.is_muted()

# Routes
# Landing page route removed - handled by login module

@chat_bp.route('/chat')
@require_admin
def chat_rooms():
    """Chat rooms menu page"""
    current_user = get_current_user()
    username = current_user['username']
    rooms = ChatRoom.query.filter_by(is_active=True).order_by(ChatRoom.created_at.desc()).all()
    return render_template('chat_rooms.html', username=escape(username), rooms=rooms)

@chat_bp.route('/chat/<room_id>')
@require_login
def chat_session(room_id):
    """Individual chat session route"""
    from flask import session, flash, redirect, url_for
    
    # Convert room_id to integer (handles both positive and negative)
    try:
        room_id = int(room_id)
    except ValueError:
        return "Invalid room ID", 404
    
    room = ChatRoom.query.get_or_404(room_id)
    if not room.is_active:
        flash('This chat room is not available', 'error')
        return redirect(url_for('chat.chat_rooms'))
    
    
    # Get current user from session
    current_user = get_current_user()
    username = current_user['username']
    
    # Track the user's visit to this room
    session['last_visited_room'] = room_id
    print(f"User {username} visited room {room_id} - tracking for redirect purposes")
    
    # Check for queued notifications from unauthorized access attempts
    notification = session.pop('notification', None)
    
    return render_template('session.html', 
                         username=escape(username), 
                         room=room,
                         room_id=room_id,
                         notification=notification)

@chat_bp.route('/api/rooms', methods=['GET'])
@require_login
def get_rooms():
    """API endpoint to get all active chat rooms"""
    rooms = ChatRoom.query.filter_by(is_active=True).order_by(ChatRoom.created_at.desc()).all()
    return jsonify([room.to_dict() for room in rooms])

@chat_bp.route('/api/rooms', methods=['POST'])
@require_login
@RateLimiter.rate_limit(limit_per_minute=10)
@CSRFProtection.require_csrf_token
def create_room():
    """API endpoint to create a new chat room"""
    try:
        data = request.get_json()
        
        if not data:
            raise SecViolation("Invalid JSON data", "INVALID_INPUT")
        
        # Validate and sanitize input
        schema = {
            'name': {
                'type': 'string',
                'required': True,
                'max_length': SECURITY_CONFIG['MAX_ROOM_NAME_LENGTH'],
                'min_length': 1,
                'sanitize_html': True
            },
            'description': {
                'type': 'string',
                'required': False,
                'max_length': 500,
                'sanitize_html': True
            }
        }
        
        validated_data = validate_and_sanitize_input(data, schema)
        name = validated_data['name']
        description = validated_data.get('description', '')
        
        # Log room creation attempt
        current_user = get_current_user()
        log_security_event(
            "ROOM_CREATE_ATTEMPT",
            f"User {current_user['username']} creating room: {name}",
            "INFO"
        )
        
        # Check if room with same name already exists
        existing_room = ChatRoom.query.filter_by(name=name, is_active=True).first()
        if existing_room:
            return jsonify({'error': 'Room with this name already exists'}), 409
        
        new_room = ChatRoom(name=name, description=description)
        db.session.add(new_room)
        db.session.commit()
        
        log_security_event(
            "ROOM_CREATED",
            f"Room '{name}' created successfully by {current_user['username']}",
            "INFO"
        )
        
        return jsonify(new_room.to_dict()), 201
        
    except SecViolation as e:
        log_security_event("ROOM_CREATE_VIOLATION", f"Security violation: {e.message}", "WARNING")
        return jsonify({'error': 'Invalid input data'}), 400
    except Exception as e:
        log_security_event("ROOM_CREATE_ERROR", f"Unexpected error: {str(e)}", "ERROR")
        return jsonify({'error': 'Failed to create room'}), 500

@chat_bp.route('/history/<room_id>')
@require_login
def history(room_id):
    """Get chat history for a specific room"""
    try:
        room_id = int(room_id)
    except ValueError:
        return "Invalid room ID", 404
    room = ChatRoom.query.get_or_404(room_id)
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).all()
    return jsonify([msg.to_dict() for msg in messages])

@chat_bp.route('/api/mute-status/<room_id>', methods=['GET'])
@require_login
def check_mute_status(room_id):
    """API endpoint to check if current user is muted in a specific room"""
    try:
        room_id = int(room_id)
    except ValueError:
        return jsonify({'error': 'Invalid room ID'}), 400
    
    current_user = get_current_user()
    user_id = current_user['user_id']
    
    mute = MutedUser.query.filter_by(
        user_id=user_id,
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

@chat_bp.route('/upload/<room_id>', methods=['POST'])
@require_login
@RateLimiter.rate_limit(limit_per_minute=20)  # Rate limit file uploads
def upload_file(room_id):
    """Handle file uploads with virus scanning for a specific room"""
    from flask import current_app
    
    try:
        # Convert and validate room_id (allow negative for admin rooms)
        try:
            room_id = int(room_id)
        except ValueError:
            return jsonify({'error': 'Invalid room ID'}), 400
        
        room = ChatRoom.query.get_or_404(room_id)
        if not room.is_active:
            return jsonify({'error': 'Chat room is not available'}), 400
        
        # Get current user from session
        current_user = get_current_user()
        user_id = current_user['user_id']
        user_name = current_user['username']
        
        # Validate and sanitize message
        message = request.form.get('message', '')
        if message:
            message = InputValidator.validate_string(
                message, 
                max_length=SECURITY_CONFIG['MAX_MESSAGE_LENGTH'],
                field_name="message"
            )
            message = InputValidator.sanitize_html(message)
        
        # Validate username (defensive check)
        user_name = InputValidator.validate_username(user_name)
        
        # Check if user is muted in this room
        if is_user_muted(str(user_name), room_id, user_id):
            return jsonify({'error': 'You are muted in this room and cannot send messages or upload files.'}), 403

        # Check if file was uploaded
        if 'file' not in request.files:
            # If there's a message, treat it as a regular text message
            if message:
                new_msg = Message(user_id=user_id, user_name=user_name, message=message, 
                                timestamp=datetime.utcnow(), room_id=room_id)
                db.session.add(new_msg)
                db.session.commit()
                
                # Import socketio at the top level would cause circular import, so we get it from current_app
                from flask import current_app
                socketio = current_app.extensions.get('socketio')
                if socketio:
                    socketio.emit('my response', new_msg.to_dict(), room=f'room_{room_id}')
                
                return jsonify({'success': True, 'message': 'Message sent successfully'})
            return jsonify({'error': 'No file part in the request'}), 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an empty file without a filename.
        if file.filename == '':
            # If there's a message, treat it as a regular text message
            if message:
                new_msg = Message(user_id=user_id, user_name=user_name, message=message, 
                                timestamp=datetime.utcnow(), room_id=room_id)
                db.session.add(new_msg)
                db.session.commit()
                
                # Import socketio at the top level would cause circular import, so we get it from current_app
                from flask import current_app
                socketio = current_app.extensions.get('socketio')
                if socketio:
                    socketio.emit('my response', new_msg.to_dict(), room=f'room_{room_id}')
                
                return jsonify({'success': True, 'message': 'Message sent successfully'})
            return jsonify({'error': 'No selected file'}), 400

        if file:
            # Validate file upload with security checks
            try:
                file_info = InputValidator.validate_file_upload(file, SECURITY_CONFIG['MAX_FILE_SIZE'])
            except SecViolation as e:
                log_security_event(
                    "FILE_UPLOAD_VIOLATION",
                    f"File upload violation by {user_name}: {e.message}",
                    "WARNING"
                )
                return jsonify({'error': str(e)}), 400
            
            # Sanitize filename
            filename = secure_filename(file_info['filename'])
            unique_filename = f"{uuid.uuid4()}_{filename}"
            
            # Read file data into memory for scanning and storage  
            file_data = file.read()
            file_size = len(file_data)
            mime_type = file.content_type or 'application/octet-stream'
            
            # Double-check file size (defensive programming)
            if file_size > SECURITY_CONFIG['MAX_FILE_SIZE']:
                return jsonify({
                    'error': f'File too large. Maximum size is {SECURITY_CONFIG["MAX_FILE_SIZE"] // (1024*1024)}MB, got {file_size // (1024*1024)}MB'
                }), 400
            
            # Create a temporary file for VirusTotal scanning
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(file_data)
                temp_file_path = temp_file.name

            try:
                # Scan file with VirusTotal
                print(f"Scanning file {filename} for viruses...")
                is_safe, scan_result, scan_message = scan_file_with_virustotal(temp_file_path)
                
                print(f"Scan result for {filename}: {scan_message}")
                
                if not is_safe:
                    # Log the security violation
                    violation = SecurityViolation(
                        user_id=str(user_id),
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
                    os.unlink(temp_file_path)
                    return jsonify({
                        'error': f'File upload blocked: {scan_message}',
                        'scan_details': scan_result
                    }), 400

                # File is safe, store in database
                # Save to database with scan information based on whether scan actually occurred
                if not VIRUSTOTAL_API_KEY:
                    scan_info = "⚠️ Uploaded without virus scan (API key not configured)"
                elif scan_result is not None:
                    scan_info = f"✅ Virus scan passed: \n {scan_message}"
                else:
                    scan_info = f"⚠️ Virus scan skipped: \n {scan_message}"
                
                # Store file in database
                uploaded_file = UploadedFile(
                    filename=unique_filename,
                    original_filename=filename,
                    file_data=file_data,
                    file_size=file_size,
                    mime_type=mime_type,
                    scan_info=scan_info
                )
                db.session.add(uploaded_file)
                db.session.flush()  # Get the file ID
                
                full_message = f"{message}\n\n{scan_info}" if message else scan_info

                new_msg = Message(
                    user_id=user_id,
                    user_name=user_name,
                    message=full_message,
                    timestamp=datetime.utcnow(),
                    file_id=uploaded_file.id,
                    room_id=room_id
                )
                db.session.add(new_msg)
                db.session.commit()

                # Remove the temporary file
                os.unlink(temp_file_path)

                # Emit message to room clients
                socketio = current_app.extensions.get('socketio')
                if socketio:
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

# SocketIO event handlers (these will be used by the main app)
def handle_join(socketio, data):
    """Handle user joining a chat room"""
    room_id = data.get('room')
    username = data.get('username', 'Guest')
    
    if room_id:
        room_name = f'room_{room_id}'
        join_room(room_name)
        print(f'{username} joined room {room_id}')

def handle_leave(socketio, data):
    """Handle user leaving a chat room"""
    room_id = data.get('room')
    username = data.get('username', 'Guest')
    
    if room_id:
        room_name = f'room_{room_id}'
        leave_room(room_name)
        print(f'{username} left room {room_id}')

def handle_chat_message(socketio, json):
    """Handle chat message with URL scanning"""
    from flask import session
    
    try:
        # Check if user is authenticated
        if 'username' not in session or 'user_id' not in session:
            socketio.emit('error', {'message': 'Authentication required'})
            return
        
        room_id = json.get('room_id')
        if not room_id:
            return
        
        # Validate room_id (allow negative for admin rooms)
        try:
            room_id = int(room_id)
        except (ValueError, TypeError):
            return
        
        # Verify room exists
        room = ChatRoom.query.get(room_id)
        if not room or not room.is_active:
            return
        
        print('received message:', json)

        # Get user info from session instead of message data
        user_name = session['username']
        user_id = session['user_id']
        message = json.get('message', '')

        # Validate and sanitize inputs
        try:
            user_name = InputValidator.validate_username(user_name)
            if message:
                message = InputValidator.validate_string(
                    message,
                    max_length=SECURITY_CONFIG['MAX_MESSAGE_LENGTH'],
                    field_name="message"
                )
                message = InputValidator.sanitize_html(message)
        except SecViolation as e:
            log_security_event(
                "CHAT_MESSAGE_VIOLATION",
                f"Message validation failed for {user_name}: {e.message}",
                "WARNING"
            )
            emit('error', {'message': 'Invalid message content'})
            return
        
        # Check if user is muted in this room
        if is_user_muted(str(user_name), room_id, user_id):
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
                        user_id=str(user_id),
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
            user_id=user_id,
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
        
    except Exception as e:
        log_security_event(
            "CHAT_MESSAGE_ERROR",
            f"Unexpected error in chat message handling: {str(e)}",
            "ERROR"
        )
        emit('error', {'message': 'Message processing failed'})

@chat_bp.route('/api/chat/<room_id>/delete', methods=['DELETE'])
@require_login
@RateLimiter.rate_limit(limit_per_minute=5)  # Strict rate limiting for destructive operations
@CSRFProtection.require_csrf_token
def delete_chat_room(room_id):
    """Delete entire chat room and all associated data"""
    try:
        # Convert and validate room_id (allow negative for admin rooms)
        try:
            room_id = int(room_id)
        except ValueError:
            return jsonify({'error': 'Invalid room ID'}), 400
        
        # Get current user info
        current_user = get_current_user()
        user_id = current_user['user_id']
        username = current_user['username']
        
        # Log the deletion attempt
        log_security_event(
            "CHAT_ROOM_DELETE_ATTEMPT", 
            f"User {username} attempting to delete room {room_id}",
            "WARNING"
        )
        
        # Get the chat room
        room = ChatRoom.query.get_or_404(room_id)
        
        print(f"User {username} ({user_id}) attempting to delete chat room {room_id}: {room.name}")
        
        # For security, we could add admin-only restriction here, but based on requirements 
        # it seems any user should be able to delete a chat room
        # If you want admin-only, uncomment the next two lines:
        # if not require_admin():
        #     return jsonify({'error': 'Admin access required'}), 403
        
        # Get all related data counts for logging
        messages_count = Message.query.filter_by(room_id=room_id).count()
        files_count = UploadedFile.query.join(Message).filter(Message.room_id == room_id).count()
        violations_count = SecurityViolation.query.filter_by(room_id=room_id).count()
        muted_users_count = MutedUser.query.filter_by(room_id=room_id).count()
        
        print(f"Deleting chat room {room_id} with:")
        print(f"  - {messages_count} messages")
        print(f"  - {files_count} uploaded files")
        print(f"  - {violations_count} security violations")
        print(f"  - {muted_users_count} muted user records")
        
        # Delete all uploaded files associated with messages in this room
        # First get all file IDs to delete
        file_ids = db.session.query(UploadedFile.id).join(Message).filter(Message.room_id == room_id).all()
        file_ids = [f[0] for f in file_ids]
        
        if file_ids:
            # Delete the uploaded files
            UploadedFile.query.filter(UploadedFile.id.in_(file_ids)).delete(synchronize_session=False)
            print(f"Deleted {len(file_ids)} uploaded files")
        
        # Delete all security violations for this room
        SecurityViolation.query.filter_by(room_id=room_id).delete()
        print(f"Deleted {violations_count} security violations")
        
        # Delete all muted user records for this room
        MutedUser.query.filter_by(room_id=room_id).delete()
        print(f"Deleted {muted_users_count} muted user records")
        
        # Delete all messages in this room (this will cascade to delete files due to foreign key)
        Message.query.filter_by(room_id=room_id).delete()
        print(f"Deleted {messages_count} messages")
        
        # Finally delete the chat room itself
        db.session.delete(room)
        
        # Commit all deletions
        db.session.commit()
        
        print(f"Successfully deleted chat room {room_id}: {room.name}")
        
        return jsonify({
            'success': True,
            'message': f'Chat room "{room.name}" and all associated data deleted successfully',
            'deleted_data': {
                'messages': messages_count,
                'files': len(file_ids),
                'violations': violations_count,
                'muted_users': muted_users_count
            }
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting chat room {room_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to delete chat room: {str(e)}'
        }), 500

@chat_bp.route('/file/<int:file_id>')
@require_login
def serve_file(file_id):
    """Serve file from database with proper authorization"""
    try:
        from flask import session
        current_user = get_current_user()
        user_id = current_user['user_id']
        username = current_user['username']
        
        print(f"Serving file {file_id}, user: {username}")
        
        # Get the file
        uploaded_file = UploadedFile.query.get_or_404(file_id)
        
        # Find the message that contains this file
        message = Message.query.filter_by(file_id=file_id).first()
        if not message:
            print(f"No message found for file {file_id}")
            return redirect_to_latest_chat_with_notification(user_id, "File not found or access denied")
        
        # Get the chat room for this message
        chat_room = ChatRoom.query.get(message.room_id)
        if not chat_room or not chat_room.is_active:
            print(f"Chat room {message.room_id} not found or inactive")
            return redirect_to_latest_chat_with_notification(user_id, "Chat room not accessible")
        
        # STRICT Authorization: User can ONLY access files when viewing the specific chat room
        # This applies to ALL files - even ones they uploaded themselves
        
        print(f"File belongs to message ID {message.id} in room {message.room_id}")
        print(f"File uploaded by user_id: {message.user_id}, current user_id: {user_id}")
        
        # Check if user is currently viewing the correct chat room (based on HTTP referer)
        from flask import request
        referer = request.headers.get('Referer', '')
        print(f"Request referer: {referer}")
        
        # Check if the referer is from the correct chat room
        expected_chat_url = f'/chat/{message.room_id}'
        is_accessing_from_correct_room = expected_chat_url in referer
        
        print(f"Expected chat URL: {expected_chat_url}")
        print(f"Accessing from correct room: {is_accessing_from_correct_room}")
        
        # STRICT RULE: Files can ONLY be accessed when viewing the correct chat room
        if not is_accessing_from_correct_room:
            print(f"User {username} denied access to file {file_id} - not accessing from correct room {message.room_id}")
            return redirect_to_latest_chat_with_notification(user_id, "Unauthorized access - files can only be accessed from within their respective chat room")
        
        # Additional verification: ensure user has access to this room
        user_uploaded_file = (message.user_id == user_id)
        user_messages_in_room = Message.query.filter_by(
            user_id=user_id, 
            room_id=message.room_id
        ).count()
        
        print(f"User uploaded this file: {user_uploaded_file}")
        print(f"User has {user_messages_in_room} messages in room {message.room_id}")
        
        # User must have participated in this room (either uploaded this file OR has other messages)
        if not user_uploaded_file and user_messages_in_room == 0:
            print(f"User {username} denied access to file {file_id} - no participation in room")
            return redirect_to_latest_chat_with_notification(user_id, "Unauthorized access - you haven't participated in this chat room")
        
        # Log successful access
        print(f"File access granted: {uploaded_file.original_filename} to user {username}")
        
        # For images, use inline display; for other files, use attachment for download
        file_extension = uploaded_file.original_filename.split('.')[-1].lower() if '.' in uploaded_file.original_filename else ''
        is_image = file_extension in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg']
        
        disposition = 'inline' if is_image else 'attachment'
        
        return Response(
            uploaded_file.file_data,
            mimetype=uploaded_file.mime_type,
            headers={
                'Content-Disposition': f'{disposition}; filename="{uploaded_file.original_filename}"',
                'Content-Length': str(uploaded_file.file_size),
                'Cache-Control': 'private, max-age=3600'  # Private cache since it's access-controlled
            }
        )
    except Exception as e:
        print(f"Error serving file {file_id}: {e}")
        return f"Access denied", 403