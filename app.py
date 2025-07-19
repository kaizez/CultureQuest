import os
import uuid
import hashlib
import requests
import time
from flask import Flask, render_template, jsonify, request, url_for
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from models import db, Message
from datetime import datetime
from markupsafe import escape
from dotenv import load_dotenv

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
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'doc', 'docx'}

# VirusTotal configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app)

# Create tables if not exist
with app.app_context():
    db.create_all()

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
        
        report_response = requests.get(VIRUSTOTAL_REPORT_URL, params=report_params)
        
        if report_response.status_code == 200:
            report_data = report_response.json()
            
            if report_data['response_code'] == 1:  # Report exists
                return analyze_scan_result(report_data)
        
        # If no existing report, submit file for scanning
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            params = {'apikey': VIRUSTOTAL_API_KEY}
            
            scan_response = requests.post(VIRUSTOTAL_URL, files=files, data=params, timeout=60)
            
            if scan_response.status_code == 200:
                scan_data = scan_response.json()
                
                if scan_data['response_code'] == 1:
                    # Wait for scan to complete and get results
                    return wait_for_scan_result(scan_data['scan_id'])
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

def wait_for_scan_result(scan_id, max_wait_time=120):
    """
    Wait for VirusTotal scan to complete and return results
    """
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        try:
            report_params = {
                'apikey': VIRUSTOTAL_API_KEY,
                'resource': scan_id
            }
            
            report_response = requests.get(VIRUSTOTAL_REPORT_URL, params=report_params)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                
                if report_data['response_code'] == 1:  # Scan complete
                    return analyze_scan_result(report_data)
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

def analyze_scan_result(report_data):
    """
    Analyze VirusTotal scan results
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

@app.route('/chat')
def chat_session():
    """Chat session route"""
    # Get username from query parameters or default to 'Guest'
    username = request.args.get('username', 'Guest')
    # Sanitize username to prevent XSS
    return render_template('session.html', username=escape(username))

@app.route('/history')
def history():
    """Get chat history"""
    messages = Message.query.all()
    return jsonify([msg.to_dict() for msg in messages])

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file uploads with virus scanning"""
    try:
        user_name = request.form.get('user_name', 'Guest')
        message = request.form.get('message', '')

        # Basic input validation for user_name and message
        if len(user_name) > 50 or len(message) > 500:
            return jsonify({'error': 'Input too long'}), 400

        # Sanitize inputs
        user_name = escape(user_name)
        message = escape(message)

        # Check if file was uploaded
        if 'file' not in request.files:
            # If there's a message, treat it as a regular text message
            if message:
                new_msg = Message(user_name=user_name, message=message, timestamp=datetime.utcnow())
                db.session.add(new_msg)
                db.session.commit()
                socketio.emit('my response', new_msg.to_dict())
                return jsonify({'success': True, 'message': 'Message sent successfully'})
            return jsonify({'error': 'No file part in the request'}), 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an empty file without a filename.
        if file.filename == '':
            # If there's a message, treat it as a regular text message
            if message:
                new_msg = Message(user_name=user_name, message=message, timestamp=datetime.utcnow())
                db.session.add(new_msg)
                db.session.commit()
                socketio.emit('my response', new_msg.to_dict())
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
                    file_url=file_url
                )
                db.session.add(new_msg)
                db.session.commit()

                # Emit message to all clients
                socketio.emit('my response', new_msg.to_dict())

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

# SocketIO event
@socketio.on('my event')
def handle_my_custom_event(json):
    print('received message:', json)

    user_name = json.get('user_name', 'Guest')
    message = json.get('message', '')

    # Basic input validation
    if len(user_name) > 50 or len(message) > 500:
        return

    # Sanitize inputs
    user_name = escape(user_name)
    message = escape(message)

    # Save to database
    new_msg = Message(
        user_name=user_name,
        message=message,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_msg)
    db.session.commit()

    # Emit message including timestamp from database
    emit('my response', new_msg.to_dict(), broadcast=True)

# Run the server
if __name__ == '__main__':
    socketio.run(app, debug=True)