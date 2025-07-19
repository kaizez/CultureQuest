import os
import uuid
from flask import Flask, render_template, jsonify, request, url_for
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from models import db, Message
from datetime import datetime
from markupsafe import escape

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-long-and-random-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'doc', 'docx'}

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
    """Handle file uploads"""
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
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Save file
            file.save(file_path)

            # Create file URL
            file_url = url_for('static', filename=f'uploads/{unique_filename}')

            # Save to database
            new_msg = Message(
                user_name=user_name,
                message=message,
                timestamp=datetime.utcnow(),
                file_name=filename,
                file_url=file_url
            )
            db.session.add(new_msg)
            db.session.commit()

            # Emit message to all clients
            socketio.emit('my response', new_msg.to_dict())

            return jsonify({'success': True, 'message': 'File uploaded successfully'})
        else:
            return jsonify({'error': 'File type not allowed'}), 400

    except Exception as e:
        print(f"Upload error: {e}")
        # Consider more specific error logging or handling here
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