import os
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from models import db, Message
from datetime import datetime
from markupsafe import escape

app = Flask(__name__)

# Configuration
# It is recommended to use environment variables for the secret key in production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-long-and-random-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app)

# Create tables if not exist
with app.app_context():
    db.create_all()

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
        timestamp=datetime.utcnow()  # Add timestamp here
    )
    db.session.add(new_msg)
    db.session.commit()

    # Emit message including timestamp from database
    emit('my response', new_msg.to_dict(), broadcast=True)

# Run the server
if __name__ == '__main__':
    socketio.run(app, debug=False)