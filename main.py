from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from models import db, Message
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'secret!'
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
def sessions():
    return render_template('session.html')

@app.route('/history')
def history():
    messages = Message.query.all()
    return jsonify([msg.to_dict() for msg in messages])

# SocketIO event
@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received message:', json)

    # Save to database
    new_msg = Message(
        user_name=json['user_name'],
        message=json['message']
    )
    db.session.add(new_msg)
    db.session.commit()

    # Emit message including timestamp from database
    socketio.emit('my response', new_msg.to_dict())

# Run the server
if __name__ == '__main__':
    socketio.run(app, debug=True)
