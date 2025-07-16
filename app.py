from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_dance.contrib.google import make_google_blueprint, google
import datetime

# Load environment variables from .env file
load_dotenv()

# Flask app setup
app = Flask(__name__, static_folder='static', template_folder='public')

# Flask session secret key
app.secret_key = os.getenv('SESSION_SECRET', 'your_secret_key')

DB_PATH = 'users.db'

# Google OAuth setup
google_bp = make_google_blueprint(
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    redirect_to='google_callback'
)
app.register_blueprint(google_bp, url_prefix='/auth')


def init_db():
    """Initialize the SQLite database if not exists or modify schema"""
    if not os.path.exists(DB_PATH):
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    email TEXT,
                    password TEXT
                )
            ''')
            conn.commit()
    else:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            try:
                c.execute("ALTER TABLE users ADD COLUMN password TEXT")
                conn.commit()
            except sqlite3.OperationalError:
                pass  # Column already exists


@app.route('/')
def login_page():
    return render_template('index.html')


@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify(success=False, message="All fields are required."), 400

        hashed_password = generate_password_hash(password)

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
            existing_user = c.fetchone()
            if existing_user:
                return jsonify(success=False, message="Username or email already exists."), 400

            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed_password))
            conn.commit()

            print(f"User Registered: {username}, {email}")

        return jsonify(success=True)

    except Exception as e:
        print(f"Error during signup: {e}")
        return jsonify(success=False, message="Server error, please try again later."), 500


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()

        if user and check_password_hash(user[3], password):
            session['username'] = username
            email = user[2]
            print(f"User Email Retrieved: {email}")
            return redirect(url_for('profile'))
        else:
            return "Invalid credentials!"


@app.route('/profile')
def profile():
    if 'username' in session:
        return render_template('profile.html', username=session['username'])
    return redirect(url_for('login_page'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login_page'))


@app.route('/auth/google/callback')
def google_callback():
    if google.authorized:
        user_info = google.get('/plus/v1/people/me')
        user_data = user_info.json()

        email = user_data['emails'][0]['value']

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email=?", (email,))
            user = c.fetchone()

            if not user:
                username = user_data['displayName']
                c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                          (username, email, ''))
                conn.commit()

            session['username'] = user_data['displayName']
            return redirect(url_for('profile'))

    return redirect(url_for('login_page'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='127.0.0.1', port=5000)
