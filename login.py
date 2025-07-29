from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import LoginManager,login_user, login_required, logout_user, current_user, UserMixin
from models import users, User  # Import the users data and User class from models.py

# Initialize Flask-Login Manager
login_manager = LoginManager()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

    def get_id(self):
        return self.id

# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        user = users[user_id]
        return User(user_id, user["role"])
    return None

# Create a Blueprint for login
login_bp = Blueprint('login', __name__)

# Login route
@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    # If the user is already logged in, redirect them to the landing page
    if current_user.is_authenticated:
        return redirect(url_for('landing_page'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate user credentials
        if username in users and users[username]["password"] == password:
            user = User(username, users[username]["role"])
            login_user(user)
            return redirect(url_for('landing_page'))  # Redirect after login
        
        # Invalid credentials
        return 'Invalid username or password', 401

    return render_template('login.html')  # Render the login page

# Logout route
@login_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing_page'))  # Redirect to landing page after logout
