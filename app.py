from flask import Flask, render_template
from flask_login import LoginManager

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for sessions

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)  # Initialize the login manager
login_manager.login_view = "login.login"  # Redirect to login if not logged in

# Import and Register the login Blueprint
from login import login_bp
app.register_blueprint(login_bp, url_prefix='/auth')

# Register other Blueprints
from challenge import challenge_bp
from admin_screening import admin_screening_bp
app.register_blueprint(challenge_bp, url_prefix='/host')
app.register_blueprint(admin_screening_bp, url_prefix='/admin')

@app.route('/')
def landing_page():
    return render_template('landing_page.html')

if __name__ == '__main__':
    app.run(debug=True)
