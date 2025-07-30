from flask import Flask, render_template
from response import response_bp, limiter
from mod import moderate_bp
from db import init_db, db
import os

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for sessions

#Amelia
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'mysql+pymysql://flask_user:your_password@localhost/challenges_hub_db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_SITE_KEY'] = '6LfyDo0rAAAAAC4VmJwx3fvFKhhfXYc3GVjqaO8q'
app.config['RECAPTCHA_SECRET_KEY'] = '6LfyDo0rAAAAAD9Mc3idU9TyOv4UcbDEicyVSe0a'

# --- Extensions Initialization ---
db.init_app(app)
limiter.init_app(app)

# --- Database Initialization ---
with app.app_context():
    init_db(app)


# Register Blueprints
app.register_blueprint(response_bp, url_prefix='/response')
app.register_blueprint(moderate_bp, url_prefix='/moderate')

@app.route('/')
def landing_page():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)