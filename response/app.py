from flask import Flask, render_template
from response import response_bp, limiter
from mod import moderate_bp
from db import init_db, db_session
import os
from dotenv import load_dotenv

def load_env():
    """Load environment variables from .env file."""
    basedir = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(basedir, '.env')
    if os.path.exists(dotenv_path):
        print(f"Loading .env file from {dotenv_path}")
        load_dotenv(dotenv_path)
    else:
        print('Error finding .env file')

load_env()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('secret_key')

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')

limiter.init_app(app)

with app.app_context():
    init_db()


@app.teardown_appcontext
def shutdown_session(exception=None):
    """Remove the database session at the end of the request or when the app shuts down."""
    db_session.remove()

app.register_blueprint(response_bp, url_prefix='/response')
app.register_blueprint(moderate_bp, url_prefix='/moderate')

@app.route('/')
def landing_page():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)