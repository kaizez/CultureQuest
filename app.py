from flask import Flask, render_template
from challenge import challenge_bp
from admin_screening import admin_screening_bp
from event import event_bp

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for sessions

# Register Blueprints
app.register_blueprint(challenge_bp, url_prefix='/host')
app.register_blueprint(admin_screening_bp, url_prefix='/admin')
app.register_blueprint(event_bp, url_prefix='/event')

@app.route('/')
def landing_page():
    return render_template('landing_page.html')

if __name__ == '__main__':
    app.run(debug=True)
