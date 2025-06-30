from flask import Flask, render_template, redirect, url_for, request
from challenge_form import handle_challenge_form, get_challenges, update_challenge_status
import sqlite3

app = Flask(__name__)

# Upload folder for the thumbnail image
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size 16 MB

@app.route("/", methods=["GET", "POST"])
def index():
    return handle_challenge_form(app)

@app.route("/screening")
def challenge_screening():
    challenges = get_challenges()  # Get all challenges from the database
    return render_template('screening.html', challenges=challenges)  # Pass challenges to the template

@app.route("/update_status/<int:id>/<status>")
def update_status(id, status):
    update_challenge_status(id, status)
    return f"Challenge {id} status updated to {status}"

@app.route("/delete/<int:id>", methods=["POST"])
def delete_challenge(id):
    # Connect to the database
    conn = sqlite3.connect('challenges.db')
    cursor = conn.cursor()
    
    # Delete the challenge with the specified ID
    cursor.execute('DELETE FROM challenges WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    # Redirect back to the screening page
    return redirect(url_for('challenge_screening'))

if __name__ == "__main__":
    app.run(debug=True)