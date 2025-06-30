import os
from flask import request, render_template
import sqlite3
from PIL import Image

# Function to connect to the file-based database
def get_db_connection():
    conn = sqlite3.connect('challenges.db')  # Use a file-based SQLite database
    conn.row_factory = sqlite3.Row  # Allow access to columns by name
    return conn

# Function to handle the challenge form submission
def handle_challenge_form(app):
    if request.method == "POST":
        # Get form data
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        description = request.form['description']
        
        # Handle file upload (thumbnail)
        thumbnail = request.files['thumbnail']
        thumbnail_path = None
        
        # Ensure the 'uploads' folder exists
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)  # Create the folder if it doesn't exist
        
        if thumbnail:
            # Check if the uploaded file is a PNG image
            try:
                # Open the image file to validate the type
                image = Image.open(thumbnail)
                if image.format != 'PNG':
                    return render_template('challenge_form.html', message="Please upload a PNG image.")
                
                # Save the file with its original filename
                thumbnail_path = os.path.join(upload_folder, thumbnail.filename)
                thumbnail.save(thumbnail_path)

            except IOError:
                return render_template('challenge_form.html', message="The uploaded file is not a valid image.")
        
        # Insert the data into the database
        conn = get_db_connection()

        # Create the table if it does not exist
        conn.execute('''CREATE TABLE IF NOT EXISTS challenges (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT,
                            email TEXT,
                            phone TEXT,
                            description TEXT,
                            thumbnail TEXT,
                            status TEXT)''')  # Ensure the table exists

        conn.execute('''INSERT INTO challenges (name, email, phone, description, thumbnail, status) 
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (name, email, phone, description, thumbnail_path, 'New'))
        conn.commit()
        conn.close()

        return render_template('challenge_form.html', message="Challenge submitted successfully!")

    return render_template('challenge_form.html')

# Function to retrieve all challenges for the screening page
def get_challenges():
    conn = get_db_connection()
    challenges = conn.execute('SELECT * FROM challenges').fetchall()
    conn.close()
    return challenges

# Function to update challenge status (in progress or approved)
def update_challenge_status(challenge_id, status):
    conn = get_db_connection()
    conn.execute('UPDATE challenges SET status = ? WHERE id = ?', (status, challenge_id))
    conn.commit()
    conn.close()