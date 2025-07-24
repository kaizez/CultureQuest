import os
import random
import string

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi'}
UPLOAD_FOLDER = 'static/uploads/'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_filename(original_filename):
    ext = original_filename.rsplit('.', 1)[1].lower()
    filename = ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + '.' + ext
    return filename

def save_file(file):
    if file and allowed_file(file.filename):
        filename = generate_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        # Ensure the upload folder exists
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)

        # Save the file
        file.save(file_path)
        return filename  # Return the saved filename for later use
    else:
        raise ValueError("Invalid file type. Only PNG, JPG, JPEG, GIF, MP4, and AVI are allowed.")
