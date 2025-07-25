import os
import random
import string
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi'}
UPLOAD_FOLDER = 'static/uploads/'

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_filename(original_filename):
    """Generate a secure random filename."""
    ext = original_filename.rsplit('.', 1)[1].lower()
    filename = ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + '.' + ext
    return filename

def save_file(file):
    """Validate and save the uploaded file."""
    if file and allowed_file(file.filename):
        # Check MIME type for added security
        mime_type = file.content_type
        if mime_type not in ['image/jpeg', 'image/png', 'video/mp4']:
            raise ValueError("Invalid file type")

        filename = generate_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        # Ensure the upload folder exists
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)

        # Save the file securely
        file.save(file_path)
        return filename  # Return the saved filename for later use
    else:
        raise ValueError("Invalid file type. Only PNG, JPG, JPEG, GIF, MP4, and AVI are allowed.")
