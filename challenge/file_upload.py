import os
import random
import string
from werkzeug.utils import secure_filename
try:
    import magic  # For file content validation - Protects against malicious files with fake extensions
    MAGIC_AVAILABLE = True
except ImportError:
    print("[WARNING] python-magic not available - file content validation disabled")
    MAGIC_AVAILABLE = False
from security_logger import log_file_upload_attempt  # Protects against unmonitored file uploads

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi'}  # Protects against dangerous file types
UPLOAD_FOLDER = 'static/uploads/'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB - Protects against DoS attacks via large file uploads
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'video/avi'
}  # Protects against MIME type spoofing attacks

def allowed_file(filename):
    """Check if the file has an allowed extension - Protects against dangerous file types."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_content(file_path):
    """Validate file content matches expected type - Protects against malicious files with fake extensions."""
    if not MAGIC_AVAILABLE:
        print("[WARNING] Magic not available - skipping file content validation")
        return True  # Skip validation if magic is not available
    
    try:
        mime_type = magic.from_file(file_path, mime=True)
        return mime_type in ALLOWED_MIME_TYPES
    except Exception:
        return False  # Protects against corrupted or malicious files

def check_file_size(file):
    """Check file size limits - Protects against DoS attacks via oversized uploads."""
    file.seek(0, os.SEEK_END)  # Go to end of file
    size = file.tell()  # Get current position (file size)
    file.seek(0)  # Reset to beginning
    return size <= MAX_FILE_SIZE

def generate_filename(original_filename):
    """Generate a secure random filename - Protects against directory traversal and filename attacks."""
    ext = original_filename.rsplit('.', 1)[1].lower()
    # Generate cryptographically secure random filename - Protects against filename prediction attacks
    filename = ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + '.' + ext
    return filename

def save_file(file):
    """Validate and save the uploaded file with comprehensive security checks."""
    if not file or not file.filename:
        log_file_upload_attempt("", 0, False, "No file provided")  # Log failed upload attempt
        raise ValueError("No file provided")
    
    file_size = 0
    try:
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
    except:
        pass
    
    # Check file size first - Protects against DoS attacks
    if not check_file_size(file):
        log_file_upload_attempt(file.filename, file_size, False, "File too large")  # Log failed upload attempt
        raise ValueError(f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB")
    
    # Check file extension - Protects against dangerous file types
    if not allowed_file(file.filename):
        log_file_upload_attempt(file.filename, file_size, False, "Invalid file extension")  # Log failed upload attempt
        raise ValueError("Invalid file type. Only PNG, JPG, JPEG, GIF, MP4, and AVI are allowed.")
    
    # Check MIME type from header - Protects against MIME type spoofing
    mime_type = file.content_type
    if mime_type not in ALLOWED_MIME_TYPES:
        log_file_upload_attempt(file.filename, file_size, False, "Invalid MIME type")  # Log failed upload attempt
        raise ValueError("Invalid MIME type detected")
    
    # Use secure filename generation - Protects against directory traversal
    filename = generate_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    # Ensure the upload folder exists with secure permissions
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, mode=0o755)  # Protects against unauthorized directory access
    
    # Save the file securely
    file.save(file_path)
    
    # Validate file content after saving - Protects against malicious files with fake extensions
    if not validate_file_content(file_path):
        os.remove(file_path)  # Remove invalid file - Protects against malicious file storage
        log_file_upload_attempt(file.filename, file_size, False, "File content validation failed")  # Log failed upload attempt
        raise ValueError("File content validation failed")
    
    # Log successful upload
    log_file_upload_attempt(file.filename, file_size, True, None)
    
    return filename  # Return the saved filename for later use
