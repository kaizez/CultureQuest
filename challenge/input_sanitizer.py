"""
Input sanitization module for preventing injection attacks.
Provides comprehensive input validation and sanitization functions.
"""
import re
import html
import bleach
from markupsafe import Markup

# Allowed HTML tags for rich text content - Protects against XSS while allowing safe formatting
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li'] #  XSS Protection with HTML Sanitization Lines 11-12
ALLOWED_ATTRIBUTES = {}  # No attributes allowed - Protects against attribute-based XSS

def sanitize_html(input_text): # INPUT SANITIZATION LINE 14-27
    """Sanitize HTML content to prevent XSS attacks - Protects against script injection."""
    if not input_text:
        return ""
    
    # Use bleach to clean HTML - Protects against malicious HTML/JavaScript   XSS Protection with HTML Sanitization Lines 19-25
    cleaned = bleach.clean(
        input_text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True  # Remove disallowed tags completely
    )
    
    return cleaned

def sanitize_text_input(input_text, max_length=None): # INPUT SANITIZATION LINE 29-47
    """Sanitize plain text input - Protects against injection and overflow attacks."""
    if not input_text:
        return ""
    
    # Convert to string and strip whitespace
    text = str(input_text).strip()
    
    # HTML encode to prevent XSS - Protects against script injection in text fields   XSS Protection with HTML Sanitization Lines 37-38
    text = html.escape(text)
    
    # Remove potentially dangerous characters - Protects against injection attacks
    text = re.sub(r'[<>"\']', '', text)
    
    # Enforce length limits - Protects against buffer overflow attacks
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text

def validate_email(email):
    """Validate email format - Protects against malformed email injection."""
    if not email:
        return False
    
    # Basic email validation regex - Protects against email injection attacks
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email) is not None

def sanitize_filename(filename):
    """Sanitize filename to prevent directory traversal - Protects against path injection."""
    if not filename:
        return ""
    
    # Remove directory traversal attempts - Protects against directory traversal attacks
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    
    # Remove potentially dangerous characters - Protects against filename injection
    filename = re.sub(r'[<>:"|?*]', '', filename)
    
    # Limit length - Protects against filesystem limits
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:250] + ('.' + ext if ext else '')
    
    return filename

def validate_integer(value, min_val=None, max_val=None):
    """Validate and sanitize integer input - Protects against integer overflow attacks."""
    try:
        int_val = int(value)
        
        # Check bounds - Protects against integer overflow/underflow
        if min_val is not None and int_val < min_val:
            return None
        if max_val is not None and int_val > max_val:
            return None
            
        return int_val
    except (ValueError, TypeError):
        return None

def sanitize_sql_input(input_text):
    """Sanitize input for SQL queries - Protects against SQL injection (use with parameterized queries)."""
    if not input_text:
        return ""
    
    # Remove SQL injection patterns - Additional protection alongside parameterized queries
    dangerous_patterns = [
        r"('|(\\')|(;)|(\\;)|(--|#)|(\\--)|(\\#))",
        r"(exec|execute|select|insert|update|delete|drop|create|alter)",
        r"(union|order\s+by|group\s+by|having)"
    ]
    
    text = str(input_text)
    for pattern in dangerous_patterns:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE)
    
    return text.strip()

def validate_challenge_input(form_data): # INPUT SANITIZATION LINE 109-140
    """Validate and sanitize challenge form input - Protects against various injection attacks."""
    sanitized = {}
    
    # Sanitize challenge name - Protects against XSS in challenge titles
    if 'challenge_name' in form_data:
        sanitized['challenge_name'] = sanitize_text_input(
            form_data['challenge_name'], 
            max_length=100
        )
    
    # Sanitize description - Allow some HTML but prevent XSS
    if 'description' in form_data: #  XSS Protection with HTML Sanitization Lines 121-130
        sanitized['description'] = sanitize_html(form_data['description'])
        if len(sanitized['description']) > 500:
            sanitized['description'] = sanitized['description'][:500]
    
    # Sanitize completion criteria - Allow some HTML but prevent XSS
    if 'completion_criteria' in form_data:
        sanitized['completion_criteria'] = sanitize_html(form_data['completion_criteria'])
        if len(sanitized['completion_criteria']) > 300:
            sanitized['completion_criteria'] = sanitized['completion_criteria'][:300]
    
    # Validate points if present - Protects against integer injection
    if 'points' in form_data and form_data['points']:
        sanitized['points'] = validate_integer(
            form_data['points'], 
            min_val=0, 
            max_val=1000
        )
    
    return sanitized

def validate_admin_input(form_data):
    """Validate and sanitize admin form input - Protects against admin panel injection attacks."""
    sanitized = {}
    
    # Validate challenge ID - Protects against ID injection
    if 'challenge_id' in form_data:
        sanitized['challenge_id'] = validate_integer(
            form_data['challenge_id'], 
            min_val=1
        )
    
    # Validate status - Protects against status injection
    if 'status' in form_data:
        allowed_statuses = ['On Hold', 'Approved', 'Rejected']
        status = form_data['status']
        if status in allowed_statuses:
            sanitized['status'] = status
    
    # Sanitize comments - Protects against XSS in admin comments
    if 'comments' in form_data:
        sanitized['comments'] = sanitize_html(form_data['comments'])
        if len(sanitized['comments']) > 1000:
            sanitized['comments'] = sanitized['comments'][:1000]
    
    # Validate points - Protects against point injection
    if 'points' in form_data and form_data['points']:
        sanitized['points'] = validate_integer(
            form_data['points'], 
            min_val=0, 
            max_val=1000
        )
    
    return sanitized