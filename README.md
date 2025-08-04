# CultureQuest ChatApp Rewards - Complete Application Logic & Security Guide

## Table of Contents
1. [Application Overview](#application-overview)
2. [Database Architecture](#database-architecture)
3. [Core Components](#core-components)
4. [User Authentication & Authorization](#user-authentication--authorization)
5. [Chat System Logic](#chat-system-logic)
6. [Rewards System Logic](#rewards-system-logic)
7. [Security Implementation](#security-implementation)
8. [File Upload & Management](#file-upload--management)
9. [Admin Management](#admin-management)
10. [Presentation Key Points](#presentation-key-points)

---

## Application Overview

**CultureQuest ChatApp Rewards** is a secure, multi-room chat application with an integrated rewards system. Users can participate in chat rooms, earn points, and redeem rewards while being protected by comprehensive security measures.

### Key Features:
- **Multi-room Chat System**: Users can create and join multiple chat rooms
- **File Sharing**: Secure file uploads with virus scanning (VirusTotal integration)
- **Rewards System**: Users earn points and redeem rewards with location-based collection
- **Admin Management**: Admin dashboard for managing violations and user moderation
- **Security-First Design**: Comprehensive security framework protecting against common vulnerabilities

### Technology Stack:
- **Backend**: Flask (Python)
- **Database**: MySQL with SQLAlchemy ORM
- **Real-time Communication**: Flask-SocketIO
- **Security**: Custom security framework with VirusTotal integration
- **Frontend**: HTML/CSS/JavaScript with real-time updates

---

## Database Architecture

The application uses **6 main database models** that work together:

### 1. ChatRoom Model (`models.py:14-33`)
```python
class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
```
**Purpose**: Stores chat room information with cascade delete for all related messages

### 2. Message Model (`models.py:57-92`)
```python
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), nullable=False)  # UUID from login system
    user_name = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_file.id'), nullable=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
```
**Purpose**: Stores all chat messages with optional file attachments and room associations

### 3. UploadedFile Model (`models.py:34-56`)
```python
class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary(length=16777215), nullable=False)  # 16MB max
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    scan_info = db.Column(db.Text, nullable=True)  # VirusTotal results
```
**Purpose**: Stores uploaded files in database with virus scan results

### 4. UserPoints & RewardItem Models (`models.py:154-200`)
```python
class UserPoints(db.Model):
    user_id = db.Column(db.String(36), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False)
    points = db.Column(db.Integer, default=0)
    
class RewardItem(db.Model):
    name = db.Column(db.String(100), nullable=False)
    cost = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
```
**Purpose**: Manages user points and available rewards for redemption

### 5. SecurityViolation Model (`models.py:94-118`)
```python
class SecurityViolation(db.Model):
    user_name = db.Column(db.String(50), nullable=False)
    violation_type = db.Column(db.String(20), nullable=False)  # 'url' or 'file'
    content = db.Column(db.Text, nullable=False)  # URL or filename
    detection_details = db.Column(db.Text, nullable=True)  # Scan results
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
```
**Purpose**: Tracks security violations for admin review and monitoring

### 6. MutedUser Model (`models.py:120-152`)
```python
class MutedUser(db.Model):
    user_id = db.Column(db.String(36), nullable=False)
    user_name = db.Column(db.String(50), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    muted_until = db.Column(db.DateTime, nullable=True)  # None = permanent
    reason = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
```
**Purpose**: Manages per-room user muting with temporary or permanent options

---

## Core Components

### 1. Authentication System (`auth_utils.py`)

**How it Works:**
```python
@require_login  # Decorator checks session for 'username' and 'user_id'
def protected_route():
    user = get_current_user()  # Returns user info from Flask session
    return render_template('page.html', user=user)
```

**Key Functions:**
- `require_login()`: Validates user session, redirects to login if not authenticated
- `require_admin()`: Additional check for admin privileges
- `get_current_user()`: Extracts user info from Flask session
- Session-based authentication using Flask sessions

### 2. Security Framework (`security.py`)

**Multi-layered Security Classes:**

#### InputValidator Class
```python
@staticmethod
def validate_string(value, max_length=255, min_length=0):
    # Removes null bytes, validates length, prevents injection
    value = value.replace('\x00', '').strip()
    if len(value) > max_length:
        raise SecurityViolation("Input too long", "INVALID_INPUT")
    return value
```

#### CSRFProtection Class
```python
@staticmethod
def generate_token():
    token = secrets.token_urlsafe(32)  # Cryptographically secure token
    session['csrf_token'] = token
    session['csrf_token_time'] = time.time()
    return token

@require_csrf_token  # Decorator validates CSRF tokens on POST/PUT/DELETE
def protected_action():
    pass
```

#### RateLimiter Class
```python
@rate_limit(limit_per_minute=60)  # Prevents DoS attacks
def api_endpoint():
    pass
```

---

## Chat System Logic

### 1. Room Creation Flow (`chat.py:389-460`)

**Step-by-step Process:**
```python
@chat_bp.route('/api/rooms', methods=['POST'])
@require_login
@RateLimiter.rate_limit(limit_per_minute=30)
@CSRFProtection.require_csrf_token
def create_room():
    # 1. Validate user input
    name = InputValidator.validate_string(data.get('name'), max_length=100)
    description = InputValidator.validate_string(data.get('description'), max_length=500)
    
    # 2. Check for duplicate room names
    existing_room = ChatRoom.query.filter_by(name=name).first()
    if existing_room:
        return jsonify({'error': 'Room name already exists'}), 400
    
    # 3. Create new room
    new_room = ChatRoom(name=name, description=description)
    db.session.add(new_room)
    db.session.commit()
    
    # 4. Log security event
    log_security_event("ROOM_CREATED", f"User created room: {name}", "INFO")
```

### 2. Message Sending Logic (`chat.py:750-874`)

**Real-time Message Flow:**
```python
def handle_chat_message(socketio, json):
    # 1. Authentication check
    current_user = get_current_user()
    if not current_user:
        emit('error', {'message': 'Authentication required'})
        return
    
    # 2. Room validation
    room_id = int(json.get('room_id'))
    room = ChatRoom.query.get(room_id)
    if not room or not room.is_active:
        return
    
    # 3. Mute check
    if is_user_muted(user_name, room_id, user_id):
        emit('mute_notification', {'message': 'You are muted'})
        return
    
    # 4. Input validation & URL scanning
    message = InputValidator.sanitize_html(json.get('message', ''))
    urls = extract_urls(message)
    for url in urls:
        is_safe, scan_result, error = scan_url_with_virustotal(url)
        if not is_safe:
            # Log violation and block message
            create_security_violation(user_name, 'url', url, message, room_id)
            return
    
    # 5. Save message to database
    new_msg = Message(user_id=user_id, user_name=user_name, 
                     message=message, room_id=room_id)
    db.session.add(new_msg)
    db.session.commit()
    
    # 6. Broadcast to room users
    emit('my response', new_msg.to_dict(), room=f'room_{room_id}')
```

### 3. File Upload Security (`chat.py:529-727`)

**Comprehensive File Processing:**
```python
@chat_bp.route('/upload/<room_id>', methods=['POST'])
@require_login
@RateLimiter.rate_limit(limit_per_minute=20)
def upload_file(room_id):
    # 1. Room access validation
    room = ChatRoom.query.get_or_404(room_id)
    if not room.is_active:
        return jsonify({'error': 'Room not available'}), 400
    
    # 2. Mute check
    if is_user_muted(user_name, room_id, user_id):
        return jsonify({'error': 'You are muted'}), 403
    
    # 3. File validation
    if not allowed_file(file.filename):  # Extension whitelist
        return jsonify({'error': 'File type not allowed'}), 400
        
    # 4. VirusTotal scanning
    is_safe, scan_result, message = scan_file_with_virustotal(file_path, filename)
    if not is_safe:
        # Create security violation record
        violation = SecurityViolation(
            user_name=user_name,
            violation_type='file',
            content=filename,
            detection_details=json.dumps(scan_result),
            room_id=room_id
        )
        return jsonify({'error': 'File blocked by security scan'}), 400
    
    # 5. Store file in database
    uploaded_file = UploadedFile(
        filename=secure_filename,
        original_filename=filename,
        file_data=file_data,
        file_size=len(file_data),
        mime_type=file.mimetype,
        scan_info=json.dumps(scan_result)
    )
    
    # 6. Create message with file attachment
    new_msg = Message(user_id=user_id, message=full_message,
                     file_id=uploaded_file.id, room_id=room_id)
```

---

## Rewards System Logic

### 1. Points System (`rewards.py:34-41`)

**Auto-initialization Logic:**
```python
def get_or_create_user_points(user_id, username):
    user_points = UserPoints.query.filter_by(user_id=user_id).first()
    if not user_points:
        # New users get 950 points automatically
        user_points = UserPoints(user_id=user_id, username=username, points=950)
        db.session.add(user_points)
        db.session.commit()
    return user_points
```

### 2. Reward Redemption Flow (`rewards.py:69-150`)

**Transaction Processing:**
```python
@rewards_bp.route('/rewards/redeem', methods=['POST'])
@require_login
@RateLimiter.rate_limit(limit_per_minute=30)
@CSRFProtection.require_csrf_token
def redeem_reward():
    # 1. Input validation
    reward_id = InputValidator.validate_integer(data.get('reward_id'))
    
    # 2. Get user points
    user_points = get_or_create_user_points(user_id, username)
    
    # 3. Get reward item
    reward_item = RewardItem.query.get(reward_id)
    
    # 4. Business logic validation
    if user_points.points < reward_item.cost:
        return jsonify({'error': 'Insufficient points'}), 400
    if reward_item.stock <= 0:
        return jsonify({'error': 'Out of stock'}), 400
    
    # 5. Atomic transaction
    user_points.points -= reward_item.cost
    reward_item.stock -= 1
    
    # 6. Create redemption record
    redemption = RewardRedemption(
        username=username,
        reward_item_id=reward_id,
        points_spent=reward_item.cost,
        status='completed'
    )
    
    db.session.add(redemption)
    db.session.commit()  # All-or-nothing transaction
```

---

## Security Implementation

### 1. Cross-Chat File Access Prevention (`chat.py:998-1036`)

**The Core Security Logic:**
```python
@chat_bp.route('/file/<file_id>')
@require_login
def download_file(file_id):
    # 1. Get file and associated message
    uploaded_file = UploadedFile.query.get_or_404(file_id)
    message = Message.query.filter_by(file_id=file_id).first()
    
    # 2. CRITICAL: Referer-based room validation
    referer = request.headers.get('Referer', '')
    expected_chat_url = f'/chat/{message.room_id}'
    is_accessing_from_correct_room = expected_chat_url in referer
    
    # 3. STRICT RULE: Files can ONLY be accessed from correct room
    if not is_accessing_from_correct_room:
        return redirect_to_latest_chat_with_notification(
            user_id, "Files can only be accessed from within their chat room"
        )
    
    # 4. Participation verification
    user_uploaded_file = (message.user_id == user_id)
    user_messages_in_room = Message.query.filter_by(
        user_id=user_id, room_id=message.room_id
    ).count()
    
    # 5. Must have participated in room (messages or uploaded file)
    if not user_uploaded_file and user_messages_in_room == 0:
        return redirect_to_latest_chat_with_notification(
            user_id, "You haven't participated in this chat room"
        )
    
    # 6. Access granted - return file
    return Response(uploaded_file.file_data, 
                   mimetype=uploaded_file.mime_type)
```

**Why This Security Works:**
- **Referer Validation**: Ensures users are viewing the correct chat room
- **Participation Requirement**: Users must have sent messages in the room
- **Universal Application**: Even your own files require room access
- **Prevents Data Leakage**: No cross-chat file access possible

### 2. VirusTotal Integration (`chat.py:63-283`)

**File & URL Scanning Process:**
```python
def scan_file_with_virustotal(file_path, filename):
    # 1. Calculate file hash
    file_hash = get_file_hash(file_path)
    
    # 2. Check existing reports
    report_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    report_response = requests.get(VIRUSTOTAL_FILE_REPORT_URL, params=report_params)
    
    # 3. If no report exists, submit file for scanning
    if report_data['response_code'] != 1:
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f)}
            scan_response = requests.post(VIRUSTOTAL_FILE_SCAN_URL, 
                                        files=files, data=scan_params)
    
    # 4. Analyze scan results
    if report_data['positives'] > 0:
        return False, report_data, "Malicious file detected"
    
    return True, report_data, "File is clean"
```

### 3. Rate Limiting Implementation (`security.py:251-318`)

**DoS Protection Logic:**
```python
class RateLimiter:
    @staticmethod
    def check_rate_limit(limit_per_minute=60, limit_per_hour=1000):
        # 1. Generate client fingerprint
        client_id = hashlib.sha256(f"{ip}:{user_agent}".encode()).hexdigest()
        
        # 2. Check if client is blocked
        if now < client_data['blocked_until']:
            return False
        
        # 3. Clean old requests (sliding window)
        client_data['requests'] = [req_time for req_time in client_data['requests'] 
                                  if now - req_time < 3600]
        
        # 4. Check per-minute limit
        recent_requests = [req_time for req_time in client_data['requests'] 
                          if now - req_time < 60]
        if len(recent_requests) >= limit_per_minute:
            client_data['blocked_until'] = now + 60  # 1-minute block
            return False
        
        # 5. Check hourly limit
        if len(client_data['requests']) >= limit_per_hour:
            client_data['blocked_until'] = now + 3600  # 1-hour block
            return False
        
        # 6. Record request and allow
        client_data['requests'].append(now)
        return True
```

---

## File Upload & Management

### 1. File Storage Strategy
- **Database Storage**: Files stored as BLOB in MySQL (up to 16MB)
- **Security Scanning**: Every file scanned with VirusTotal before storage
- **Metadata Tracking**: Original filename, size, MIME type, scan results stored
- **Access Control**: Files only accessible from correct chat room

### 2. Allowed File Types (`chat.py:32`)
```python
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}
```

### 3. File Processing Pipeline
1. **Extension Validation**: Whitelist-based file type checking
2. **Size Limits**: Maximum 10MB per file (configurable)
3. **Virus Scanning**: VirusTotal API integration
4. **Secure Storage**: Database BLOB storage with metadata
5. **Access Control**: Room-based download restrictions

---

## Admin Management

### 1. Admin Dashboard (`chat_manage.py`)

**Violation Management:**
```python
@chat_manage_bp.route('/api/admin/violations', methods=['GET'])
@require_admin
def get_violations():
    # Paginated violation listing for admin review
    violations = SecurityViolation.query.order_by(
        SecurityViolation.timestamp.desc()
    ).paginate(page=page, per_page=per_page)
    
    return jsonify({
        'violations': [v.to_dict() for v in violations.items],
        'total': violations.total,
        'pages': violations.pages
    })
```

**User Muting System:**
```python
@chat_manage_bp.route('/api/admin/mute-user', methods=['POST'])
@require_admin
@CSRFProtection.require_csrf_token
def mute_user():
    # Per-room user muting with optional duration
    mute = MutedUser(
        user_id=user_id,
        user_name=user_name,
        room_id=room_id,
        muted_until=muted_until,  # None = permanent
        reason=reason,
        muted_by_admin=admin_username
    )
```

### 2. Room Deletion (`chat.py:875-972`)

**Cascade Deletion Process:**
```python
@chat_bp.route('/api/chat/<room_id>/delete', methods=['DELETE'])
@require_login
@CSRFProtection.require_csrf_token
def delete_chat_room(room_id):
    # 1. Delete uploaded files
    file_ids = db.session.query(UploadedFile.id).join(Message).filter(
        Message.room_id == room_id
    ).all()
    UploadedFile.query.filter(UploadedFile.id.in_(file_ids)).delete()
    
    # 2. Delete security violations
    SecurityViolation.query.filter_by(room_id=room_id).delete()
    
    # 3. Delete muted user records
    MutedUser.query.filter_by(room_id=room_id).delete()
    
    # 4. Delete messages
    Message.query.filter_by(room_id=room_id).delete()
    
    # 5. Delete room
    db.session.delete(room)
    db.session.commit()
```

---

## Presentation Key Points

### 1. **Architecture Highlights**
- **"I built a secure, multi-room chat application with integrated rewards system"**
- **Database Design**: 6 interconnected models handling chat, security, and rewards
- **Real-time Communication**: Flask-SocketIO for instant messaging
- **Security-First Approach**: Custom security framework with 10+ protection layers

### 2. **Core Functionality Demo Points**
- **Chat System**: "Users can create rooms, send messages, upload files with virus scanning"
- **Security Features**: "Every file is scanned with VirusTotal, URLs are checked for malware"
- **Room Isolation**: "Users can only access files from rooms they're actively viewing"
- **Rewards Integration**: "Users earn points for participation and redeem real rewards"

### 3. **Security Implementation**
- **"I implemented comprehensive security covering the OWASP Top 10 vulnerabilities"**
- **Input Validation**: All user inputs sanitized and validated
- **CSRF Protection**: Cryptographically secure tokens for state-changing operations
- **Rate Limiting**: DoS protection with sliding window algorithm
- **Access Control**: Participation-based file access with referer validation

### 4. **Technical Achievements**
- **File Upload Security**: "Every uploaded file is virus-scanned before storage"
- **Chat Isolation**: "Implemented strict room-based access control preventing data leakage"
- **Admin Tools**: "Built comprehensive admin dashboard for violation management"
- **Database Integration**: "Used MySQL with proper foreign keys and cascade operations"

### 5. **Code Quality Points**
- **Error Handling**: Comprehensive exception handling with security logging
- **Documentation**: Detailed code comments and security documentation
- **Modularity**: Separated concerns with blueprints and utility modules
- **Scalability**: Database-optimized queries and efficient data structures

### 6. **Business Logic**
- **User Experience**: "New users automatically get 950 points to start"
- **Reward System**: "Stock management, transaction integrity, location-based collection"
- **Moderation**: "Per-room muting system with temporary/permanent options"
- **Audit Trail**: "All security events logged for compliance and monitoring"

### 7. **Demonstration Flow**
1. **Show Room Creation**: Create a new chat room
2. **Message Exchange**: Send messages between rooms
3. **File Upload**: Upload and access files (show security scanning)
4. **Cross-Room Access**: Demonstrate access denial for wrong room
5. **Rewards System**: Show points, redeem a reward
6. **Admin Panel**: Show violation management and user muting
7. **Security Features**: Highlight CSRF tokens, rate limiting in developer tools

This guide provides you with everything you need to confidently explain your application's logic, security implementation, and demonstrate its functionality to your teacher!