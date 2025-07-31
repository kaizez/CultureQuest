from flask import Blueprint, render_template, jsonify, request
from models import db, SecurityViolation, MutedUser, ChatRoom
from datetime import datetime, timedelta

chat_manage_bp = Blueprint('chat_manage', __name__)

@chat_manage_bp.route('/chat_manage')
def chat_management_dashboard():
    """Chat management dashboard route"""
    return render_template('chat_management.html')

@chat_manage_bp.route('/api/admin/violations', methods=['GET'])
def get_violations():
    """API endpoint to get security violations with optional pagination"""
    page = request.args.get('page', type=int)
    per_page = request.args.get('per_page', type=int)
    
    violations_query = SecurityViolation.query.order_by(SecurityViolation.timestamp.desc())
    
    if page is not None and per_page is not None:
        # Paginated response
        per_page = min(per_page, 100)  # Limit per_page to prevent abuse
        violations = violations_query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        return jsonify({
            'violations': [violation.to_dict() for violation in violations.items],
            'page': page,
            'pages': violations.pages,
            'per_page': per_page,
            'total': violations.total,
            'has_next': violations.has_next,
            'has_prev': violations.has_prev
        })
    else:
        # Return all violations (for client-side pagination)
        violations = violations_query.all()
        return jsonify([violation.to_dict() for violation in violations])

@chat_manage_bp.route('/api/admin/violations/<int:violation_id>', methods=['GET'])
def get_violation_details(violation_id):
    """API endpoint to get specific violation details"""
    violation = SecurityViolation.query.get_or_404(violation_id)
    return jsonify(violation.to_dict())

@chat_manage_bp.route('/api/admin/violations/<int:violation_id>', methods=['DELETE'])
def delete_violation(violation_id):
    """API endpoint to delete a violation record"""
    violation = SecurityViolation.query.get_or_404(violation_id)
    db.session.delete(violation)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Violation deleted successfully'})

@chat_manage_bp.route('/api/admin/violations/<int:violation_id>/status', methods=['PATCH'])
def update_violation_status(violation_id):
    """API endpoint to update violation status"""
    violation = SecurityViolation.query.get_or_404(violation_id)
    data = request.get_json()
    
    if 'status' in data and data['status'] in ['pending', 'handled', 'ignored']:
        violation.status = data['status']
        db.session.commit()
        return jsonify({'success': True, 'message': 'Status updated successfully'})
    
    return jsonify({'error': 'Invalid status value'}), 400

@chat_manage_bp.route('/api/admin/mute-user', methods=['POST'])
def mute_user():
    """API endpoint to mute a user in a specific room"""
    data = request.get_json()
    
    if not data or 'user_name' not in data or 'room_id' not in data:
        return jsonify({'error': 'user_name and room_id are required'}), 400
    
    user_name = data['user_name'].strip()
    room_id = data['room_id']
    duration_hours = data.get('duration_hours', None)  # None for permanent mute
    reason = data.get('reason', 'Security violation')
    
    # Validate room exists
    room = ChatRoom.query.get(room_id)
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    try:
        # Check if user is already muted in this room
        existing_mute = MutedUser.query.filter_by(
            user_name=user_name, 
            room_id=room_id, 
            is_active=True
        ).first()
        
        if existing_mute and existing_mute.is_muted():
            return jsonify({'error': 'User is already muted in this room'}), 400
        
        # Clean up any old inactive mutes for this user/room combination
        old_mutes = MutedUser.query.filter_by(
            user_name=user_name,
            room_id=room_id,
            is_active=False
        ).all()
        
        for old_mute in old_mutes:
            db.session.delete(old_mute)
        
        if old_mutes:
            db.session.commit()
        
        # Calculate mute expiration
        muted_until = None
        if duration_hours:
            muted_until = datetime.utcnow() + timedelta(hours=duration_hours)
        
        # Create mute record
        mute = MutedUser(
            user_name=user_name,
            room_id=room_id,
            muted_until=muted_until,
            reason=reason,
            muted_by_admin='Admin'  # Will be updated when auth is implemented
        )
        
        db.session.add(mute)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'User {user_name} muted in room {room.name}',
            'mute': mute.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error muting user: {e}")
        return jsonify({'error': 'Failed to mute user'}), 500

@chat_manage_bp.route('/api/admin/unmute-user', methods=['POST'])
def unmute_user():
    """API endpoint to unmute a user in a specific room"""
    data = request.get_json()
    
    if not data or 'user_name' not in data or 'room_id' not in data:
        return jsonify({'error': 'user_name and room_id are required'}), 400
    
    user_name = data['user_name'].strip()
    room_id = data['room_id']
    
    try:
        # Find active mute
        mute = MutedUser.query.filter_by(
            user_name=user_name,
            room_id=room_id,
            is_active=True
        ).first()
        
        if not mute:
            return jsonify({'error': 'User is not muted in this room'}), 404
        
        # Delete the mute record instead of deactivating
        db.session.delete(mute)
        db.session.commit()
        
        room = ChatRoom.query.get(room_id)
        return jsonify({
            'success': True, 
            'message': f'User {user_name} unmuted in room {room.name if room else room_id}'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error unmuting user: {e}")
        return jsonify({'error': 'Failed to unmute user'}), 500

@chat_manage_bp.route('/api/admin/muted-users', methods=['GET'])
def get_muted_users():
    """API endpoint to get all muted users"""
    muted_users = MutedUser.query.filter_by(is_active=True).order_by(MutedUser.muted_at.desc()).all()
    return jsonify([mute.to_dict() for mute in muted_users])