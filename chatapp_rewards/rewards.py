import os
import uuid
import json as json_module
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from werkzeug.utils import secure_filename
from models import db, UserPoints, RewardItem, RewardRedemption, UploadedFile
from datetime import datetime
from chat import scan_file_with_virustotal, allowed_file

rewards_bp = Blueprint('rewards', __name__)

def get_or_create_user_points(username):
    """Get user points or create new user with 950 default points"""
    user_points = UserPoints.query.filter_by(username=username).first()
    if not user_points:
        user_points = UserPoints(username=username, points=950)
        db.session.add(user_points)
        db.session.commit()
    return user_points

@rewards_bp.route('/rewards')
def rewards_page():
    """Display the rewards page"""
    username = request.args.get('username', 'User')
    
    # Get user points
    user_points = get_or_create_user_points(username)
    
    # Get all active reward items
    reward_items = RewardItem.query.filter_by(is_active=True).all()
    
    return render_template('rewards.html', 
                         username=username, 
                         user_points=user_points.points,
                         reward_items=reward_items)

@rewards_bp.route('/rewards/redeem', methods=['POST'])
def redeem_reward():
    """Handle reward redemption"""
    data = request.get_json()
    username = data.get('username')
    reward_id = data.get('reward_id')
    
    if not username or not reward_id:
        return jsonify({'error': 'Missing username or reward_id'}), 400
    
    # Get user points
    user_points = get_or_create_user_points(username)
    
    # Get reward item
    reward_item = RewardItem.query.get(reward_id)
    if not reward_item or not reward_item.is_active:
        return jsonify({'error': 'Reward not found or inactive'}), 404
    
    # Check if user has enough points
    if user_points.points < reward_item.cost:
        return jsonify({'error': 'Insufficient points'}), 400
    
    # Check stock
    if reward_item.stock <= 0:
        return jsonify({'error': 'Item out of stock'}), 400
    
    try:
        # Deduct points from user
        user_points.points -= reward_item.cost
        user_points.updated_at = datetime.utcnow()
        
        # Reduce stock
        reward_item.stock -= 1
        reward_item.updated_at = datetime.utcnow()
        
        # Create redemption record
        redemption = RewardRedemption(
            username=username,
            reward_item_id=reward_id,
            points_spent=reward_item.cost,
            status='completed'
        )
        
        db.session.add(redemption)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully redeemed {reward_item.name}!',
            'remaining_points': user_points.points,
            'remaining_stock': reward_item.stock
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to process redemption'}), 500

@rewards_bp.route('/rewards/admin')
def rewards_admin():
    """Display the rewards admin page"""
    username = request.args.get('username', 'Admin')
    
    # Get all reward items
    reward_items = RewardItem.query.all()
    
    # Get all users and their points
    user_points = UserPoints.query.all()
    
    # Get recent redemptions
    recent_redemptions = RewardRedemption.query.order_by(RewardRedemption.redeemed_at.desc()).limit(10).all()
    
    return render_template('rewards_admin.html',
                         username=username,
                         reward_items=reward_items,
                         user_points=user_points,
                         recent_redemptions=recent_redemptions)

@rewards_bp.route('/rewards/admin/add_item', methods=['POST'])
def add_reward_item():
    """Add a new reward item with image upload"""
    try:
        # Get form data
        name = request.form.get('name')
        description = request.form.get('description', '')
        cost = int(request.form.get('cost'))
        stock = int(request.form.get('stock', 0))
        
        # Handle image upload
        image_url = ''
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                if not allowed_file(file.filename):
                    return jsonify({'error': 'Invalid file type. Only images are allowed.'}), 400
                
                # Create a unique filename
                filename = str(uuid.uuid4()) + '_' + secure_filename(file.filename)
                temp_file_path = os.path.join('static/uploads', filename)
                
                # Save file temporarily
                file.save(temp_file_path)
                
                # Scan the file with VirusTotal
                is_safe, scan_result, scan_message = scan_file_with_virustotal(temp_file_path)
                
                if not is_safe:
                    # Remove the temporary file
                    os.unlink(temp_file_path)
                    return jsonify({
                        'error': f'Image upload blocked: {scan_message}',
                        'scan_details': scan_result
                    }), 400
                
                # File is safe, read it into memory and store in database
                with open(temp_file_path, 'rb') as f:
                    file_data = f.read()
                
                # Get file info
                file_size = os.path.getsize(temp_file_path)
                
                # Create UploadedFile record
                uploaded_file = UploadedFile(
                    filename=filename,
                    original_filename=file.filename,
                    file_data=file_data,
                    file_size=file_size,
                    mime_type=file.content_type or 'image/jpeg',
                    scan_info=f"✅ Virus scan passed: {scan_message}" if scan_result else "⚠️ Uploaded without virus scan (API key not configured)"
                )
                
                db.session.add(uploaded_file)
                db.session.flush()  # Get the ID
                
                # Set image URL to reference the uploaded file
                image_url = f'/file/{uploaded_file.id}'
                
                # Remove the temporary file
                os.unlink(temp_file_path)
        
        # Create reward item
        reward_item = RewardItem(
            name=name,
            description=description,
            cost=cost,
            stock=stock,
            image_url=image_url,
            is_active=True
        )
        
        db.session.add(reward_item)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Reward item added successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to add reward item: {str(e)}'}), 500

@rewards_bp.route('/rewards/admin/update_stock', methods=['POST'])
def update_stock():
    """Update stock for a reward item"""
    data = request.get_json()
    reward_id = data.get('reward_id')
    new_stock = data.get('stock')
    
    try:
        reward_item = RewardItem.query.get(reward_id)
        if not reward_item:
            return jsonify({'error': 'Reward item not found'}), 404
        
        reward_item.stock = int(new_stock)
        reward_item.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Stock updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update stock'}), 500

@rewards_bp.route('/rewards/admin/update_points', methods=['POST'])
def update_user_points():
    """Update points for a user"""
    data = request.get_json()
    username = data.get('username')
    new_points = data.get('points')
    
    try:
        user_points = get_or_create_user_points(username)
        user_points.points = int(new_points)
        user_points.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User points updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update user points'}), 500

@rewards_bp.route('/rewards/admin/delete_item', methods=['POST'])
def delete_reward_item():
    """Delete a reward item permanently"""
    data = request.get_json()
    reward_id = data.get('reward_id')
    
    try:
        reward_item = RewardItem.query.get(reward_id)
        if not reward_item:
            return jsonify({'error': 'Reward item not found'}), 404
        
        # If the item has an associated image file, delete it from UploadedFile table
        if reward_item.image_url and reward_item.image_url.startswith('/file/'):
            file_id = reward_item.image_url.split('/')[-1]
            uploaded_file = UploadedFile.query.get(file_id)
            if uploaded_file:
                db.session.delete(uploaded_file)
        
        # Delete all redemption records for this item
        RewardRedemption.query.filter_by(reward_item_id=reward_id).delete()
        
        # Delete the reward item itself
        db.session.delete(reward_item)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Reward item deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete reward item'}), 500