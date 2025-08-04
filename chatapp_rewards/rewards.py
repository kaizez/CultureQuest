import os
import uuid
import json as json_module
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from werkzeug.utils import secure_filename
from models import db, UserPoints, RewardItem, RewardRedemption, UploadedFile, RewardOrder
from datetime import datetime, date
from chat import scan_file_with_virustotal, allowed_file
from auth_utils import require_login, require_admin, get_current_user, get_user_id, get_username
from security import (
    SecurityMiddleware, InputValidator, CSRFProtection, RateLimiter,
    SecurityViolation as SecViolation, validate_and_sanitize_input,
    log_security_event, SECURITY_CONFIG
)
from carpark_utils import find_nearest_carpark

rewards_bp = Blueprint('rewards', __name__)

# Google Maps API Key - In production, store this in environment variables
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY', 'YOUR_GOOGLE_MAPS_API_KEY_HERE')

def get_current_user_with_id():
    """Get current user info with proper user_id handling for admin users"""
    current_user = get_current_user()
    user_id = current_user['user_id']
    username = current_user['username']
    
    # Handle admin users who might not have a proper user_id
    if not user_id and current_user.get('is_admin'):
        user_id = '00000000-0000-0000-0000-000000000000'  # 36 chars admin UUID
    
    return user_id, username, current_user

def get_or_create_user_points(user_id, username):
    """Get user points or create new user with 950 default points"""
    user_points = UserPoints.query.filter_by(user_id=user_id).first()
    if not user_points:
        user_points = UserPoints(user_id=user_id, username=username, points=950)
        db.session.add(user_points)
        db.session.commit()
    return user_points

@rewards_bp.route('/rewards')
@require_login
def rewards_page():
    """Display the rewards page"""
    user_id, username, current_user = get_current_user_with_id()
    
    # Get user points
    user_points = get_or_create_user_points(user_id, username)
    
    # Get all active reward items
    reward_items = RewardItem.query.filter_by(is_active=True).all()
    
    # Get user's reward order history (claimed rewards)
    user_reward_orders = RewardOrder.query.filter_by(user_id=user_id).order_by(RewardOrder.created_at.desc()).all()
    
    # Get user's redemption history (old system compatibility)
    user_redemptions = RewardRedemption.query.filter_by(username=username).order_by(RewardRedemption.redeemed_at.desc()).all()
    
    return render_template('rewards.html', 
                         username=username, 
                         user_points=user_points.points,
                         reward_items=reward_items,
                         user_reward_orders=user_reward_orders,
                         user_redemptions=user_redemptions,
                         google_maps_api_key=GOOGLE_MAPS_API_KEY)

@rewards_bp.route('/rewards/redeem', methods=['POST'])
@require_login
@RateLimiter.rate_limit(limit_per_minute=30)
@CSRFProtection.require_csrf_token
def redeem_reward():
    """Handle reward redemption"""
    try:
        data = request.get_json()
        if not data:
            raise SecViolation("Invalid JSON data", "INVALID_INPUT")
        
        # Validate reward_id
        reward_id = data.get('reward_id')
        if not reward_id:
            raise SecViolation("Missing reward_id", "INVALID_INPUT")
        
        reward_id = InputValidator.validate_integer(
            reward_id, min_value=1, max_value=999999, field_name="reward_id"
        )
        
        # Get current user from session
        user_id, username, current_user = get_current_user_with_id()
        
        # Get user points
        user_points = get_or_create_user_points(user_id, username)
        
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
        
        # Log redemption attempt
        log_security_event(
            "REWARD_REDEMPTION_ATTEMPT",
            f"User {username} attempting to redeem reward {reward_item.name}",
            "INFO"
        )
        
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
        
        log_security_event(
            "REWARD_REDEEMED",
            f"User {username} successfully redeemed {reward_item.name}",
            "INFO"
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully redeemed {reward_item.name}!',
            'remaining_points': user_points.points,
            'remaining_stock': reward_item.stock
        })
        
    except SecViolation as e:
        log_security_event("REWARD_REDEEM_VIOLATION", f"Security violation: {e.message}", "WARNING")
        return jsonify({'error': 'Invalid request data'}), 400
    except Exception as e:
        db.session.rollback()
        log_security_event("REWARD_REDEEM_ERROR", f"Redemption error: {str(e)}", "ERROR")
        return jsonify({'error': 'Failed to process redemption'}), 500

@rewards_bp.route('/rewards/claim', methods=['POST'])
@require_login
@RateLimiter.rate_limit(limit_per_minute=30)
@CSRFProtection.require_csrf_token
def claim_reward():
    """Handle new reward claiming flow with date/address selection"""
    try:
        data = request.get_json()
        if not data:
            raise SecViolation("Invalid JSON data", "INVALID_INPUT")
        
        # Validate reward_id
        reward_id = data.get('reward_id')
        if not reward_id:
            raise SecViolation("Missing reward_id", "INVALID_INPUT")
        
        reward_id = InputValidator.validate_integer(
            reward_id, min_value=1, max_value=999999, field_name="reward_id"
        )
        
        # Validate collection_date
        collection_date_str = data.get('collection_date')
        if not collection_date_str:
            raise SecViolation("Missing collection_date", "INVALID_INPUT")
        
        try:
            collection_date = datetime.strptime(collection_date_str, '%Y-%m-%d').date()
            if collection_date < date.today():
                return jsonify({'error': 'Collection date cannot be in the past'}), 400
        except ValueError:
            raise SecViolation("Invalid collection_date format", "INVALID_INPUT")
        
        # Validate address
        address = data.get('address')
        if not address:
            raise SecViolation("Missing address", "INVALID_INPUT")
        
        address = InputValidator.validate_string(
            address, max_length=500, min_length=5, field_name="address"
        )
        address = InputValidator.sanitize_html(address)
        
        # Validate coordinates (optional)
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        # Get current user from session
        user_id, username, current_user = get_current_user_with_id()
        
        # Get user points
        user_points = get_or_create_user_points(user_id, username)
        
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
        
        # Find nearest collection point if coordinates are provided
        nearest_collection_point = None
        if latitude and longitude:
            try:
                latitude = float(latitude)
                longitude = float(longitude)
                nearest_collection_point = find_nearest_carpark(latitude, longitude)  # Uses legacy function for compatibility
            except (ValueError, TypeError) as e:
                log_security_event(
                    "REWARD_CLAIM_INVALID_COORDS",
                    f"Invalid coordinates provided: {e}",
                    "WARNING"
                )
        
        # Generate unique order ID
        order_id = datetime.now().strftime('%Y%m%d%H%M%S') + str(uuid.uuid4())[:8]
        
        # Create reward order
        reward_order = RewardOrder(
            order_id=order_id,
            user_id=user_id,
            username=username,
            reward_item_id=reward_id,
            collection_date=collection_date,
            customer_address=address,
            customer_latitude=latitude if latitude else None,
            customer_longitude=longitude if longitude else None,
            points_spent=reward_item.cost
        )
        
        # Add collection point information if found
        if nearest_collection_point:
            reward_order.assigned_carpark_name = nearest_collection_point['name']
            reward_order.assigned_carpark_address = nearest_collection_point['address']
            reward_order.assigned_carpark_latitude = nearest_collection_point['coordinates']['lat']
            reward_order.assigned_carpark_longitude = nearest_collection_point['coordinates']['lng']
            reward_order.carpark_distance = nearest_collection_point['distance']
        
        # Log claim attempt
        log_security_event(
            "REWARD_CLAIM_ATTEMPT",
            f"User {username} attempting to claim reward {reward_item.name} for {collection_date}",
            "INFO"
        )
        
        # Deduct points from user
        user_points.points -= reward_item.cost
        user_points.updated_at = datetime.utcnow()
        
        # Reduce stock
        reward_item.stock -= 1
        reward_item.updated_at = datetime.utcnow()
        
        # Create redemption record for tracking
        redemption = RewardRedemption(
            username=username,
            reward_item_id=reward_id,
            points_spent=reward_item.cost,
            status='completed'
        )
        
        # Save all records
        db.session.add(reward_order)
        db.session.add(redemption)
        db.session.commit()
        
        log_security_event(
            "REWARD_CLAIMED",
            f"User {username} successfully claimed {reward_item.name} for collection on {collection_date}",
            "INFO"
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully claimed {reward_item.name}!',
            'order_id': order_id,
            'collection_date': collection_date_str,
            'remaining_points': user_points.points,
            'remaining_stock': reward_item.stock,
            'nearest_collection_point': nearest_collection_point
        })
        
    except SecViolation as e:
        log_security_event("REWARD_CLAIM_VIOLATION", f"Security violation: {e.message}", "WARNING")
        return jsonify({'error': 'Invalid request data'}), 400
    except Exception as e:
        db.session.rollback()
        log_security_event("REWARD_CLAIM_ERROR", f"Claim error: {str(e)}", "ERROR")
        return jsonify({'error': 'Failed to process claim'}), 500

@rewards_bp.route('/rewards/confirmation/<order_id>')
@require_login
def reward_confirmation(order_id):
    """Display reward collection confirmation page"""
    try:
        current_user = get_current_user()
        user_id = current_user['user_id']
        
        # Get the reward order
        reward_order = RewardOrder.query.filter_by(
            order_id=order_id, 
            user_id=user_id
        ).first()
        
        if not reward_order:
            flash("Order not found", "error")
            return redirect(url_for('rewards.rewards_page'))
        
        return render_template('reward_confirmation.html', 
                             order=reward_order,
                             username=current_user['username'],
                             google_maps_api_key=GOOGLE_MAPS_API_KEY)
        
    except Exception as e:
        log_security_event("REWARD_CONFIRMATION_ERROR", f"Confirmation error: {str(e)}", "ERROR")
        flash("Error loading confirmation page", "error")
        return redirect(url_for('rewards.rewards_page'))

@rewards_bp.route('/rewards/admin')
@require_admin
def rewards_admin():
    """Display the rewards admin page"""
    current_user = get_current_user()
    username = current_user['username']
    
    # Get all reward items
    reward_items = RewardItem.query.all()
    
    # Get all users and their points
    user_points = UserPoints.query.all()
    
    # Get recent redemptions
    recent_redemptions = RewardRedemption.query.order_by(RewardRedemption.redeemed_at.desc()).limit(10).all()
    
    # Get recent reward orders
    recent_orders = RewardOrder.query.order_by(RewardOrder.created_at.desc()).limit(10).all()
    
    return render_template('rewards_admin.html',
                         username=username,
                         reward_items=reward_items,
                         user_points=user_points,
                         recent_redemptions=recent_redemptions,
                         recent_orders=recent_orders)

@rewards_bp.route('/rewards/admin/add_item', methods=['POST'])
@require_admin
@RateLimiter.rate_limit(limit_per_minute=10)
@CSRFProtection.require_csrf_token
def add_reward_item():
    """Add a new reward item with image upload"""
    try:
        # Validate form data
        name = request.form.get('name')
        description = request.form.get('description', '')
        cost = request.form.get('cost')
        stock = request.form.get('stock', 0)
        
        # Validate and sanitize inputs
        name = InputValidator.validate_string(name, max_length=100, min_length=1, field_name="name")
        name = InputValidator.sanitize_html(name)
        
        if description:
            description = InputValidator.validate_string(description, max_length=1000, field_name="description")
            description = InputValidator.sanitize_html(description)
        
        cost = InputValidator.validate_integer(cost, min_value=1, max_value=999999, field_name="cost")
        stock = InputValidator.validate_integer(stock, min_value=0, max_value=999999, field_name="stock")
        
        # Handle image upload
        image_url = ''
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                # Validate file upload with security checks
                try:
                    file_info = InputValidator.validate_file_upload(file, SECURITY_CONFIG['MAX_FILE_SIZE'])
                    
                    # Additional check for image files only
                    if file_info['extension'] not in {'png', 'jpg', 'jpeg', 'gif'}:
                        raise SecViolation("Only image files are allowed for reward items", "INVALID_FILE_TYPE")
                        
                except SecViolation as e:
                    log_security_event(
                        "REWARD_IMAGE_UPLOAD_VIOLATION",
                        f"Image upload violation: {e.message}",
                        "WARNING"
                    )
                    return jsonify({'error': str(e)}), 400
                
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
        
    except SecViolation as e:
        log_security_event("REWARD_ADD_VIOLATION", f"Security violation: {e.message}", "WARNING")
        return jsonify({'error': 'Invalid input data'}), 400
    except Exception as e:
        db.session.rollback()
        log_security_event("REWARD_ADD_ERROR", f"Add reward item error: {str(e)}", "ERROR")
        return jsonify({'error': 'Failed to add reward item'}), 500

@rewards_bp.route('/rewards/admin/update_stock', methods=['POST'])
@require_admin
@RateLimiter.rate_limit(limit_per_minute=30)
@CSRFProtection.require_csrf_token
def update_stock():
    """Update stock for a reward item"""
    try:
        data = request.get_json()
        if not data:
            raise SecViolation("Invalid JSON data", "INVALID_INPUT")
        
        reward_id = InputValidator.validate_integer(
            data.get('reward_id'), min_value=1, max_value=999999, field_name="reward_id"
        )
        new_stock = InputValidator.validate_integer(
            data.get('stock'), min_value=0, max_value=999999, field_name="stock"
        )
        
        reward_item = RewardItem.query.get(reward_id)
        if not reward_item:
            return jsonify({'error': 'Reward item not found'}), 404
        
        reward_item.stock = new_stock
        reward_item.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        log_security_event(
            "REWARD_STOCK_UPDATED",
            f"Stock updated for reward {reward_item.name}: {new_stock}",
            "INFO"
        )
        
        return jsonify({'success': True, 'message': 'Stock updated successfully'})
        
    except SecViolation as e:
        log_security_event("STOCK_UPDATE_VIOLATION", f"Security violation: {e.message}", "WARNING")
        return jsonify({'error': 'Invalid input data'}), 400
    except Exception as e:
        db.session.rollback()
        log_security_event("STOCK_UPDATE_ERROR", f"Stock update error: {str(e)}", "ERROR")
        return jsonify({'error': 'Failed to update stock'}), 500

@rewards_bp.route('/rewards/admin/update_points', methods=['POST'])
@require_admin
def update_user_points():
    """Update points for a user"""
    data = request.get_json()
    user_id = data.get('user_id')
    username = data.get('username')  # For backwards compatibility
    new_points = data.get('points')
    
    try:
        if user_id:
            # Look up by user_id (preferred method)
            user_points = UserPoints.query.filter_by(user_id=user_id).first()
            if not user_points:
                return jsonify({'error': 'User not found'}), 404
        else:
            # Fallback to username for backwards compatibility
            user_points = UserPoints.query.filter_by(username=username).first()
            if not user_points:
                return jsonify({'error': 'User not found'}), 404
        
        user_points.points = int(new_points)
        user_points.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User points updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update user points'}), 500

@rewards_bp.route('/rewards/admin/delete_item', methods=['POST'])
@require_admin
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

@rewards_bp.route('/rewards/admin/update_order_status', methods=['POST'])
@require_admin
@RateLimiter.rate_limit(limit_per_minute=30)
@CSRFProtection.require_csrf_token
def update_order_status():
    """Update status of a reward order"""
    try:
        data = request.get_json()
        if not data:
            raise SecViolation("Invalid JSON data", "INVALID_INPUT")
        
        order_id = data.get('order_id')
        new_status = data.get('status')
        
        if not order_id or not new_status:
            raise SecViolation("Missing order_id or status", "INVALID_INPUT")
        
        # Validate order_id
        order_id = InputValidator.validate_string(
            order_id, max_length=50, min_length=10, field_name="order_id"
        )
        
        # Validate status
        valid_statuses = ['pending', 'confirmed', 'collected', 'cancelled']
        if new_status not in valid_statuses:
            raise SecViolation(f"Invalid status. Must be one of: {', '.join(valid_statuses)}", "INVALID_INPUT")
        
        # Get the reward order
        reward_order = RewardOrder.query.filter_by(order_id=order_id).first()
        if not reward_order:
            return jsonify({'error': 'Reward order not found'}), 404
        
        old_status = reward_order.status
        reward_order.status = new_status
        reward_order.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        log_security_event(
            "REWARD_ORDER_STATUS_UPDATED",
            f"Admin updated order {order_id} status from {old_status} to {new_status}",
            "INFO"
        )
        
        return jsonify({
            'success': True,
            'message': f'Order status updated to {new_status.title()}',
            'order_id': order_id,
            'old_status': old_status,
            'new_status': new_status,
            'updated_at': reward_order.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except SecViolation as e:
        log_security_event("ORDER_STATUS_UPDATE_VIOLATION", f"Security violation: {e.message}", "WARNING")
        return jsonify({'error': 'Invalid request data'}), 400
    except Exception as e:
        db.session.rollback()
        log_security_event("ORDER_STATUS_UPDATE_ERROR", f"Status update error: {str(e)}", "ERROR")
        return jsonify({'error': 'Failed to update order status'}), 500

@rewards_bp.route('/rewards/admin/order_details/<order_id>')
@require_admin
def admin_order_details(order_id):
    """Get detailed information about a specific reward order for admin"""
    try:
        current_user = get_current_user()
        username = current_user['username']
        
        # Get the reward order
        reward_order = RewardOrder.query.filter_by(order_id=order_id).first()
        
        if not reward_order:
            flash("Order not found", "error")
            return redirect(url_for('rewards.rewards_admin'))
        
        return render_template('admin_order_details.html',
                             username=username,
                             order=reward_order,
                             google_maps_api_key=GOOGLE_MAPS_API_KEY)
        
    except Exception as e:
        log_security_event("ADMIN_ORDER_DETAILS_ERROR", f"Order details error: {str(e)}", "ERROR")
        flash("Error loading order details", "error")
        return redirect(url_for('rewards.rewards_admin'))