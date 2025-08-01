# CultureQuest MySQL Migration Guide

## Overview

This guide helps you migrate from JSON file storage to MySQL database using SQLAlchemy.

## Database Configuration

**Database URL:** `mysql://Pleaseusesecurely:Pleasestopleakingenv@staging.nypdsf.me:8080/culturequest`

## Migration Steps

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run Automated Setup (Recommended)

```bash
python setup_mysql.py
```

This will:
- Install all required dependencies
- Test database connection
- Create database tables
- Migrate existing JSON data to MySQL
- Backup original JSON files

### 3. Manual Migration (Alternative)

If you prefer manual steps:

```bash
# Test database connection first
python test_database.py

# Run migration
python migrate_to_mysql.py
```

### 4. Verify Migration

```bash
# Test the application
python app.py

# Test database operations
python test_database.py
```

## Database Schema

### Users Table
- `id` (VARCHAR(36), Primary Key) - UUID
- `username` (VARCHAR(50), Unique, Indexed)
- `email` (VARCHAR(120), Unique, Indexed)
- `password` (VARCHAR(255)) - Hashed password (nullable for Google users)
- `profile_picture` (TEXT) - Profile picture URL/path
- `occupation` (VARCHAR(100))
- `birthday` (DATE)
- `labels` (TEXT)
- `online_start_time` (VARCHAR(10))
- `online_end_time` (VARCHAR(10))
- `is_google_user` (BOOLEAN)
- `email_verified` (BOOLEAN)
- `created_at` (DATETIME)
- `last_login` (DATETIME)

### Reset Codes Table
- `id` (INT, Primary Key, Auto Increment)
- `email` (VARCHAR(120), Indexed)
- `code` (VARCHAR(6))
- `expires` (DATETIME)
- `attempts` (INT)
- `created_at` (DATETIME)

### Verification Codes Table
- `id` (INT, Primary Key, Auto Increment)
- `email` (VARCHAR(120), Indexed)
- `code` (VARCHAR(6))
- `expires` (DATETIME)
- `attempts` (INT)
- `user_data` (TEXT) - JSON string of pending user data
- `created_at` (DATETIME)

## Key Changes

### Files Modified
- `app.py` - Added SQLAlchemy configuration
- `login.py` - Replaced JSON operations with database operations
- `requirements.txt` - Added database dependencies

### New Files Created
- `database.py` - Database initialization
- `models.py` - SQLAlchemy models
- `db_operations.py` - Database CRUD operations
- `migrate_to_mysql.py` - Migration script
- `setup_mysql.py` - Automated setup script
- `test_database.py` - Database testing script

### Backward Compatibility
All existing API endpoints and functionality remain the same. The change is purely in the storage backend.

## Database Connection Features

- **Connection Pooling** - Automatic connection pool management
- **Connection Recovery** - Auto-reconnection on connection loss
- **Query Optimization** - Indexed lookups for usernames and emails
- **Data Integrity** - Foreign key constraints and transactions

## Security Improvements

- **SQL Injection Protection** - SQLAlchemy ORM prevents SQL injection
- **Password Hashing** - Continues to use Werkzeug's secure password hashing
- **Session Management** - Improved session handling with database storage
- **Code Expiration** - Automatic cleanup of expired verification/reset codes

## Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Verify MySQL server is running
   - Check database credentials
   - Ensure database `culturequest` exists

2. **Import Errors**
   - Run `pip install -r requirements.txt`
   - Check Python version compatibility

3. **Migration Errors**
   - Backup JSON files are created automatically
   - Check console output for specific errors
   - Verify database permissions

### Testing

Run comprehensive tests:
```bash
python test_database.py
```

### Rollback Plan

If migration fails:
1. JSON backup files are stored in `json_backup/` directory
2. Restore original JSON files
3. Comment out database imports in `login.py`
4. Restore original JSON-based functions

## Performance Benefits

- **Faster Queries** - Database indexing vs file scanning
- **Concurrent Access** - Multiple users can access simultaneously
- **Scalability** - Database can handle thousands of users
- **Data Integrity** - ACID transactions ensure data consistency
- **Automatic Cleanup** - Expired codes are automatically removed

## Next Steps

After successful migration:
1. Monitor application performance
2. Set up database backups
3. Consider removing JSON files after testing
4. Update deployment scripts to include database setup

## Support

If you encounter issues:
1. Check the console output for error messages
2. Verify database connection settings
3. Run the test script to isolate issues
4. Check MySQL server logs for connection issues