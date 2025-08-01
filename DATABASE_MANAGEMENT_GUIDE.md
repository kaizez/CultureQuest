# Database Management Guide

This guide explains when and how to use the database management scripts in your CultureQuest application.

## Scripts Overview

### 1. `fix_file_table_safe.py` - Database Structure Setup/Fix
### 2. `clear_user_data.py` - Data Cleanup

---

## When to Use `fix_file_table_safe.py`

**Purpose**: Sets up or fixes the database table structure for file storage and rewards system functionality.

### Use this script when:

✅ **First-time setup**: Setting up the application on a new database
- Creates the `uploaded_file` table with proper LONGBLOB support
- Creates rewards system tables (`user_points`, `reward_item`, `reward_redemption`)
- Adds the `file_id` column to the `message` table
- Sets up foreign key relationships

✅ **Database structure issues**: Getting errors like:
- `"Unknown column 'file_id' in 'field list'"`
- `"Table 'uploaded_file' doesn't exist"`
- `"Table 'user_points' doesn't exist"`
- `"Table 'reward_item' doesn't exist"`
- `"Data too long for column 'file_data'"`

✅ **After major database changes**: 
- If someone modified the database schema
- If you restored from an old backup
- If table structure got corrupted

### What it does:
- Removes old foreign key constraints safely
- Drops and recreates the `uploaded_file` table with LONGBLOB support
- Creates rewards system tables with proper relationships
- Adds proper foreign key relationships
- Attempts to increase MySQL packet size for large files

### Warning:
⚠️ **This will delete all stored files** in the database. Use only when necessary.

---

## When to Use `clear_user_data.py`

**Purpose**: Cleans all your application data while preserving database structure and other users' data.

### Use this script when:

✅ **Testing/Development**: 
- Need a clean slate for testing
- Want to remove test data
- Preparing for a demo

✅ **Data cleanup**: 
- Too much accumulated data
- Want to start fresh with conversations
- Clean up after security violations

✅ **Before deployment**:
- Remove development/test data before going live

### What it does:
- Deletes all reward redemptions
- Deletes all reward items
- Deletes all user points records
- Deletes all messages
- Deletes all uploaded files  
- Deletes all chat rooms
- Deletes all security violations
- Deletes all muted users
- Resets auto-increment counters
- **Preserves database structure**
- **Preserves other users' data** (if sharing database)

### Safe to use:
✅ **This preserves the database schema** - your application will continue to work normally after clearing data.

---

## Usage Examples

### Scenario 1: First-time Setup
```bash
# Step 1: Set up database structure
python3 fix_file_table_safe.py

# Step 2 (optional): Start with clean data
python3 clear_user_data.py
```

### Scenario 2: File Upload Errors
If you get errors like "Data too long for column" or "Table doesn't exist":
```bash
python3 fix_file_table_safe.py
```

### Scenario 3: Just Want to Clear Data
If your app is working but you want to remove all messages/files:
```bash
python3 clear_user_data.py
```

### Scenario 4: Complete Reset (Structure + Data)
```bash
# Step 1: Fix/recreate table structure
python3 fix_file_table_safe.py

# Step 2: Clear any remaining data
python3 clear_user_data.py
```

---

## Decision Tree

```
Do you have database structure errors?
├── YES → Use fix_file_table_safe.py
└── NO
    └── Do you just want to clear data?
        ├── YES → Use clear_user_data.py  
        └── NO → No script needed
```

---

## Important Notes

### Before Running Either Script:
1. **Backup your database** if you have important data
2. **Stop your application** to avoid conflicts
3. **Confirm you have database credentials** in your `.env` file

### After Running Scripts:
1. **Restart your application**
2. **Test file upload functionality**
3. **Verify database connections work**

### MySQL Packet Size:
If you still get "packet too large" errors after `fix_file_table_safe.py`:
1. Add `max_allowed_packet=1G` to your MySQL configuration file
2. Restart MySQL service
3. Or contact your database administrator

---

## Quick Reference

| Problem | Solution |
|---------|----------|
| "Table doesn't exist" | `fix_file_table_safe.py` |
| "Unknown column" | `fix_file_table_safe.py` |
| "Data too long" | `fix_file_table_safe.py` |
| Too much old data | `clear_user_data.py` |
| Want fresh start | `clear_user_data.py` |
| First-time setup | `fix_file_table_safe.py` then optionally `clear_user_data.py` |