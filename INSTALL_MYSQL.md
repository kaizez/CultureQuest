# MySQL Installation & Setup Guide

## Step-by-Step Installation

### 1. Install Dependencies

```bash
pip install pymysql cryptography
pip install -r requirements.txt
```

### 2. Test MySQL Connection

Before running the full setup, test the connection:

```bash
python test_mysql_connection.py
```

This will:
- Test raw MySQL connection
- Show MySQL version
- List existing tables
- Verify database access

### 3. Run Setup (if connection test passes)

```bash
python setup_mysql.py
```

## Troubleshooting

### Error: "No module named 'MySQLdb'"

**Solution:** This is fixed by installing PyMySQL:
```bash
pip install pymysql
```

The app now uses PyMySQL as a replacement for MySQLdb.

### Error: "Access denied for user"

**Possible causes:**
1. Wrong username/password
2. User doesn't have permissions
3. Database doesn't exist

**Check:**
- Username: `Pleaseusesecurely`  
- Password: `Pleasestopleakingenv`
- Database: `culturequest`
- Host: `staging.nypdsf.me:8080`

### Error: "Can't connect to MySQL server"

**Possible causes:**
1. MySQL server is down
2. Wrong host/port
3. Firewall blocking connection
4. Network connectivity issues

**Verify:**
```bash
# Test with MySQL client (if available)
mysql -h staging.nypdsf.me -P 8080 -u Pleaseusesecurely -p culturequest

# Or test with telnet
telnet staging.nypdsf.me 8080
```

### Error: "Unknown database 'culturequest'"

**Solution:** Create the database on MySQL server:
```sql
CREATE DATABASE culturequest;
```

## Manual Installation Steps

If the automated setup fails, follow these manual steps:

### 1. Install PyMySQL
```bash
pip install pymysql
```

### 2. Test Connection
```bash
python test_mysql_connection.py
```

### 3. Install All Dependencies
```bash
pip install -r requirements.txt
```

### 4. Create Database Tables
```python
from app import app, db
with app.app_context():
    db.create_all()
```

### 5. Migrate Data
```bash
python migrate_to_mysql.py
```

### 6. Test Application
```bash
python app.py
```

## Database Requirements

### MySQL Server Requirements
- MySQL 5.7+ or MySQL 8.0+
- Database: `culturequest` must exist
- User must have: SELECT, INSERT, UPDATE, DELETE, CREATE, DROP permissions

### Python Requirements
- Python 3.7+
- PyMySQL driver
- SQLAlchemy 2.0+
- Flask-SQLAlchemy 3.0+

## Connection String Format

The application uses this connection string:
```
mysql+pymysql://username:password@host:port/database
```

Current configuration:
```
mysql+pymysql://Pleaseusesecurely:Pleasestopleakingenv@staging.nypdsf.me:8080/culturequest
```

## Testing

### Test Database Connection
```bash
python test_mysql_connection.py
```

### Test Database Operations  
```bash
python test_database.py
```

### Test Full Application
```bash
python app.py
# Then visit http://127.0.0.1:5000
```

## Security Notes

- The database credentials are currently hardcoded
- Consider moving to environment variables for production
- Ensure MySQL server has proper security configuration
- Use SSL connection for production environments

## Success Indicators

✅ **Connection Test Passes**
```
✅ Connected to MySQL successfully!
✅ MySQL version: 8.0.x
✅ Database 'culturequest' accessible
```

✅ **Setup Completes Successfully**
```
✅ Dependencies installed successfully!
✅ Database connection successful!
✅ Database tables created successfully!
✅ Successfully migrated X users
🎉 Setup completed successfully!
```

## Next Steps After Successful Setup

1. Test the web application
2. Verify all authentication flows work
3. Check user registration and login
4. Test admin dashboard
5. Backup JSON files are in `json_backup/` directory