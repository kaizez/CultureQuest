# CultureQuest Project Structure

## Root Directory Files

### Core Application Files
- `app.py` - Main Flask application (MySQL version)
- `login.py` - Authentication and user management
- `database.py` - Database initialization
- `models.py` - SQLAlchemy database models
- `db_operations.py` - Database CRUD operations

### Migration & Setup Files
- `migrate_to_mysql.py` - JSON to MySQL migration script
- `setup_mysql.py` - Automated setup script
- `test_database.py` - Database operations testing
- `test_mysql_connection.py` - MySQL connection testing

### Configuration Files
- `requirements.txt` - Python dependencies
- `.env.example` - Environment variables template (if exists)

### Data Files
- `users_data.json` - Original user data (backup after migration)
- `verification_codes.json` - Original verification codes (backup)
- `reset_codes.json` - Original reset codes (backup)

### Documentation
- `README.md` - Project documentation
- `MYSQL_MIGRATION.md` - Migration guide
- `INSTALL_MYSQL.md` - Installation troubleshooting
- `PROJECT_STRUCTURE.md` - This file

### Frontend Assets
- `public/` - HTML templates
- `static/` - CSS, JavaScript, images

## CultureQuest/ Directory (GitHub Repository)
- Contains your original GitHub repository
- Keep this intact for version control
- Contains older JSON-based version

## Removed Unnecessary Files
- ✅ `localhost-key.pem` - SSL certificate (not needed)
- ✅ `localhost.pem` - SSL certificate (not needed) 
- ✅ `package.json` - Node.js config (not needed for Python app)
- ✅ `static/style.css` - Duplicate of `static/css/style.css`
- ✅ `static/logo.png` - Duplicate of `static/img/logo.png`
- ✅ `static/logowithoutbackground.jpg` - Duplicate image

## Current Status
- ✅ MySQL migration files ready
- ✅ Duplicate files removed
- ✅ GitHub repository preserved
- ✅ Clean project structure

## Next Steps
1. Run MySQL migration: `python setup_mysql.py`
2. Test the application: `python app.py`
3. Update your GitHub repository with MySQL changes if desired