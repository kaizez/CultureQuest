#!/usr/bin/env python3
"""
Safe fix for uploaded_file table structure - handles foreign keys properly
"""

import os
import sys
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_db_connection():
    """Create database connection from environment variables"""
    db_host = os.environ.get('DB_HOST')
    db_port = os.environ.get('DB_PORT')
    db_user = os.environ.get('DB_USER')
    db_password = os.environ.get('DB_PASSWORD')
    db_name = os.environ.get('DB_NAME')
    
    if not all([db_host, db_port, db_user, db_password, db_name]):
        print("Error: Missing database connection parameters in .env file")
        sys.exit(1)
    
    connection_string = f'mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
    return create_engine(connection_string)

def fix_file_table_safe():
    """Safely fix the uploaded_file table structure"""
    engine = get_db_connection()
    
    try:
        with engine.connect() as connection:
            # Start transaction
            trans = connection.begin()
            
            try:
                print("Safely fixing uploaded_file table structure...")
                
                # 1. First, remove the foreign key constraint
                print("Step 1: Removing foreign key constraints...")
                
                # Find and drop foreign key constraint
                fk_query = """
                SELECT CONSTRAINT_NAME 
                FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
                WHERE TABLE_SCHEMA = :db_name 
                AND TABLE_NAME = 'message' 
                AND COLUMN_NAME = 'file_id' 
                AND REFERENCED_TABLE_NAME IS NOT NULL
                """
                
                result = connection.execute(text(fk_query), {"db_name": os.environ.get('DB_NAME')})
                fk_constraints = result.fetchall()
                
                for constraint in fk_constraints:
                    constraint_name = constraint[0]
                    drop_fk_sql = f"ALTER TABLE message DROP FOREIGN KEY {constraint_name}"
                    connection.execute(text(drop_fk_sql))
                    print(f"✅ Dropped foreign key constraint: {constraint_name}")
                
                # 2. Set any existing file_id values to NULL to avoid issues
                connection.execute(text("UPDATE message SET file_id = NULL WHERE file_id IS NOT NULL"))
                print("✅ Cleared existing file_id references")
                
                # 3. Drop the uploaded_file table
                connection.execute(text("DROP TABLE IF EXISTS uploaded_file"))
                print("✅ Dropped uploaded_file table")
                
                # 4. Create new uploaded_file table with proper LONGBLOB
                create_table_sql = """
                CREATE TABLE uploaded_file (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    original_filename VARCHAR(255) NOT NULL,
                    file_data LONGBLOB NOT NULL,
                    file_size BIGINT NOT NULL,
                    mime_type VARCHAR(100) NOT NULL,
                    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    scan_info TEXT
                ) ENGINE=InnoDB 
                DEFAULT CHARSET=utf8mb4 
                COLLATE=utf8mb4_unicode_ci
                """
                
                connection.execute(text(create_table_sql))
                print("✅ Created new uploaded_file table with LONGBLOB support")
                
                # 5. Add the foreign key constraint back
                add_fk_sql = """
                ALTER TABLE message 
                ADD CONSTRAINT fk_message_uploaded_file 
                FOREIGN KEY (file_id) REFERENCES uploaded_file(id) ON DELETE SET NULL
                """
                
                connection.execute(text(add_fk_sql))
                print("✅ Added foreign key constraint back")
                
                # 6. Try to update MySQL settings (may require admin privileges)
                try:
                    connection.execute(text("SET GLOBAL max_allowed_packet=1073741824"))
                    print("✅ Updated MySQL packet size for large files")
                except Exception as e:
                    print(f"⚠️  Could not update packet size (requires admin privileges): {e}")
                    print("   You may need to manually set max_allowed_packet=1G in MySQL config")
                
                # Commit transaction
                trans.commit()
                print("\n✅ Table structure fixed successfully!")
                print("You can now upload larger files (up to LONGBLOB limit)")
                print("\nIf you still get packet size errors, you may need to:")
                print("1. Add 'max_allowed_packet=1G' to your MySQL config file")
                print("2. Restart MySQL service")
                print("3. Or ask your database administrator to increase the packet size")
                
            except Exception as e:
                # Rollback on error
                trans.rollback()
                print(f"\n❌ Fix failed: {e}")
                sys.exit(1)
                
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        sys.exit(1)

def confirm_action():
    """Ask user to confirm the action"""
    print("⚠️  WARNING: This will recreate the uploaded_file table!")
    print("Any existing files stored in the database will be LOST!")
    print("Existing message file references will be cleared.")
    
    response = input("\nAre you sure you want to proceed? Type 'YES' to confirm: ")
    
    if response != 'YES':
        print("Operation cancelled.")
        sys.exit(0)

if __name__ == "__main__":
    print("Safe Fix for uploaded_file Table Structure")
    print("=" * 45)
    
    # Confirm the action
    confirm_action()
    
    # Fix the table
    fix_file_table_safe()
    
    print("\nOperation completed successfully!")