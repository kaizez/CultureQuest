#!/usr/bin/env python3
"""
MySQL Clear Script for CultureQuest User Data
This script clears all user data from the CultureQuest application tables
without dropping the schema or affecting other users' data in the shared database.
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

def clear_user_data():
    """Clear all CultureQuest user data from database tables"""
    engine = get_db_connection()
    
    try:
        with engine.connect() as connection:
            # Start transaction
            trans = connection.begin()
            
            try:
                print("Starting data cleanup for CultureQuest tables...")
                
                # Clear data in order (respecting foreign key constraints)
                # 1. Messages (references chat_room and uploaded_file)
                result = connection.execute(text("DELETE FROM message"))
                print(f"Cleared {result.rowcount} messages")
                
                # 2. Security violations (references chat_room)
                result = connection.execute(text("DELETE FROM security_violation"))
                print(f"Cleared {result.rowcount} security violations")
                
                # 3. Muted users (references chat_room)
                result = connection.execute(text("DELETE FROM muted_user"))
                print(f"Cleared {result.rowcount} muted users")
                
                # 4. Uploaded files (can be cleared independently)
                result = connection.execute(text("DELETE FROM uploaded_file"))
                print(f"Cleared {result.rowcount} uploaded files")
                
                # 5. Chat rooms (parent table)
                result = connection.execute(text("DELETE FROM chat_room"))
                print(f"Cleared {result.rowcount} chat rooms")
                
                # Reset auto-increment counters to 1
                print("\nResetting auto-increment counters...")
                connection.execute(text("ALTER TABLE message AUTO_INCREMENT = 1"))
                connection.execute(text("ALTER TABLE security_violation AUTO_INCREMENT = 1"))
                connection.execute(text("ALTER TABLE muted_user AUTO_INCREMENT = 1"))
                connection.execute(text("ALTER TABLE uploaded_file AUTO_INCREMENT = 1"))
                connection.execute(text("ALTER TABLE chat_room AUTO_INCREMENT = 1"))
                print("Auto-increment counters reset")
                
                # Commit transaction
                trans.commit()
                print("\n✅ Successfully cleared all CultureQuest user data")
                print("Note: Database schema and structure remain intact")
                
            except Exception as e:
                # Rollback on error
                trans.rollback()
                print(f"\n❌ Error during data cleanup: {e}")
                print("Transaction rolled back - no data was modified")
                sys.exit(1)
                
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        sys.exit(1)

def confirm_action():
    """Ask user to confirm the destructive action"""
    print("⚠️  WARNING: This will permanently delete ALL CultureQuest user data!")
    print("This includes:")
    print("- All chat messages")
    print("- All uploaded files")
    print("- All chat rooms")
    print("- All security violations")
    print("- All muted users")
    print("\nThe database schema will remain intact.")
    print("This action CANNOT be undone!")
    
    response = input("\nAre you sure you want to proceed? Type 'YES' to confirm: ")
    
    if response != 'YES':
        print("Operation cancelled.")
        sys.exit(0)

if __name__ == "__main__":
    print("CultureQuest Database Clear Script")
    print("=" * 40)
    
    # Confirm the action
    confirm_action()
    
    # Clear the data
    clear_user_data()
    
    print("\nOperation completed successfully!")