#!/usr/bin/env python3
"""
Clear User Data Script for CultureQuest
========================================

PURPOSE:
Drops only the chatapp_rewards related database tables to allow for schema updates.
This script will NOT touch any tables outside of the chatapp_rewards module.

WHEN TO USE:
- When you see database errors like "Unknown column 'user_id'"  
- After updating the chatapp_rewards models with new columns
- When authentication integration requires database schema changes

USAGE:
1. Stop your application server
2. Run: python clear_user_data.py
3. Confirm the action by typing 'YES'
4. Restart your application server 
5. The app will automatically recreate tables with the new schema

SAFETY:
- Only affects chatapp_rewards tables (chat_room, message, user_points, etc.)
- Login system tables are NOT affected
- Challenge module tables are NOT affected
- Other application data remains intact
"""

import pymysql
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_db_connection():
    """Get database connection using environment variables"""
    try:
        # Get database connection parameters (same as used in app.py)
        db_host = os.getenv('DB_HOST')
        db_port = int(os.getenv('DB_PORT', 8080))
        db_user = os.getenv('DB_USER')
        db_password = os.getenv('DB_PASSWORD')
        db_name = os.getenv('DB_NAME')
        
        # Check if all required variables are present
        if not all([db_host, db_user, db_password, db_name]):
            missing_vars = []
            if not db_host: missing_vars.append('DB_HOST')
            if not db_user: missing_vars.append('DB_USER')
            if not db_password: missing_vars.append('DB_PASSWORD')
            if not db_name: missing_vars.append('DB_NAME')
            print(f"Missing required environment variables: {', '.join(missing_vars)}")
            print("Please check your .env file")
            return None
        
        print(f"Connecting to database: {db_user}@{db_host}:{db_port}/{db_name}")
        
        connection = pymysql.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        return connection
    except Exception as e:
        print(f"Error connecting to database: {e}")
        print("Please verify your database credentials in .env file")
        return None

def drop_chatapp_rewards_tables():
    """Drop only the tables related to chatapp_rewards module"""
    
    # Tables to drop (in order to handle foreign key constraints)
    tables_to_drop = [
        'reward_redemption',    # Has foreign key to reward_item and user_points
        'message',              # Has foreign key to uploaded_file and chat_room
        'muted_user',           # Has foreign key to chat_room
        'security_violation',   # Standalone table
        'uploaded_file',        # Has foreign key to chat_room
        'user_points',          # Standalone table
        'reward_item',          # Standalone table
        'chat_room'             # Referenced by other tables
    ]
    
    connection = get_db_connection()
    if not connection:
        print("Failed to connect to database")
        return False
    
    try:
        with connection.cursor() as cursor:
            # Disable foreign key checks temporarily
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            
            dropped_tables = []
            for table in tables_to_drop:
                try:
                    # Check if table exists first
                    cursor.execute(f"SHOW TABLES LIKE '{table}'")
                    if cursor.fetchone():
                        cursor.execute(f"DROP TABLE `{table}`")
                        dropped_tables.append(table)
                        print(f"✓ Dropped table: {table}")
                    else:
                        print(f"⚠ Table {table} does not exist, skipping")
                except Exception as e:
                    print(f"✗ Error dropping table {table}: {e}")
            
            # Re-enable foreign key checks
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            
            connection.commit()
            print(f"\n✓ Successfully dropped {len(dropped_tables)} tables")
            print("Tables dropped:", ", ".join(dropped_tables))
            
        return True
        
    except Exception as e:
        print(f"Error during table dropping: {e}")
        connection.rollback()
        return False
    finally:
        connection.close()

def confirm_action():
    """Ask user to confirm the destructive action"""
    print("=" * 60)
    print("WARNING: DESTRUCTIVE ACTION")
    print("=" * 60)
    print("This script will DROP the following chatapp_rewards tables:")
    print("- chat_room")
    print("- uploaded_file") 
    print("- message")
    print("- security_violation")
    print("- muted_user")
    print("- user_points")
    print("- reward_item")
    print("- reward_redemption")
    print("\nALL DATA in these tables will be PERMANENTLY LOST!")
    print("Tables outside of chatapp_rewards module will NOT be affected.")
    print("=" * 60)
    
    response = input("Are you sure you want to continue? (type 'YES' to confirm): ").strip()
    return response == 'YES'

def main():
    """Main function"""
    print("Clear User Data Script for CultureQuest")
    print("Targeting chatapp_rewards tables only\n")
    
    if not confirm_action():
        print("Operation cancelled by user.")
        return
    
    print("\nStarting table cleanup...")
    success = drop_chatapp_rewards_tables()
    
    if success:
        print("\n" + "=" * 60)
        print("SUCCESS: Chatapp_rewards tables have been dropped")
        print("You can now restart your application to recreate tables with the new schema")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("ERROR: Failed to complete table cleanup")
        print("Please check the error messages above")
        print("=" * 60)

if __name__ == "__main__":
    main()