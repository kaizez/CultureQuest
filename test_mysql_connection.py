#!/usr/bin/env python3
"""
Simple script to test MySQL connection using PyMySQL
"""

import pymysql

def test_mysql_connection():
    """Test raw MySQL connection"""
    print("Testing MySQL connection with PyMySQL...")
    
    # Database connection parameters
    host = 'staging.nypdsf.me'
    port = 8080
    user = 'SQLUser'
    password = 'Pleasestopleakingenv'
    database = 'culturequest'
    
    try:
        # Create connection
        connection = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        
        print("✅ Connected to MySQL successfully!")
        
        # Test a simple query
        with connection.cursor() as cursor:
            cursor.execute("SELECT VERSION() as version")
            result = cursor.fetchone()
            print(f"✅ MySQL version: {result['version']}")
        
        # Test database access
        with connection.cursor() as cursor:
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            print(f"✅ Database '{database}' accessible")
            if tables:
                print(f"   Existing tables: {[table[f'Tables_in_{database}'] for table in tables]}")
            else:
                print("   No tables found (this is normal for initial setup)")
        
        connection.close()
        print("✅ Connection closed successfully")
        return True
        
    except pymysql.Error as e:
        print(f"❌ MySQL Error: {e}")
        return False
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

def main():
    """Main function"""
    print("=== MySQL Connection Test ===")
    print()
    
    success = test_mysql_connection()
    
    print()
    if success:
        print("🎉 MySQL connection test passed!")
        print("You can now run: python setup_mysql.py")
    else:
        print("❌ MySQL connection test failed!")
        print()
        print("Troubleshooting steps:")
        print("1. Verify MySQL server is running on staging.nypdsf.me:8080")
        print("2. Check if database 'culturequest' exists")
        print("3. Verify credentials: User='Pleaseusesecurely', Password='Pleasestopleakingenv'")
        print("4. Check firewall/network connectivity")
        print("5. Try connecting from a MySQL client first")
    
    return success

if __name__ == '__main__':
    main()