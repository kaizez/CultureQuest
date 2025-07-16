import sqlite3
import os

DB_PATH = 'users.db'  # Path to your database

# Check if the database exists
if not os.path.exists(DB_PATH):
    print(f"Database file '{DB_PATH}' does not exist!")
else:
    # Connect to the database
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()

        # Check if the 'users' table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        table_exists = c.fetchone()

        if table_exists:
            # Fetch all users to verify the stored data
            c.execute("SELECT * FROM users")
            users = c.fetchall()

            if users:
                print(f"{'ID':<5} {'Username':<20} {'Email':<30} {'Password':<60}")
                print("="*115)
                for user in users:
                    print(f"{user[0]:<5} {user[1]:<20} {user[2]:<30} {user[3]:<60}")
            else:
                print("The 'users' table is empty.")
        else:
            print("The 'users' table does not exist in the database.")
