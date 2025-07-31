import sqlite3

# SQLite database file
DB_FILE = 'challenges.db'

# Initialize the SQLite database and create table if not exists
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # Create the challenges table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                description TEXT,
                media TEXT,
                status TEXT DEFAULT 'On Hold',
                comments TEXT DEFAULT ''
            )
        ''')
        conn.commit()

        # Add the 'status' and 'comments' columns if they don't already exist
        try:
            cursor.execute('''
                ALTER TABLE challenges
                ADD COLUMN status TEXT DEFAULT 'On Hold';
            ''')
        except sqlite3.OperationalError:
            pass  # Ignore error if column already exists

        try:
            cursor.execute('''
                ALTER TABLE challenges
                ADD COLUMN comments TEXT DEFAULT '';
            ''')
        except sqlite3.OperationalError:
            pass  # Ignore error if column already exists

        conn.commit()

# Function to insert a challenge into the database
def insert_challenge(name, email, phone, description, media_filename):
    """Insert a new challenge into the database."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO challenges (name, email, phone, description, media)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, email, phone, description, media_filename))
        conn.commit()

# Function to update the status and comments of a challenge
def update_challenge_status(challenge_id, status, comments):
    """Update the status and comments for a challenge."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE challenges
            SET status = ?, comments = ?
            WHERE id = ?
        ''', (status, comments, challenge_id))
        conn.commit()

# Function to fetch challenges from the database
def fetch_challenges(status_filter=None):
    """Fetch challenges from the database with an optional status filter."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        if status_filter:
            cursor.execute('SELECT * FROM challenges WHERE status = ?', (status_filter,))
        else:
            cursor.execute('SELECT * FROM challenges')  # Fetch all challenges without filter
        
        challenges = cursor.fetchall()
        challenges = [{'id': row[0], 'name': row[1], 'email': row[2], 'phone': row[3], 'description': row[4], 'media': row[5], 'status': row[6], 'comments': row[7]} for row in challenges]
    return challenges

# Run the initialization function (when run directly)
if __name__ == '__main__':
    init_db()
    print("Database initialized and columns 'status' and 'comments' added successfully (if not already present).")
