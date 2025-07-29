import sqlite3

# SQLite database file
DB_FILE = 'challenges.db'

# Initialize the SQLite database and create table if not exists
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                description TEXT,
                media TEXT
            )
        ''')
        conn.commit()

def insert_challenge(name, email, phone, description, media_filename):
    """Insert a new challenge into the database."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO challenges (name, email, phone, description, media)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, email, phone, description, media_filename))
        conn.commit()

def fetch_challenges():
    """Fetch all challenges from the database."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM challenges')
        challenges = cursor.fetchall()  # Fetch all challenges
        challenges = [{'id': row[0], 'name': row[1], 'email': row[2], 'phone': row[3], 'description': row[4], 'media': row[5]} for row in challenges]
    return challenges

# Run the initialization function
if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")
