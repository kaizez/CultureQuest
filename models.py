# models.py

# Sample User Data for testing
users = {
    "Ayden-User": {"password": "user123", "role": "user"},
    "Ayden-Admin": {"password": "admin123", "role": "admin"}
}

# User class for Flask-Login
class User:
    def __init__(self, username, role):
        self.id = username
        self.role = role

    def get_id(self):
        return self.id
