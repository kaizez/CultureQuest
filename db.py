from flask_sqlalchemy import SQLAlchemy
import json
# 1. Initialize SQLAlchemy without the app object
db = SQLAlchemy(session_options={"autoflush": False})

# 2. Create a function to initialize the DB and populate data
def init_db(app):
    """Initializes the database, creates tables, and populates initial data if empty."""
    from models import Challenge, ChallengeResponse, Comment
    from utils import initial_challenges_data
    with app.app_context():
        db.create_all()

        if not Challenge.query.first():
            print("Populating database with initial challenges...")
            all_challenges_data = (
                initial_challenges_data['new_challenges'] +
                initial_challenges_data['current_challenges'] +
                initial_challenges_data['done_challenges']
            )

            for data in all_challenges_data:
                challenge = Challenge(
                    status=data.get('status'),
                    title=data['title'],
                    difficulty=data['difficulty'],
                    description=data['description'],
                    duration=data.get('duration', 'Varies'),
                    category=data.get('category'),
                    progress_percent=data.get('progress_percent'),
                    duration_left=data.get('duration_left'),
                    xp=data.get('xp'),
                    what_you_will_do=json.dumps(data.get('what_you_will_do', [])),
                    requirements=json.dumps(data.get('requirements', [])),
                )
                db.session.add(challenge)
                
                if 'comments' in data and data['comments']:
                    for comment_data in data['comments']:
                        new_comment = Comment(
                            text=comment_data['text'],
                            user_id=comment_data.get('user', 'default_user'),
                            challenge_id=challenge.id,
                            status='APPROVED'
                        )
                        db.session.add(new_comment)

            db.session.commit()
            print("Database population complete.")
        else:
            print("Database already contains challenges. Skipping population.")