from flask import Flask, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from app.models import db, User
from app.blueprints.auth.routes import auth_bp
from app.blueprints.challenges.routes import challenges_bp
from app.blueprints.admin.routes import admin_bp

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'super-secret-key'   # Replace with a secure key in production!
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///culturequest.db'  # Use MySQL URI if desired

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(challenges_bp)
    app.register_blueprint(admin_bp)

    @app.route('/')
    def home():
        return redirect('/challenges/')

    # Optional: Custom error handlers for 403/404
    @app.errorhandler(403)
    def forbidden(e):
        return "<h1>403 Forbidden</h1>", 403

    @app.errorhandler(404)
    def not_found(e):
        return "<h1>404 Not Found</h1>", 404

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
