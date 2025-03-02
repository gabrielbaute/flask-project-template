from werkzeug.security import generate_password_hash
from database import db
from database.user_models import User
from config import Config

def create_admin_user():
    admin_username = Config.ADMIN_USERNAME
    admin_email = Config.ADMIN_EMAIL
    admin_password = Config.ADMIN_PASSWORD

    if not User.query.filter_by(email=admin_email).first():
        admin_user = User(
            username=admin_username,
            email=admin_email,
            password=generate_password_hash(admin_password, method='pbkdf2:sha256'),
            is_active=True
        )
        db.session.add(admin_user)
        db.session.commit()
