from flask_sqlalchemy import SQLAlchemy
from .user_models import User, PasswordHistory

db = SQLAlchemy()

def init_db(app):
    db.init_app(app)

