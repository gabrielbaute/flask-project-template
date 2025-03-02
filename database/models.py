from flask_login import UserMixin
from datetime import datetime
from database import db
import uuid

class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)  # Contador de intentos fallidos
    last_failed_login = db.Column(db.DateTime, nullable=True)  # Fecha del último intento fallido
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('password_history', lazy='dynamic'))