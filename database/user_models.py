from flask_login import UserMixin
from sqlalchemy.orm import relationship
from datetime import datetime
from database import db
import uuid

class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    # Campos de control de acceso
    is_active = db.Column(db.Boolean, default=False)  # Activo o inactivo
    failed_login_attempts = db.Column(db.Integer, default=0)  # Contador de intentos fallidos
    last_failed_login = db.Column(db.DateTime, nullable=True)  # Fecha del último intento fallido
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) # Fecha de creación
    totp_secret = db.Column(db.String(32), nullable=True)   # Clave para autenticación de dos factores
    is_2fa_enabled = db.Column(db.Boolean, default=False)  # Campo para reflejar el estado de 2FA

    # Otros datos del usuario
    primer_nombre = db.Column(db.String(150), nullable=True)
    segundo_nombre = db.Column(db.String(150), nullable=True)
    primer_apellido = db.Column(db.String(150), nullable=True)
    segundo_apellido = db.Column(db.String(150), nullable=True)
    documento_de_identidad = db.Column(db.String(20), nullable=True)
    telefono = db.Column(db.String(20), nullable=True)
    fecha_nacimiento = db.Column(db.Date, nullable=True)
    foto_perfil = db.Column(db.String(150), nullable=True)

    # Relación con SessionHistory
    session_history = relationship(
        'SessionHistory',
        backref='user',    # Permite acceder al usuario desde SessionHistory
        lazy=True          # Carga perezosa de los datos relacionados
    )

    # Relación con SessionHistory
    audit_logs = relationship(
        'AuditLog',
        backref='user',    # Permite acceder al usuario desde SessionHistory
        lazy=True          # Carga perezosa de los datos relacionados
    )
    
    def __repr__(self):
        return f'<User {self.username}>'

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('password_history', lazy='dynamic'))

    def __repr__(self):
        return f'<PasswordHistory {self.user_id}>'

class SessionHistory(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    usuario_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    tipo_evento = db.Column(db.String(10), nullable=False)  # LOGIN o LOGOUT
    fecha_evento = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_origen = db.Column(db.String(45), nullable=False)  # Dirección IPv4/IPv6
    dispositivo = db.Column(db.String(50), nullable=True)  # PC, Android, iPhone, etc.
    navegador = db.Column(db.String(50), nullable=True)  # Chrome, Edge, etc.

    def __repr__(self):
        return f'<SessionHistory {self.usuario_id}>'

class AuditLog(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    usuario_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    accion = db.Column(db.String(50), nullable=False)  # Descripción de la acción
    detalles = db.Column(db.Text, nullable=True)  # Información adicional (JSON o texto)
    fecha_cambio = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_origen = db.Column(db.String(45), nullable=False)  # IPv4/IPv6
    dispositivo = db.Column(db.String(50), nullable=True)  # PC, Android, etc.
    user_agent = db.Column(db.Text, nullable=True)  # Agente de usuario completo
    observaciones = db.Column(db.Text, nullable=True)  # Comentarios adicionales

    def __repr__(self):
        return f'<SessionHistory {self.usuario_id}>'

from datetime import datetime, timedelta

class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)