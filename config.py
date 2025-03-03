"""Configuración de la aplicación Flask."""

import os
from dotenv import load_dotenv
from datetime import timedelta

# Carga las variables de entorno desde el archivo .env en el directorio raíz
load_dotenv()

BASE_DIR=os.path.abspath(os.path.dirname(__file__))

# Función para convertir una cadena a un valor booleano
def str_to_bool(value):
    return value.lower() in ['true', '1', 'yes']

class Config:
    """Configuración de la aplicación Flask."""

    # Flask server
    PORT=os.environ.get("PORT")
    DEBUG=os.environ.get("DEBUG")

    # Variables de entorno para el administrador
    ADMIN_USERNAME=os.environ.get('ADMIN_USERNAME') or 'admin'
    ADMIN_EMAIL=os.environ.get('ADMIN_EMAIL') or 'admin@example.com'
    ADMIN_PASSWORD=os.environ.get('ADMIN_PASSWORD') or 'admin_password'

    # SQLAlchemy
    SQLALCHEMY_DATABASE_URI=os.environ.get('SQLALCHEMY_DATABASE_URI') or f'sqlite:///{os.path.join(BASE_DIR, "yourdatabase.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS=os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS') or False

    # Encriptado
    SECRET_KEY=os.environ.get('SECRET_KEY') or 'una_clave_secreta_segura'
    SECURITY_PASSWORD_SALT=os.getenv('SECURITY_PASSWORD_SALT')
    JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1)
    JWT_TOKEN_LOCATION=['cookies']
    JWT_ACCESS_COOKIE_PATH='/'
    JWT_REFRESH_COOKIE_PATH='/'
    JWT_COOKIE_SECURE=False #Cambiar a true para usar HTTPS en producción
    JWT_COOKIE_CSRF_PROTECT=False  # Desactiva la protección CSRF para pruebas

    # Configuración de OAuth para Google
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI')

    # Configuración de OAuth para Microsoft
    MICROSOFT_CLIENT_ID = os.environ.get('MICROSOFT_CLIENT_ID')
    MICROSOFT_CLIENT_SECRET = os.environ.get('MICROSOFT_CLIENT_SECRET')
    MICROSOFT_REDIRECT_URI = os.environ.get('MICROSOFT_REDIRECT_URI')

    # Configuración de OAuth para Github
    GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
    GITHUB_REDIRECT_URI = os.environ.get('GITHUB_REDIRECT_URI')

    # Configuración de Flask-Mail
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = os.environ.get('MAIL_PORT')
    MAIL_USE_TLS = str_to_bool(os.environ.get('MAIL_USE_TLS', 'False'))
    MAIL_USE_SSL = str_to_bool(os.environ.get('MAIL_USE_SSL', 'False'))
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    MAIL_DEBUG = int(os.environ.get('MAIL_DEBUG', 0))