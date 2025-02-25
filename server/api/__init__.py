from flask import Blueprint

api_bp = Blueprint('api', __name__)

from .auth_api import *  # Importar las rutas de autenticación
