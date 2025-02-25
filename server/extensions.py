from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from flask_mail import Mail


login_manager = LoginManager()
jwt = JWTManager()
mail = Mail()
