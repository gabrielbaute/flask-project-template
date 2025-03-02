import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template
from flask_migrate import Migrate
from config import Config
from database import init_db, db
from server.routes.register_blueprints import register_blueprints
from server.create_admin import create_admin_user
from server.extensions import login_manager, jwt, mail
from server.oidc import google_login_bp, github_login_bp, microsoft_login_bp
from server.oidc.google_login import init_oauth as init_google_oauth
from server.oidc.github_login import init_oauth as init_github_oauth
from server.oidc.microsoft_login import init_oauth as init_microsoft_oauth
from server.api import api_bp
from database import User

def create_app():
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')
    app.config.from_object(Config)

    init_db(app)

    mail.init_app(app)
    jwt.init_app(app)
    init_google_oauth(app)
    init_github_oauth(app)
    init_microsoft_oauth(app)

    migrate = Migrate(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    register_blueprints(app)
    app.register_blueprint(api_bp)
    app.register_blueprint(google_login_bp)
    app.register_blueprint(github_login_bp)
    app.register_blueprint(microsoft_login_bp)

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('main_templates/404.html'), 404

    with app.app_context():
        db.create_all()  # Crear las tablas de la base de datos
        create_admin_user()  # Crear el usuario administrador si no existe

    # Configuración de logging
    if not app.debug:
        if not app.logger.handlers:
            file_handler = RotatingFileHandler('logs/flask-template.log', maxBytes=10240, backupCount=10)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('Flask Template startup')

    return app
