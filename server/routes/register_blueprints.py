from server.routes.auth_routes import auth_bp
from server.routes.main_routes import main_bp
from server.routes.profile_routes import profile_bp

def register_blueprints(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(profile_bp)
    # Registrar otros blueprints aquí en el futuro
