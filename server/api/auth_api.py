from flask import jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, User
from server.extensions import jwt
from server.api import api_bp
from mail.auth_mail import send_reset_password_email

@api_bp.route('/api/login', methods=['POST'])
def api_login():
    """
    Ejemplo de estructura de petición post:
        {
            "email": "admin@example.com",
            "password": "admin_password"
        }
    """
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    user = User.query.filter_by(email=email).first()
    
    if not user or not check_password_hash(user.password, password):
        return jsonify({"msg": "Bad email or password"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token)

@api_bp.route('/api/register', methods=['POST'])
def api_register():
    """
    Ejemplo de estructura de petición post:
        {
            "username": "new_user",
            "email": "new_user@example.com",
            "password": "new_password"
        }
    """
    username = request.json.get('username', None)
    email = request.json.get('email', None)
    password = request.json.get('password', None)

    user = User.query.filter_by(email=email).first()

    if user:
        return jsonify({"msg": "Email address already exists"}), 400

    new_user = User(username=username, email=email, password=generate_password_hash(password, method='pbkdf2:sha256'))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "Registration successful"}), 201

@api_bp.route('/api/forgot_password', methods=['POST'])
def api_forgot_password():
    """
    Ejemplo de estructura de petición post:
        {
            "email": "user@example.com"
        }
    """
    email = request.json.get('email', None)
    user = User.query.filter_by(email=email).first()
    if user:
        send_reset_password_email(user)
    return jsonify({"msg": "If an account with that email exists, a password reset link has been sent"}), 200

@api_bp.route('/api/reset_password/<token>', methods=['POST'])
def api_reset_password(token):
    """
    Ejemplo de estructura de petición post:
        {
            "password": "new_password"
        }
    """
    from mail.auth_mail import decode_reset_token  # Importación perezosa
    user_id = decode_reset_token(token)
    if not user_id:
        return jsonify({"msg": "The reset link is invalid or has expired"}), 400

    password = request.json.get('password', None)
    user = User.query.get(user_id)
    user.password = generate_password_hash(password, method='pbkdf2:sha256')
    db.session.commit()
    return jsonify({"msg": "Your password has been reset. You can now log in"}), 200

@api_bp.route('/api/logout', methods=['POST'])

@jwt_required()
def api_logout():
    """
    Ejemplo de estructura de petición post:
        {}
    """
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    return response

@api_bp.route('/api/protected', methods=['GET'])
@jwt_required()
def api_protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(logged_in_as=user.username), 200
