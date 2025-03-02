from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, make_response, session, current_app, send_file, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies, unset_access_cookies
from datetime import datetime, timedelta
from io import BytesIO
import jwt
import pyotp
import qrcode

from mail import send_confirmation_email,send_account_locked_email, decode_email_token, create_email_token, send_reset_password_email, create_reset_token, decode_reset_token
from server.forms import LoginForm, RegisterForm, ForgotPasswordForm, ResetPasswordForm, ReactivateAccountForm, ResendConfirmationForm, TOTPForm
from utils import enforce_password_history_limit
from database import db
from database.user_models import User, PasswordHistory, SessionHistory

auth_bp = Blueprint('auth', __name__)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_PERIOD = timedelta(minutes=15)

"""
    Rutas para registro y confirmación de cuenta
"""
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        username = form.username.data
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email address already exists', 'danger')
            return redirect(url_for('auth.register'))

        new_user = User(username=username, 
                        email=email, 
                        password=generate_password_hash(password, method='pbkdf2:sha256'))
        
        db.session.add(new_user)
        db.session.commit()

        send_confirmation_email(new_user)
        flash('A confirmation email has been sent to your email address. Please confirm your email to complete the registration.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth_templates/register.html', form=form)

@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    user_id = decode_email_token(token)
    if user_id is None:
        flash('The confirmation link is invalid or has expired. Please request a new confirmation link below.', 'danger')
        return redirect(url_for('auth.resend_confirmation'))

    user = User.query.get(user_id)
    if user.is_active:
        flash('Account already confirmed. Please log in.', 'success')
        return redirect(url_for('auth.login'))

    # Activar la cuenta del usuario
    user.is_active = True

    # Registrar la contraseña inicial en el historial
    password_history = PasswordHistory(user_id=user.id, password_hash=user.password)
    db.session.add(password_history)

    db.session.commit()
    flash('Your account has been confirmed. You can now log in.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/resend_confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    form = ResendConfirmationForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user and not user.is_active:
            send_confirmation_email(user)
            flash('A new confirmation email has been sent to your email address.', 'success')
        else:
            flash('Invalid email or the account is already active.', 'danger')

        return redirect(url_for('auth.login'))

    return render_template('auth_templates/resend_confirmation.html', form=form)

"""
    Rutas para inicio y cierre de sesión
"""
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('auth.login'))
        
        # Verificar si la cuenta está inactiva
        if not user.is_active:
            flash('Your account has been locked due to multiple failed login attempts. Check your email to reset your password.', 'danger')
            return redirect(url_for('auth.login'))

        # Verificar la contraseña
        if check_password_hash(user.password, password):
            # Restablecer el contador de intentos fallidos en caso de éxito
            user.failed_login_attempts = 0
            user.last_failed_login = None
            db.session.commit()

            login_user(user)
            session['user_id'] = user.id
            
            # Registrar el evento de inicio de sesión
            session_event = SessionHistory(
                usuario_id=user.id,
                tipo_evento='LOGIN',
                ip_origen=request.remote_addr,
                dispositivo=request.user_agent.platform,
                navegador=request.user_agent.browser
            )
            db.session.add(session_event)
            db.session.commit()

            current_app.logger.info('User logged in: %s', email)
            flash('Login successful. Welcome back!', 'success')
            return redirect(url_for('main.home'))

        # Manejar intentos fallidos
        now = datetime.utcnow()
        if user.last_failed_login and now - user.last_failed_login > LOCKOUT_PERIOD:
            # Restablecer el contador si el tiempo ha expirado
            user.failed_login_attempts = 0

        user.failed_login_attempts += 1
        user.last_failed_login = now

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.is_active = False
            db.session.commit()
            send_account_locked_email(user)  # Notificación automática
            flash('Too many failed login attempts. Your account has been locked. Follow the instructions sent to your email.', 'danger')
            return redirect(url_for('auth.login'))

        db.session.commit()
        flash('Please check your login details and try again.', 'danger')
        return redirect(url_for('auth.login'))

    return render_template('auth_templates/login.html', form=form)

@auth_bp.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    # Registrar evento de cierre de sesión
    session_event = SessionHistory(
        usuario_id=current_user.id,
        tipo_evento='LOGOUT',
        ip_origen=request.remote_addr,
        dispositivo=request.user_agent.platform,
        navegador=request.user_agent.browser
    )
    db.session.add(session_event)
    db.session.commit()

    # Cerrar la sesión del usuario
    logout_user()
    session.pop('user_id', None)
    current_app.logger.info('User logged out')  # Registrar en el log
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))


"""
    Rutas para restablecimiento de contraseña
"""
@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_password_email(user)
        flash('If an account with that email exists, a password reset link has been sent.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth_templates/forgot_password.html', form=form)

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        user_id = decode_reset_token(token)
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        user = User.query.get(user_id)

        # Verificar que la contraseña no haya sido utilizada antes
        for old_password in user.password_history:
            if check_password_hash(old_password.password_hash, password):
                flash('You cannot reuse a previous password. Please choose a different one.', 'danger')
                return redirect(url_for('auth.reset_password', token=token))

        # Actualizar la contraseña del usuario
        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        user.failed_login_attempts = 0
        user.is_active = True

        # Guardar en el historial de contraseñas
        new_password_history = PasswordHistory(user_id=user.id, password_hash=user.password)
        db.session.add(new_password_history)

        # Limitar el historial a las últimas N contraseñas
        enforce_password_history_limit(user, max_history=3)

        db.session.commit()
        flash('Your password has been reset. You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth_templates/reset_password.html', form=form)

@auth_bp.route('/reactivate', methods=['GET', 'POST'])
def reactivate_account():
    form = ReactivateAccountForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if not user or user.is_active:
            flash('Invalid email or the account is already active.', 'danger')
            return redirect(url_for('auth.reactivate_account'))

        # Enviar correo con token de restablecimiento
        send_reset_password_email(user)
        flash('If the email exists and the account is locked, you will receive a password reset email shortly.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth_templates/reactivate_account.html', form=form)

"""
    Rutas para 2FA
"""
@auth_bp.route('/enable_2fa', methods=['GET'])
@login_required
def enable_2fa():
    user = current_user
    if user.totp_secret is None:
        # Generar un nuevo secreto TOTP si no existe
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    # Renderizar la plantilla con el QR generado dinámicamente desde get_qr_code
    return render_template('auth_templates/enable_2fa.html', user_id=user.id)

@auth_bp.route('/get_qr_code/<user_id>', methods=['GET'])
@login_required
def get_qr_code(user_id):
    if current_user.id != user_id:
        abort(403)  # Asegurarse de que solo el usuario autenticado puede acceder a su QR

    totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.email,
        issuer_name="YourAppName"
    )
    qr = qrcode.make(totp_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)

    return send_file(buffer, mimetype='image/png')

@auth_bp.route('/verify_2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    form = TOTPForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(form.totp_code.data):
            session['2fa_verified'] = True
            flash('Two-Factor Authentication verified successfully!', 'success')
            return redirect(url_for('main.home'))
        else:
            flash('Invalid TOTP code. Please try again.', 'danger')

    return render_template('auth_templates/verify_2fa.html', form=form)

@auth_bp.route('/disable_2fa', methods=['GET', 'POST'])
@login_required
def disable_2fa():
    if request.method == 'POST':
        current_user.totp_secret = None
        db.session.commit()
        flash('Two-Factor Authentication has been disabled.', 'success')
        return redirect(url_for('main.home'))

    return render_template('auth_templates/disable_2fa.html')

@auth_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(logged_in_as=user.username), 200
