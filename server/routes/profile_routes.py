from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, send_file, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging, pyotp, os

from database import db
from database.user_models import User
from utils import create_user_folder, allowed_file, unique_filename
from server.forms import UploadPhotoForm, ChangePasswordForm, ChangeEmailForm, Enable2FAForm, Disable2FAForm

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/upload_photo', methods=['GET', 'POST'])
@login_required
def upload_photo():
    form = UploadPhotoForm()

    if form.validate_on_submit():
        file = form.photo.data

        # Crear el directorio del usuario si no existe
        user_folder = create_user_folder(current_user.id)

        # Generar un nombre de archivo único
        filename = unique_filename(secure_filename(file.filename))
        file_path = os.path.join(user_folder, filename)

        # Guardar el archivo
        file.save(file_path)

        # Actualizar el modelo del usuario con el nombre del archivo
        current_user.foto_perfil = filename
        db.session.commit()

        flash('Profile picture updated successfully.', 'success')
        return redirect(url_for('profile.view_profile'))

    return render_template(
        'profile_templates/upload_photo.html',
        form=form
    )


@profile_bp.route('/profile_photo')
@login_required
def serve_profile_photo():
    if not current_user.foto_perfil:
        return current_app.send_static_file('img/default_profile.png')

    user_folder = create_user_folder(current_user.id)
    file_path = os.path.normpath(os.path.join(user_folder, current_user.foto_perfil))    

    if not os.path.exists(file_path):
        return current_app.send_static_file('img/default_profile.png')

    return send_file(file_path)


@profile_bp.route('/profile')
@login_required
def view_profile():
    # Cargar historial de sesiones y auditoría para las pestañas
    session_history = current_user.session_history  # Obtén desde el modelo User
    audit_logs = current_user.audit_logs  # Obtén desde el modelo User

    return render_template(
        'profile_templates/profile.html',
        user=current_user,
        session_history=session_history,
        audit_logs=audit_logs
    )

@profile_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    change_password_form = ChangePasswordForm()
    enable_2fa_form = Enable2FAForm()
    disable_2fa_form = Disable2FAForm()
    change_email_form = ChangeEmailForm()

    # Verificar si el usuario tiene 2FA activado
    has_2fa = current_user.totp_secret is not None

    return render_template(
        'profile_templates/settings.html',
        user=current_user,
        change_password_form=change_password_form,
        enable_2fa_form=enable_2fa_form,
        disable_2fa_form=disable_2fa_form,
        change_email_form=change_email_form,
        has_2fa=has_2fa
    )

@profile_bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        if not check_password_hash(current_user.password, current_password):
            flash("Current password is incorrect", "danger")
            return redirect(url_for('profile.settings'))

        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        logging.info(f"Password changed for user {current_user.email}")
        flash("Password updated successfully", "success")
        return redirect(url_for('profile.settings'))
    flash("Invalid form submission", "danger")
    return redirect(url_for('profile.settings'))

@profile_bp.route('/change_email', methods=['POST'])
@login_required
def change_email():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        new_email = form.new_email.data

        if not current_user.totp_secret:
            flash("You must enable 2FA to change your email address", "danger")
            return redirect(url_for('profile.settings'))

        if User.query.filter_by(email=new_email).first():
            flash("This email is already in use", "danger")
            return redirect(url_for('profile.settings'))

        current_user.email = new_email
        db.session.commit()
        logging.info(f"Email changed for user {current_user.email}")
        flash("Email address updated successfully", "success")
    else:
        flash("Invalid form submission", "danger")
    return redirect(url_for('profile.settings'))
