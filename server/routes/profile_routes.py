from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, send_file
from werkzeug.utils import secure_filename
import os
from flask_login import login_required, current_user

from database import db
from database.user_models import User
from utils import create_user_folder, allowed_file, unique_filename
from server.forms import UploadPhotoForm

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
    # Validar que el usuario tiene una foto asignada
    if not current_user.foto_perfil:
        abort(404, description="No profile photo found.")

    # Obtener la ruta del archivo
    user_folder = create_user_folder(current_user.id)
    file_path = os.path.join(user_folder, current_user.foto_perfil)

    # Verificar si el archivo existe
    if not os.path.exists(file_path):
        abort(404, description="Profile photo not found.")

    return send_file(file_path)


@profile_bp.route('/profile')
@login_required
def view_profile():
    return ('This is your profie page')