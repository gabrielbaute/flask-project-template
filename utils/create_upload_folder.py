import os, hashlib, time
from flask import current_app

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def create_upload_folder(app):
    """
    Crea la carpeta principal de uploads si no existe.
    """
    upload_folder = app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

def create_user_folder(user_id):
    """
    Obtiene o crea una carpeta única para cada usuario basada en su ID.
    """
    # Obtener la carpeta base de uploads desde la configuración
    upload_folder = current_app.config['UPLOAD_FOLDER']

    # Generar un hash único para identificar al usuario
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()

    # Crear la ruta completa del directorio del usuario
    user_folder = os.path.join(upload_folder, user_hash)

    # Verificar si la carpeta ya existe antes de crearla
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    return user_folder

def get_user_photo_path(user_id, filename):
    user_folder = create_user_folder(user_id)  # Crear/verificar la carpeta
    return os.path.join(user_folder, filename)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_uploaded_file(file):
    if not file:
        return "No file part"
    if file.filename == '':
        return "No selected file"
    if not allowed_file(file.filename):
        return "Invalid file type. Please upload a PNG or JPEG image."
    return None

def unique_filename(filename):
    """
    Genera un nombre de archivo único basado en un timestamp.
    """
    timestamp = int(time.time())
    name, ext = os.path.splitext(filename)
    return f"{name}_{timestamp}{ext}"
