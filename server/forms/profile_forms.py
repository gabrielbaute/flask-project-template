from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import FileField, SubmitField
from wtforms.validators import DataRequired

class UploadPhotoForm(FlaskForm):
    """
    Formulario para subir una foto de perfil.
    """
    photo = FileField(
        'Profile Photo',
        validators=[
            DataRequired(message="Please select a file."),
            FileAllowed(['jpg', 'jpeg', 'png'], 'Only JPG, JPEG, and PNG files are allowed.')
        ]
    )
    submit = SubmitField('Upload')
