from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import FileField, SubmitField, StringField, DateField
from wtforms.validators import DataRequired, Length, Optional, Regexp

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

class EditProfileForm(FlaskForm):
    """
    Formulario para editar los datos del perfil.
    """
    primer_nombre = StringField('First Name', validators=[Length(max=150), Optional()])
    segundo_nombre = StringField('Second Name', validators=[Length(max=150), Optional()])
    primer_apellido = StringField('Last Name', validators=[Length(max=150), Optional()])
    segundo_apellido = StringField('Second Last Name', validators=[Length(max=150), Optional()])
    documento_de_identidad = StringField('Document ID', validators=[
        Length(max=20), Optional(), Regexp(r'^\d+$', message="Document ID must contain only numbers.")
    ])
    telefono = StringField('Phone', validators=[Length(max=20), Optional()])
    fecha_nacimiento = DateField('Date of Birth', format='%Y-%m-%d', validators=[Optional()])
    foto_perfil = FileField('Profile Picture', validators=[Optional()])
    submit = SubmitField('Update Profile')
