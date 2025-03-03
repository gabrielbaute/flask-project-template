from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired, EqualTo, Email

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')]
    )
    submit = SubmitField('Update Password')

class ChangeEmailForm(FlaskForm):
    new_email = StringField('New Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Email')

class Enable2FAForm(FlaskForm):
    submit = SubmitField('Enable 2FA')

class Disable2FAForm(FlaskForm):
    submit = SubmitField('Disable 2FA')