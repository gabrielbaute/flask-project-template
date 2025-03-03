from flask_mail import Message
from flask import render_template, url_for
from server.extensions import mail
import logging

from mail.tokens_mail_generator import create_email_token, create_reset_token

def send_confirmation_email(user):
    try:
        """
        Envía un email de confirmación al usuario.
        """
        token = create_email_token(user.id)
        msg = Message('Confirm Your Email', recipients=[user.email])
        msg.html = render_template('email_templates/confirm_email.html', username=user.username, token=token)
        mail.send(msg)
        
        logging.info(f"Confirmation email sent to {user.email}.")
    
    except Exception as e:
        logging.error(f"Failed to send confirmation email to {user.email}: {e}")

def send_reset_password_email(user):
    try:
        """
        Envía un email al usuario con un enlace para restablecer su contraseña.
        """
        token = create_reset_token(user.id)
        msg = Message('Reset Your Password', recipients=[user.email])
        msg.html = render_template('email_templates/reset_password.html', username=user.username, token=token)
        mail.send(msg)
        
        logging.info(f"Reset password email sent to {user.email}.")

    except Exception as e:
        logging.error(f"Failed to send reset password email to {user.email}: {e}")    

def send_account_locked_email(user):
    try:
        """
        Envía un correo al usuario cuando su cuenta ha sido bloqueada.
        """
        msg = Message('Your Account Has Been Locked', recipients=[user.email])
        msg.html = render_template('email_templates/account_locked_email.html', username=user.username)
        mail.send(msg)

        logging.info(f"Account locked email sent to {user.email}.")
    
    except Exception as e:
        logging.error(f"Failed to send account locked email to {user.email}: {e}")
