from flask_mail import Message
from flask import render_template, url_for
from server.extensions import mail

from mail.tokens_mail_generator import create_email_token, create_reset_token

def send_confirmation_email(user):
    token = create_email_token(user.id)
    msg = Message('Confirm Your Email', recipients=[user.email])
    msg.html = render_template('email_templates/confirm_email.html', username=user.username, token=token)
    mail.send(msg)

def send_reset_password_email(user):
    token = create_reset_token(user.id)
    msg = Message('Reset Your Password', recipients=[user.email])
    msg.html = render_template('email_templates/reset_password.html', username=user.username, token=token)
    mail.send(msg)

def send_account_locked_email(user):
    msg = Message('Your Account Has Been Locked', recipients=[user.email])
    msg.html = render_template('email_templates/account_locked_email.html', username=user.username)
    mail.send(msg)
