from flask_mail import Message
from flask import render_template, url_for
from server.extensions import mail
import jwt
from datetime import datetime, timedelta
from config import Config

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
    msg.html = render_template('email_templates/account_locked.html', username=user.username)
    mail.send(msg)

def create_email_token(user_id):
    token = jwt.encode({
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, Config.SECRET_KEY, algorithm='HS256')
    return token

def decode_email_token(token):
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None

def create_reset_token(user_id):
    token = jwt.encode({
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, Config.SECRET_KEY, algorithm='HS256')
    return token

def decode_reset_token(token):
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
