from flask_mail import Message
from database.user_models import User
from server.extensions import mail
from flask import request, render_template

def send_login_notification(user, ip_address):
    """
    Envía una notificación por email al usuario cuando inicia sesión en un dispositivo.
    """
    device = request.user_agent.platform
    browser = request.user_agent.browser

    # Renderizar la plantilla con los datos
    msg = Message('New Login Notification', recipients=[user.email])
    msg.html = render_template(
        'email_templates/login_notification.html',
        username=user.username,
        ip_address=ip_address,
        device=device,
        browser=browser
    )
    mail.send(msg)

def send_enable_2fa_notification(user):
    """
    Envía una notificación por email al usuario cuando habilita el 2FA.
    """
    ip_origen = request.remote_addr or "Unknown"
    dispositivo = request.user_agent.platform or "Unknown"
    user_agent = request.headers.get('User-Agent') or "Unknown"

    # Configurar el mensaje
    msg = Message(
        subject="Two-Factor Authentication Enabled",
        recipients=[user.email]
    )
    msg.html = render_template(
        "email_templates/enable_2fa_notification.html",
        username=user.username,
        ip_origen=ip_origen,
        dispositivo=dispositivo,
        user_agent=user_agent
    )
    mail.send(msg)

def send_disable_2fa_notification(user):
    """
    Envía una notificación por email al usuario cuando deshabilita el 2FA.
    """
    ip_origen = request.remote_addr or "Unknown"
    dispositivo = request.user_agent.platform or "Unknown"
    user_agent = request.headers.get('User-Agent') or "Unknown"

    # Configurar el mensaje
    msg = Message(
        subject="Two-Factor Authentication Disabled",
        recipients=[user.email]
    )
    msg.html = render_template(
        "email_templates/disable_2fa_notification.html",
        username=user.username,
        ip_origen=ip_origen,
        dispositivo=dispositivo,
        user_agent=user_agent
    )
    mail.send(msg)