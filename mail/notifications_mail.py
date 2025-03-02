from flask_mail import Message
from database.user_models import User
from server.extensions import mail
from flask import request, render_template

def send_login_notification(user, ip_address):
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

