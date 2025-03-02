from flask_mail import Message
from database.user_models import User
from server.extensions import mail
from flask import request

def send_login_notification(user, ip_address):
    msg = Message('New Login Notification', recipients=[user.email])
    msg.body = f"""
    Hi {user.username},
    
    A new login to your account has been detected:

    IP Address: {ip_address}
    Device: {request.user_agent.platform} ({request.user_agent.browser})
    
    If this was you, no further action is needed.
    If you did not log in, please reset your password immediately.

    Best regards,
    Security Team
    """
    mail.send(msg)
