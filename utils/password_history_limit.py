from database.models import db, PasswordHistory

def enforce_password_history_limit(user, max_history=3):
    if user.password_history.count() > max_history:
        oldest_password = user.password_history.order_by(PasswordHistory.created_at).first()
        db.session.delete(oldest_password)
        db.session.commit()