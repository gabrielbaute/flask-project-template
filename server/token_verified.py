from flask import request, redirect, url_for
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

def jwt_required_custom(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return fn(*args, **kwargs)
        except:
            return redirect(url_for('auth.login'))
    return wrapper
