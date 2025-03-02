from flask import Blueprint, redirect, url_for, render_template, session, current_app
from flask_login import login_required, current_user
from database.user_models import User

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('main.home'))
    else:
        return redirect(url_for('auth.login'))

@main_bp.route('/home')
@login_required
def home():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        return render_template('main_templates/home.html', user=user)
    else:
        return redirect(url_for('auth.login'))
