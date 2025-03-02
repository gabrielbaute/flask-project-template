from flask import redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from server.oidc import google_login_bp
from database import db, User
from flask_login import login_user

oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        access_token_url='https://accounts.google.com/o/oauth2/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
        client_kwargs={'scope': 'openid email profile'},
    )
    return google

@google_login_bp.route('/login/google')
def google_login():
    redirect_uri = url_for('google_login.google_authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@google_login_bp.route('/authorize/google')
def google_authorize():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    user = User.query.filter_by(email=user_info['email']).first()
    
    if not user:
        user = User(username=user_info['name'], email=user_info['email'])
        db.session.add(user)
        db.session.commit()

    login_user(user)
    session['user_id'] = user.id
    return redirect(url_for('main.home'))
