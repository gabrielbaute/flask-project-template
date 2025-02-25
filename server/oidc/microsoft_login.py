from flask import redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from server.oidc import microsoft_login_bp
from database.models import User
from database import db
from flask_login import login_user

oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    microsoft = oauth.register(
        name='microsoft',
        client_id=app.config['MICROSOFT_CLIENT_ID'],
        client_secret=app.config['MICROSOFT_CLIENT_SECRET'],
        access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
        authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        userinfo_endpoint='https://graph.microsoft.com/oidc/userinfo',
        client_kwargs={'scope': 'openid email profile'},
    )
    return microsoft

@microsoft_login_bp.route('/login/microsoft')
def microsoft_login():
    redirect_uri = url_for('microsoft_login.microsoft_authorize', _external=True)
    return oauth.microsoft.authorize_redirect(redirect_uri)

@microsoft_login_bp.route('/authorize/microsoft')
def microsoft_authorize():
    token = oauth.microsoft.authorize_access_token()
    user_info = oauth.microsoft.parse_id_token(token)
    user = User.query.filter_by(email=user_info['email']).first()
    
    if not user:
        user = User(username=user_info['name'], email=user_info['email'])
        db.session.add(user)
        db.session.commit()

    login_user(user)
    session['user_id'] = user.id
    return redirect(url_for('main.home'))
