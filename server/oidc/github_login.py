from flask import redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from server.oidc import github_login_bp
from database import db
from database.user_models import User
from flask_login import login_user

oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    github = oauth.register(
        name='github',
        client_id=app.config['GITHUB_CLIENT_ID'],
        client_secret=app.config['GITHUB_CLIENT_SECRET'],
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        userinfo_endpoint='https://api.github.com/user',
        client_kwargs={'scope': 'user:email'},
    )
    return github

@github_login_bp.route('/login/github')
def github_login():
    redirect_uri = url_for('github_login.github_authorize', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@github_login_bp.route('/authorize/github')
def github_authorize():
    token = oauth.github.authorize_access_token()
    user_info = oauth.github.get('user').json()
    user = User.query.filter_by(email=user_info['email']).first()
    
    if not user:
        user = User(username=user_info['login'], email=user_info['email'])
        db.session.add(user)
        db.session.commit()

    login_user(user)
    session['user_id'] = user.id
    return redirect(url_for('main.home'))
