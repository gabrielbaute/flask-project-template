from flask import Blueprint

google_login_bp = Blueprint('google_login', __name__)
github_login_bp = Blueprint('github_login', __name__)
microsoft_login_bp = Blueprint('microsoft_login', __name__)

from .google_login import *
from .github_login import *
from .microsoft_login import *
