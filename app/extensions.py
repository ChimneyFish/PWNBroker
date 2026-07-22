from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from apscheduler.schedulers.background import BackgroundScheduler

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()
# In-memory storage — correct as long as the app runs as a single gunicorn
# worker (see run.py); would under-count across multiple worker processes.
limiter = Limiter(key_func=get_remote_address)
oauth = OAuth()
scheduler = BackgroundScheduler(timezone="UTC")
