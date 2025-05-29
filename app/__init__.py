from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SUFNPSDNU389-90CDJI0JQWOX'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
#.u=Hyu!uLj+s.48
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)

from app import routes
