from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_manager, LoginManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS




app = Flask(__name__)
app.config['SECRET_KEY'] = 'SUFNPSDNU389-90CDJI0JQWOX' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

#configurações de Login
login_manager = LoginManager()
login_manager.init_app(app)

from app import routes