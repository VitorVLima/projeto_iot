from app import db, app, login_manager
from datetime import datetime
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), nullable=True)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    mqtt_topic_prefix = db.Column(db.String(100), unique=False, nullable=False)

    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    admin = db.relationship('User', remote_side=[id], backref='users')


with app.app_context():
    db.create_all()