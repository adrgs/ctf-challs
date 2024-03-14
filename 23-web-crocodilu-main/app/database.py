from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(36),
                   primary_key=True,
                   default=lambda: str(uuid4()),
                   unique=True,
                   nullable=False)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean, default=False)
    code = db.Column(db.String(4), nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password: str) -> None:
        self.password = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"


class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.String(36),
                   primary_key=True,
                   default=lambda: str(uuid4()),
                   unique=True,
                   nullable=False)
    title = db.Column(db.String(50), nullable=False)
    content = db.Column(db.String(512), nullable=False)
    date_posted = db.Column(db.DateTime,
                            nullable=False,
                            default=datetime.utcnow)
    user_id = db.Column(db.String(36),
                        db.ForeignKey('users.id'),
                        nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"