from flask import Flask, flash, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from database import db, User, Post
from auth import register, login, logout, request_code, reset_password
from redis import Redis
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired
from bs4 import BeautifulSoup

import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crocodilu.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretflaskkey')

app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY', '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY', '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe') 

login_manager = LoginManager()
login_manager.init_app(app)

db.init_app(app)

redis = Redis(host=os.getenv('REDIS_HOST', 'localhost'),
              port=int(os.getenv('REDIS_PORT', '6379')),
              db=0)
redis.set('queued_count', 0)
redis.set('proceeded_count', 0)

with app.app_context():
    db.create_all()
    if not User.query.filter(User.email.like('admin@hacktm.ro')).first():
        user = User(name='admin',
                    email='admin@hacktm.ro',
                    password=generate_password_hash(
                        os.getenv('ADMIN_PASSWORD', 'admin')),
                    active=True,
                    admin=True)
        db.session.add(user)
        post = Post(title='Welcome to Crocodilu', content=os.getenv('FLAG', 'HackTM{example}'), author=user)
        db.session.add(post)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/profile')
@login_required
def profile():
    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', posts=posts, user=current_user)

class ReportForm(FlaskForm):
    captcha = RecaptchaField()
    submit = SubmitField('Report')

@app.route("/post/<post_id>", methods=['GET', 'POST'])
@login_required
def post(post_id):
    form = ReportForm()
    post = Post.query.get_or_404(post_id)
    if post.author.id != current_user.id and not current_user.admin:
        return redirect(url_for('profile'))

    if request.method != 'POST':
        return render_template('post.html', title=post.title, post=post, form=form)

    if not form.captcha.validate(form):
        return render_template('post.html', title=post.title, post=post, form=form, error='Invalid captcha')

    redis.rpush('query', f'/post/{post_id}')
    redis.incr('queued_count')

    return render_template('post.html', title=post.title, post=post, form=form, error='Your report has been queued.')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')


@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    blacklist = ['script', 'body', 'embed', 'object', 'base', 'link', 'meta', 'title', 'head', 'style', 'img', 'frame']

    if current_user.admin:
        return redirect(url_for('profile'))
    form = PostForm()
    if form.validate_on_submit():
        content = form.content.data
        soup = BeautifulSoup(content, 'html.parser')
        for tag in blacklist:
            if soup.find(tag):
                content = 'Invalid YouTube embed!'
                break

        for iframe in soup.find_all('iframe'):
            if iframe.has_attr('srcdoc') or not iframe.has_attr('src') or not iframe['src'].startswith('https://www.youtube.com/'):
                content = 'Invalid YouTube embed!'
                break

        post = Post(title=form.title.data,
                    content=content,
                    author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('profile'))
    return render_template('create_post.html', title='Create Post', form=form)


app.add_url_rule('/request_code',
                 methods=['GET', 'POST'],
                 view_func=request_code)
app.add_url_rule('/reset_password',
                 methods=['GET', 'POST'],
                 view_func=reset_password)
app.add_url_rule('/register', methods=['GET', 'POST'], view_func=register)
app.add_url_rule('/login', methods=['GET', 'POST'], view_func=login)
app.add_url_rule('/logout', view_func=logout)

if __name__ == '__main__':
    app.run(port=5001, debug=True)