from flask import Flask, flash, request, render_template, redirect, url_for
from markupsafe import escape
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from database import db, User, Post
from auth import register, login
from redis import Redis
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired
from bs4 import BeautifulSoup
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta

import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secrets.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretflaskkey')
app.config['SESSION_COOKIE_DOMAIN'] = '.wtl.pw'

app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY', '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY', '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe') 

login_manager = LoginManager()
login_manager.init_app(app)

db.init_app(app)
csrf = CSRFProtect(app)

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
        post = Post(title='Nobody will read this', content=os.getenv('FLAG', 'HackTM{example}'), author=user)
        post2 = Post(title='Hello and Welcome!', content='Timisoara is a vibrant city in western Romania, located near the border with Hungary and Serbia.', author=user)
        post3 = Post(title='Just a random note', content='Timisoara was one of the first cities in Europe to have electric street lighting. HackTM :)', author=user)
        db.session.add(post)
        db.session.commit()
        db.session.add(post2)
        db.session.commit()
        db.session.add(post3)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def index():
    if current_user.is_authenticated:
        posts = Post.query.filter_by(user_id=current_user.id).all()
        for post in posts:
            post.content = escape(post.content)
            post.title = escape(post.title)
        return render_template('index.html', posts=posts, user=current_user)

    return render_template('index.html')


class ReportForm(FlaskForm):
    captcha = RecaptchaField()
    submit = SubmitField('Report')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')


class ReportForm(FlaskForm):
    captcha = RecaptchaField()


@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    form = ReportForm()
    if request.method != 'POST':
        return render_template('report.html', form=form)

    url = request.form['url'].strip()

    if not url.startswith('http://') and not url.startswith('https://'):
        return render_template('report.html', form=form, error='Invalid URL')

    if form.validate_on_submit():
        redis.rpush('query', url)
        redis.incr('queued_count')
        return render_template('report.html', form=form, error='Your report has been queued!')

@app.route('/search', methods=['GET'])
@login_required
def search():
    posts = Post.query.filter(
        (Post.user_id == current_user.id) & (Post.title.like('%' + request.args.get('query') + '%') | Post.content.like('%' + request.args.get('query') + '%'))
    ).all()
    if not posts:
        return redirect('http://secrets.wtl.pw/#' + request.args.get('query').strip(), 301)
    
    return redirect('http://results.wtl.pw/results?ids=' + ','.join([str(post.id) for post in posts]) + '&query=' + request.args.get('query'), 301)

@app.route('/results', methods=['GET'])
@login_required
def results():
    ids = request.args.get('ids').split(',')
    posts = Post.query.filter(Post.id.in_(ids) & (Post.user_id==current_user.id)).all()
    query = str(escape(request.args.get('query')))

    for post in posts:
        post.content = str(escape(post.content))
        post.content = post.content.replace(query, '<span style="background-color: yellow;">' + query + '</span>')
        post.title = str(escape(post.title))
        post.title = post.title.replace(query, '\x3cspan style="background-color: yellow;"\x3e' + query + '</span>')

    return render_template('index.html', posts=posts, user=current_user)

@app.route('/create_note', methods=['GET', 'POST'])
@login_required
def create_note():
    form = PostForm()
    if form.validate_on_submit():
        content = form.content.data
        post = Post(title=form.title.data,
                    content=content,
                    author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your note has been created!', 'success')
        return redirect(url_for('index'))
    return render_template('create_note.html', title='Create Note', form=form)


app.add_url_rule('/register', methods=['GET', 'POST'], view_func=register)
app.add_url_rule('/login', methods=['GET', 'POST'], view_func=login)

if __name__ == '__main__':
    app.run(port=5001, debug=True)
