from database import db, User
from flask import Flask, request, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
import random
import string
from redis import Redis
import os
from flask_wtf import FlaskForm, RecaptchaField

redis = Redis(host=os.getenv('REDIS_HOST', 'localhost'),
              port=int(os.getenv('REDIS_PORT', '6379')),
              db=0)


def is_valid_email(email: str) -> bool:
    email_pattern = re.compile(r"[0-9A-Za-z]+@[0-9A-Za-z]+\.[a-z]+")
    return email_pattern.match(email) is not None

class RegisterForm(FlaskForm):
    captcha = RecaptchaField()

def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()

    if request.method != 'POST':
        return render_template('register.html', captcha = form.captcha)

    if not form.captcha.validate(form):
        return render_template('register.html', error='Invalid captcha', captcha = form.captcha)

    name = request.form['name'].strip()
    email = request.form['email'].strip().lower()
    password = request.form['password']

    if not name or not email or not password:
        return render_template('register.html', error='Please fill all fields', captcha = form.captcha)

    if not is_valid_email(email):
        return render_template('register.html', error='Invalid email', captcha = form.captcha)

    if User.query.filter(User.email.like(email)).first():
        return render_template('register.html', error='Email already exists', captcha = form.captcha)
    user = User(name=name,
                email=email,
                password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    # TODO: send email with activation link, will fix this next release

    return redirect(url_for('login'))


def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method != 'POST':
        return render_template('login.html')

    email = request.form['email'].strip()
    password = request.form['password']
    user = User.query.filter(User.email.like(email)).first()
    if user and check_password_hash(user.password, password):
        if user.active is False:
            return render_template(
                'login.html', error='User not active, please check your email')

        login_user(user)
        return redirect(url_for('index'))
    else:
        return render_template('login.html', error='Invalid email or password')


def request_code():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method != 'POST':
        return render_template('request_code.html')

    email = request.form['email'].strip()
    if not is_valid_email(email):
        return render_template('request_code.html', error='Invalid email')

    user = User.query.filter(User.email.like(email)).first()

    if user:
        if user.admin:
            return render_template('request_code.html',
                                   error='Admins cannot reset their password')

        user.code = ''.join(random.choices(string.digits, k=4))
        # TODO: send email with code, will fix this next release

        db.session.commit()

        return redirect(url_for('reset_password'))
    else:
        return render_template('request_code.html', error='Invalid email')


def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method != 'POST':
        return render_template('reset_password.html')

    email = request.form['email'].strip()
    if not is_valid_email(email):
        return render_template('request_code.html', error='Invalid email')

    reqs = redis.get(email)
    if reqs is not None and int(reqs) > 2:
        return render_template('reset_password.html',
                               error='Too many requests')
    else:
        if reqs is None:
            redis.set(email, '1')
        else:
            redis.incr(email)
        redis.expire(email, 3600)

    code = request.form['code'].strip()
    if not code.isdigit():
        return render_template('reset_password.html', error='Invalid code')

    password = request.form['password']
    user = User.query.filter(User.email.like(email)
                             & User.code.like(code)).first()

    if user and not user.admin:
        user.code = None
        user.password = generate_password_hash(password)
        user.active = True
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('reset_password.html',
                           error='Invalid email or code')


@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
