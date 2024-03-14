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
    email_pattern = re.compile(r"^[0-9A-Za-z]+@[0-9A-Za-z]+\.[a-z]+$")
    return email_pattern.match(email) is not None

class RegisterForm(FlaskForm):
    captcha = RecaptchaField()

def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()

    if request.method != 'POST':
        return render_template('register.html', captcha = form.captcha, form = form)

    if not form.captcha.validate(form):
        return render_template('register.html', error='Invalid captcha', captcha = form.captcha, form = form)

    name = request.form['name'].strip()
    email = request.form['email'].strip().lower()
    password = request.form['password']

    if not name or not email or not password:
        return render_template('register.html', error='Please fill all fields', captcha = form.captcha, form = form)

    if not is_valid_email(email):
        return render_template('register.html', error='Invalid email', captcha = form.captcha, form = form)

    if User.query.filter(User.email.like(email)).first():
        return render_template('register.html', error='Email already exists', captcha = form.captcha, form = form)
    user = User(name=name,
                email=email,
                password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('login'))

class LoginForm(FlaskForm):
    pass

def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()

    if request.method != 'POST':
        return render_template('login.html', form=form)

    email = request.form['email'].strip()
    password = request.form['password']
    user = User.query.filter(User.email.like(email)).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        response = redirect(url_for('index'))
        return response
    else:
        return render_template('login.html', error='Invalid email or password', form=form)
