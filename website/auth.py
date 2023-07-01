from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        errors = []

        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        elif not firstName or len(firstName) < 5:
            errors.append('First name should be at least 5 characters long.')
        elif not password1 or len(password1) < 7:
            errors.append('Password should be at least 7 characters long.')
        elif password1 != password2:
            errors.append('Passwords do not match.')
        if errors:
            for error in errors:
                flash(error, 'error')
        else:
            if User.query.filter_by(email=email).first():
                flash('Email already exists. Please choose a different email.', 'error')
                return redirect(url_for('auth.login'))
            else:
                new_user = User(
                    email=email, 
                    password=generate_password_hash(password1, method='sha256'),
                    first_name=firstName
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Sign-up successful!', 'success')

            return redirect(url_for('views.home'))
        
    return render_template("sign_up.html", user=current_user)
