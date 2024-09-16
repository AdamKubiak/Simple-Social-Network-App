from flask import render_template, redirect, request, url_for, flash
from . import auth
from .forms import LoginForm, RegisterForm
from ..models import User
from .. import db
from flask_login import login_user, logout_user, login_required, current_user


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        
@auth.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.login.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            
            return redirect(url_for("main.user", username=user.username))
        flash("Invalid username or password.")
    return render_template("auth/login.html", form=form)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("main.index"))


@auth.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(username=form.login.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)
