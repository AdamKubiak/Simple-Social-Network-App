from collections.abc import Sequence
from typing import Any, Mapping
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from ..models import User

class LoginForm(FlaskForm):
    login = StringField('Login', validators=[DataRequired(), Length(1,64),])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RegisterForm(FlaskForm):
    login = StringField('Login', validators=[DataRequired(), Length(min=3, max=32)])
    password = PasswordField('Password', validators=[DataRequired()])
    password1 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Create Account')

    def validate_login(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username already exists")
