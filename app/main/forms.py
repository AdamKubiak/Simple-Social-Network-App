from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length


class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    submit = SubmitField('Submit')

class EditProfileForm(FlaskForm):
    name = StringField('Name and Surrname', validators=[Length(0,64)])
    location = StringField('Location', validators=[Length(0,64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Save')

class PostForm(FlaskForm):
    body = StringField("What's in your head?", validators=[DataRequired()])
    submit = SubmitField('Post')
