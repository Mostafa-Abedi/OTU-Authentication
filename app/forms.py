from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError
from app.models import User

class RegistrationForm(FlaskForm):
    student_number = StringField('Student Number', validators=[
        DataRequired(),
        Regexp(r'^\d{9}$', message="Student number must be exactly 9 digits.")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Enter a valid email address.")
    ])
    password1 = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=12, message="Password must be at least 12 characters long."),
        Regexp(r'.*[A-Z].*', message="Password must contain at least one uppercase letter."),
        Regexp(r'.*[a-z].*', message="Password must contain at least one lowercase letter."),
        Regexp(r'.*\d.*', message="Password must contain at least one digit."),
        Regexp(r'.*[\W_].*', message="Password must contain at least one special character.")
    ])
    password2 = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password1', message="Passwords must match.")
    ])
    submit = SubmitField('Register')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email is already registered.")

    def validate_student_number(self, student_number):
        if User.query.filter_by(student_number=student_number.data).first():
            raise ValidationError("Student number is already registered.")

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TOTPForm(FlaskForm):
    token = StringField('Enter 6-digit code', validators=[DataRequired()])
    submit = SubmitField('Verify')


SECURITY_QUESTIONS = [
    ("", "--- Select a question ---"),
    ("mother_maiden", "What is your mother's maiden name?"),
    ("first_pet", "What was the name of your first pet?"),
    ("birth_city", "In what city were you born?"),
    ("favorite_teacher", "Who was your favorite teacher?"),
    ("childhood_friend", "What is the name of your childhood best friend?")
]

class SecurityQuestionForm(FlaskForm):
    question = SelectField('Security Question', choices=SECURITY_QUESTIONS, validators=[DataRequired()])
    answer = PasswordField('Answer', validators=[DataRequired()])
    submit = SubmitField('Save')
