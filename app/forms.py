from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError
from app.models import User

question_choices1 = [
    ('What is your favorite food?', 'What is your favorite food?'),
    ('What was your first pet’s name?', 'What was your first pet’s name?'),
    ('What city were you born in?', 'What city were you born in?'),
    ('What is the name of your favorite childhood teacher?', 'What is the name of your favorite childhood teacher?'),
    ('What was the make and model of your first car?', 'What was the make and model of your first car?'),
    ('What is your mother’s maiden name?', 'What is your mother’s maiden name?'),
    ('What is the name of the street you grew up on?', 'What is the name of the street you grew up on?'),
    ('What was the name of your elementary school?', 'What was the name of your elementary school?')
]

question_choices2 = [
    ('What was your childhood nickname?', 'What was your childhood nickname?'),
    ('What is the middle name of your oldest sibling?', 'What is the middle name of your oldest sibling?'),
    ('What is your favorite movie?', 'What is your favorite movie?'),
    ('What was your dream job as a child?', 'What was your dream job as a child?'),
    ('What is the name of your favorite book?', 'What is the name of your favorite book?'),
    ('In what city did your parents meet?', 'In what city did your parents meet?'),
    ('What is your favorite color?', 'What is your favorite color?'),
    ('What was the name of your first employer?', 'What was the name of your first employer?')
]

question_choices3 = [
    ('What is your favorite sports team?', 'What is your favorite sports team?'),
    ('What was your first concert?', 'What was your first concert?'),
    ('What is the name of your best friend from high school?', 'What is the name of your best friend from high school?'),
    ('What was the name of your first stuffed animal?', 'What was the name of your first stuffed animal?'),
    ('What is your father’s middle name?', 'What is your father’s middle name?'),
    ('Where did you go on your first vacation?', 'Where did you go on your first vacation?')
]


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
        Regexp(r'.*[A-Z].*', message="Must contain an uppercase letter."),
        Regexp(r'.*[a-z].*', message="Must contain a lowercase letter."),
        Regexp(r'.*\d.*', message="Must contain a digit."),
        Regexp(r'.*[\W_].*', message="Must contain a special character.")
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


class SecurityQuestionVerifyForm(FlaskForm):
    answer = StringField('Answer', validators=[DataRequired()])
    submit = SubmitField('Verify')

class MultipleSecurityQuestionsForm(FlaskForm):
    question1 = SelectField('Question 1', choices=question_choices1, validators=[DataRequired()])
    answer1 = StringField('Answer 1', validators=[DataRequired()])
    question2 = SelectField('Question 2', choices=question_choices2, validators=[DataRequired()])
    answer2 = StringField('Answer 2', validators=[DataRequired()])
    question3 = SelectField('Question 3', choices=question_choices3, validators=[DataRequired()])
    answer3 = StringField('Answer 3', validators=[DataRequired()])
    submit = SubmitField('Save Questions')
