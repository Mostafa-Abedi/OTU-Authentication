from app import db
from flask_login import UserMixin

class SecurityQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(256), nullable=False)
    answer_hash = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    student_number = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    is_verified_2fa = db.Column(db.Boolean, default=False)
    has_security_questions = db.Column(db.Boolean, default=False)

    # Relationship to multiple security questions
    security_questions = db.relationship('SecurityQuestion', backref='user', lazy=True)
