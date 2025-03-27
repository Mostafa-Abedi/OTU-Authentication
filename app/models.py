from app import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    student_number = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    is_verified_2fa = db.Column(db.Boolean, default=False)

    security_question = db.Column(db.String(256), nullable=True)
    security_answer_hash = db.Column(db.String(256), nullable=True)
