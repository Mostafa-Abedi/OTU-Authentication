import random
import pyotp
import qrcode
from base64 import b64encode
from io import BytesIO

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models import User, SecurityQuestion
from app.forms import (
    RegistrationForm,
    LoginForm,
    TOTPForm,
    MultipleSecurityQuestionsForm,
    SecurityQuestionVerifyForm
)

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        otp_secret = pyotp.random_base32()
        user = User(
            student_number=form.student_number.data,
            email=form.email.data,
            password=generate_password_hash(form.password1.data),
            otp_secret=otp_secret
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        session['temp_user_id'] = user.id
        return redirect(url_for('main.auth_method_choice'))
    return render_template('register.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.email == form.username.data) |
            (User.student_number == form.username.data)
        ).first()
        if user and check_password_hash(user.password, form.password.data):
            session['temp_user_id'] = user.id
            return redirect(url_for('main.auth_method_choice'))
        else:
            flash("Invalid student number/email or password.")
    return render_template('sign_in.html', form=form)


@main.route('/2fa', methods=['GET', 'POST'])
def verify_2fa():
    form = TOTPForm()
    user_id = session.get('temp_user_id')
    if not user_id:
        return redirect(url_for('main.login'))
    user = User.query.get(user_id)
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(form.token.data):
            login_user(user)
            user.is_verified_2fa = True
            db.session.commit()
            session.pop('temp_user_id', None)
            return redirect(url_for('main.profile'))
        else:
            flash("Invalid code.")
    return render_template('verify_2fa.html', form=form)


@main.route('/2fa/setup', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    form = TOTPForm()
    user = current_user
    totp = pyotp.TOTP(user.otp_secret)
    otp_uri = totp.provisioning_uri(name=user.email, issuer_name="School Login 2FA")

    img = qrcode.make(otp_uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_b64 = b64encode(buffer.getvalue()).decode("utf-8")
    qr_code_url = f"data:image/png;base64,{qr_b64}"

    if form.validate_on_submit():
        if totp.verify(form.token.data):
            user.is_verified_2fa = True
            db.session.commit()
            flash("2FA setup complete.")
            return redirect(url_for('main.profile'))
        else:
            flash("Invalid code. Please try again.")

    return render_template("setup_2fa.html", form=form, qr_code_url=qr_code_url, otp_secret=user.otp_secret)


@main.route('/profile')
@login_required
def profile():
    return render_template("profile.html", user=current_user)


@main.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main.route('/setup/security-question', methods=['GET', 'POST'])
@login_required
def setup_security_question():
    form = MultipleSecurityQuestionsForm()

    if form.validate_on_submit():
        SecurityQuestion.query.filter_by(user_id=current_user.id).delete()

        questions = [
            (form.question1.data, form.answer1.data),
            (form.question2.data, form.answer2.data),
            (form.question3.data, form.answer3.data)
        ]

        for question_text, answer in questions:
            sq = SecurityQuestion(
                question=question_text,
                answer_hash=generate_password_hash(answer.strip().lower()),
                user_id=current_user.id
            )
            db.session.add(sq)

        current_user.has_security_questions = True
        db.session.commit()
        flash("Security questions saved.")
        return redirect(url_for('main.profile'))

    return render_template("setup_security_question.html", form=form)


    return render_template("setup_security_question.html", form=form)


@main.route('/verify/security-question', methods=['GET', 'POST'])
def verify_security_question():
    user_id = session.get('temp_user_id')
    if not user_id:
        return redirect(url_for('main.login'))

    user = User.query.get(user_id)
    questions = user.security_questions
    if not questions:
        flash("No security questions found for this user.")
        return redirect(url_for('main.login'))

    if 'question_ids_attempted' not in session:
        session['question_ids_attempted'] = []
        session['current_question_id'] = None
        session['question_attempts'] = 0

    remaining_questions = [q for q in questions if q.id not in session['question_ids_attempted']]
    if not remaining_questions:
        flash("All security questions answered incorrectly. Try another method.")
        session.pop('question_ids_attempted', None)
        session.pop('question_attempts', None)
        session.pop('current_question_id', None)
        return redirect(url_for('main.auth_method_choice'))

    if not session.get('current_question_id'):
        current_question = random.choice(remaining_questions)
        session['current_question_id'] = current_question.id
    else:
        current_question = next((q for q in remaining_questions if q.id == session['current_question_id']), None)
        if not current_question:
            current_question = random.choice(remaining_questions)
            session['current_question_id'] = current_question.id

    form = SecurityQuestionVerifyForm()

    if form.validate_on_submit():
        if check_password_hash(current_question.answer_hash, form.answer.data.strip().lower()):
            login_user(user)
            session.pop('temp_user_id', None)
            session.pop('question_ids_attempted', None)
            session.pop('question_attempts', None)
            session.pop('current_question_id', None)
            return redirect(url_for('main.profile'))
        else:
            session['question_attempts'] += 1
            flash("Incorrect answer.")
            if session['question_attempts'] >= 3:
                session['question_ids_attempted'].append(current_question.id)
                session['current_question_id'] = None
                session['question_attempts'] = 0
                return redirect(url_for('main.verify_security_question'))

    return render_template("verify_security_question.html", form=form, question_text=current_question.question)


@main.route('/auth-method-choice', methods=['GET', 'POST'])
def auth_method_choice():
    user_id = session.get('temp_user_id')
    if not user_id:
        return redirect(url_for('main.login'))

    user = User.query.get(user_id)
    if not user:
        flash("Session expired.")
        return redirect(url_for('main.login'))

    # 🛠️ New logic: if no methods are configured, log them in
    if not user.has_security_questions and not user.is_verified_2fa:
        login_user(user)
        session.pop('temp_user_id', None)
        flash("You haven't set up any authentication methods. Go to your profile to set one up.", 'warning')
        return redirect(url_for('main.profile'))

    if request.method == 'POST':
        method = request.form.get('method')
        if method == 'totp' and user.is_verified_2fa:
            return redirect(url_for('main.verify_2fa'))
        elif method == 'security' and user.has_security_questions:
            return redirect(url_for('main.verify_security_question'))
        else:
            flash("Invalid or unavailable method selected.")
            return redirect(url_for('main.auth_method_choice'))

    return render_template('auth_method_choice.html', user=user)

