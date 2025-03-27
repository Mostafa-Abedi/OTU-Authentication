import pyotp, qrcode
from base64 import b64encode
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.forms import RegistrationForm, LoginForm, TOTPForm
from app.models import User
from app import db
from flask_login import login_user, logout_user, login_required, current_user

from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash

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
        return redirect(url_for('main.setup_2fa'))
    return render_template('register.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Match by student number or email
        user = User.query.filter(
            (User.email == form.username.data) |
            (User.student_number == form.username.data)
        ).first()
        if user and check_password_hash(user.password, form.password.data):
            session['temp_user_id'] = user.id
            return redirect(url_for('main.verify_2fa'))
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

    # Generate base64-encoded QR code
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
