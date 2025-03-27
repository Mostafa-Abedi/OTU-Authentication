# 🔐 Flask 2FA Authentication App

A secure and modular Flask web application implementing **Two-Factor Authentication (2FA)**. This app features user registration, login, profile management, and configurable 2FA options, including **Time-Based One-Time Passwords (TOTP)** with QR code integration. Ideal for learning and demonstrating identity and access management (IAM) concepts.

---

## 🚀 Features

- 🔒 Secure user registration and login using hashed passwords  
- 👤 Profile page displaying user info  
- 📱 Two-Factor Authentication using TOTP (Time-Based One-Time Passwords)  
- 📷 QR code generation for scanning with Google Authenticator or similar apps  
- ✅ 2FA verification step after login for enhanced security  
- 🧪 Built with Flask, WTForms, Flask-Login, PyOTP, and more  

---

## 📦 Tech Stack

- Python 3.x  
- Flask  
- SQLite  
- Flask-WTF  
- Flask-Login  
- PyOTP  
- qrcode  
- Bootstrap  

---

## 🛠️ Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/flask-2fa-auth-app.git
   cd flask-2fa-auth-app
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install the dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**

   ```bash
   flask run
   ```

5. Open your browser and go to `http://localhost:5000`

---

## 📂 Project Structure

```
flask-2fa-auth-app/
├── app/
│   ├── static/
│   ├── templates/
│   ├── __init__.py
│   ├── routes.py
│   ├── models.py
│   └── forms.py
├── venv/
├── config.py
├── requirements.txt
├── run.py
└── README.md
```

---

## 🧪 Usage

1. Register a new user.
2. Log in with your credentials.
3. Set up 2FA by scanning the generated QR code with an authenticator app.
4. Enter the 6-digit TOTP code to verify.
5. Upon successful verification, access your profile securely.

---

## ✨ Future Enhancements

- Email/SMS-based OTP  
- Security questions  
- QR-code-based login  
- Standalone Authenticator app  
- Multi-account support  
- Offline functionality  
- Logging and access tracking  

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Made with ❤️ by Mostafa Abedi 
For SOFE 4840U: Software & Computer Security @ Ontario Tech University
