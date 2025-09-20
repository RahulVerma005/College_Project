import os
import secrets
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
from flask import session

from flask import Flask, render_template, request, redirect, url_for, flash, send_file,session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail , Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash


# --- App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:password@localhost/attendance_db"


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
import smtplib
from email.message import EmailMessage

EMAIL_ADDRESS = "techprime572@gmail.com"       # Your Gmail address
EMAIL_APP_PASSWORD = "tdhm vryq sfjv fwhc"   # 16-char app password — spaces optional when pasting

msg = EmailMessage()
msg["Subject"] = "Test mail"
msg["From"] = EMAIL_ADDRESS
msg["To"] = "recipient@example.com"
msg.set_content("Hello from Flask/smtplib!")

# SMTP with TLS (recommended): smtp.gmail.com, port 587
with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
    smtp.send_message(msg)


# --- Flask Mail Config ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "techprime572@gmail.com"       # change
app.config['MAIL_PASSWORD'] = "tdhm vryq sfjv fwhc"          # change
mail = Mail(app)


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    roll_no = db.Column(db.String(20), unique=True, nullable=False)  # unique roll number
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # New field    
    password_hash = db.Column(db.String(255), nullable=False)
    qr_token = db.Column(db.String(32), unique=True) 
    qr_expiry = db.Column(db.DateTime)  # expiry time

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('qr_page'))
    else:
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        roll_no = request.form.get('roll_no')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(roll_no=roll_no).first():
            flash("Roll number already registered!" )
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash("Email already registered!")
            return redirect(url_for('signup'))

        new_user = User(roll_no=roll_no, username=username ,email = email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('qr_page'))

    if request.method == 'POST':
        roll_no = request.form.get('roll_no')
        password = request.form.get('password')
        user = User.query.filter_by(roll_no=roll_no).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('qr_page'))
        else:
            flash("Invalid roll number or password!" )

    return render_template('login.html')



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email!", "danger")
            return redirect(url_for('forgot_password'))

        # Generate OTP
        otp = str(secrets.randbelow(999999)).zfill(6)

        # Store OTP + user_id in session
        session['otp'] = otp
        session['user_id'] = user.id

        # Send Email
        msg = Message("Password Reset OTP",
                      sender="your_email@gmail.com",
                      recipients=[email])
        msg.body = f"Hello {user.username},\n\nYour OTP is: {otp}\n\nUse this OTP to reset your password."
        mail.send(msg)

        flash("OTP sent to your email!", "info")
        return redirect(url_for('verify_otp'))

    return render_template('forgot_password.html')


# This is the route to verify the OTP entered by the user

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        if 'otp' not in session or 'user_id' not in session:
            flash("Session expired! Please try again.", "danger")
            return redirect(url_for('forgot_password'))

        if entered_otp == session['otp']:
            user_id = session['user_id']
            session.pop('otp', None)
            return redirect(url_for('reset_password', user_id=user_id))
        else:
            flash("Invalid OTP, please try again.", "danger")
            return redirect(url_for('verify_otp'))

    return render_template('otp_verify.html')


@app.route('/reset-password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form.get('password')
        user.set_password(new_password)
        db.session.commit()
        flash("Password reset successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', user=user)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/qr_code')
@login_required
def qr_page():
    # Generate new QR code with expiry of 60 seconds
    new_token = secrets.token_urlsafe(16)
    current_user.qr_token = new_token
    current_user.qr_expiry = datetime.utcnow() + timedelta(seconds=60)
    db.session.commit()

    # qr_data_url = f"http://192.168.1.34:5000/attendance/{new_token}"
    qr_data_url = url_for('attendance', token=new_token, _external=True)


    return render_template('qr_code.html', qr_data_url=qr_data_url, expiry=60)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all attendance records for the logged-in student
    attendance_records = Attendance.query.filter_by(user_id=current_user.id).order_by(Attendance.date.desc()).all()
    
    return render_template("dashboard.html", attendance_records=attendance_records, username=current_user.username)



@app.route('/generate-qr-image')
@login_required
def generate_qr_image():
    if not current_user.qr_token:
        return redirect(url_for('qr_page'))

    # Check expiry
    if current_user.qr_expiry and datetime.utcnow() > current_user.qr_expiry:
        flash("QR code expired! Generate again.", "warning")
        current_user.qr_token = None
        db.session.commit()
        return redirect(url_for('qr_page'))
    qr_data = url_for('attendance', token=current_user.qr_token, _external=True)

    # qr_data = f"http://192.168.1.34:5000/attendance/{current_user.qr_token}"

    buffer = BytesIO()
    img = qrcode.make(qr_data)
    img.save(buffer, 'PNG')
    buffer.seek(0)
    return send_file(buffer, mimetype='image/png')


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    marked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Optional relationship so you can navigate user.attendances
    user = db.relationship('User', backref=db.backref('attendances', lazy=True))

@app.route('/attendance/<token>')
def attendance(token):
    user = User.query.filter_by(qr_token=token).first()

    if user and user.qr_expiry and datetime.utcnow() <= user.qr_expiry:
        today = datetime.utcnow().date()

        # Check if attendance already exists
        existing_attendance = Attendance.query.filter_by(user_id=user.id, date=today).first()
        if existing_attendance:
            # return "<h1>Your attendance is already marked for today!</h1>"
              return render_template('already_marked.html')

        # Mark new attendance
        new_attendance = Attendance(user_id=user.id, date=today)
        db.session.add(new_attendance)

        # Invalidate QR after marking
        user.qr_token = None
        db.session.commit()

        return render_template('attendance.html', username=user.username)
    else:
        return "<h1>Invalid or Expired QR Code!</h1>"




if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)


