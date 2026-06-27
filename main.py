from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file,
    abort
)
from captcha_verify import generate_captcha, verify_captcha
from password_verify import (
    verify_password,
    email_exists,
    create_user,
    send_reset_otp,
    verify_reset_otp,
    update_password
)
from otp_verify import send_otp, verify_otp
from authenticator import (
    generate_qr,
    verify_authenticator,
    reset_qr,
    get_secret

)
from ip_track import get_ip
from datetime import date
import sqlite3
from flask import send_file
import random

import time

app = Flask(__name__)
import os

app.secret_key = os.getenv(
    "SECRET_KEY",
    "development-secret"
)

DB = "visitors.db"
MAX_VISITS = 25

CAPTCHAS = [
    {
        "image": "captcha1.jpg",
        "correct": [2, 4, 7],
        "instruction": "Select all cars"
    },
    {
        "image": "captcha2.jpg",
        "correct": [2, 3, 5, 6],
        "instruction": "Select wheelchair"
    },
    {
        "image": "captcha3.jpg",
        "correct": [1, 6],
        "instruction": "Select all traffic lights"
    },
    {
        "image": "captcha4.jpg",
        "correct": [5, 7, 9],
        "instruction": "Select all stairs"
    },
    {
        "image": "captcha5.jpg",
        "correct": [1, 2, 3],
        "instruction": "Select all traffic lights"
    },
    {
        "image": "captcha6.jpg",
        "correct": [5, 6, 8, 9],
        "instruction": "Select motor cycle"
    } 
]
  

def get_new_captcha():

    available = session.get(
        "available",
        CAPTCHAS.copy()
    )

    if not available:
        return None

    captcha = random.choice(
        available
    )

    available.remove(captcha)

    session["available"] = available

    return captcha


@app.before_request
def track_ip():

    
    if request.path != "/":
        return

    ip = get_ip()
    today = str(date.today())

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT count, visit_date, blocked
        FROM ip_logs
        WHERE ip=?
        """,
        (ip,)
    )

    row = cur.fetchone()

    if row:

        count, visit_date, blocked = row

        # Already blocked
        if blocked:
            conn.close()
            abort(403)

        # New day → reset counter
        if visit_date != today:
            count = 0

        count += 1

        if count >= MAX_VISITS:

            cur.execute(
                """
                UPDATE ip_logs
                SET count=?,
                    visit_date=?,
                    blocked=1
                WHERE ip=?
                """,
                (count, today, ip)
            )

            conn.commit()
            conn.close()

            abort(403)

        cur.execute(
            """
            UPDATE ip_logs
            SET count=?,
                visit_date=?
            WHERE ip=?
            """,
            (count, today, ip)
        )

    else:

        cur.execute(
            """
            INSERT INTO ip_logs
            (ip, count, visit_date, blocked)
            VALUES (?, ?, ?, ?)
            """,
            (ip, 1, today, 0)
        )

    conn.commit()
    conn.close()

@app.route('/captcha')
def captcha():
    return generate_captcha()

@app.route('/register')
def register():

    return render_template(
        'register.html'
    )

@app.route('/create_account', methods=['POST'])
def create_account():

    email = request.form['email']
    password = request.form['password']
    confirm = request.form['confirm_password']

    if password != confirm:

        return render_template(
            'register.html',
            error="Passwords do not match"
        )

    if email_exists(email):

        return render_template(
            'register.html',
            error="Email already exists"
        )

    create_user(
        email,
        password
    )

    return render_template(
        'login.html',
        success="Account Created Successfully"
    )
@app.route('/')
def home():
    lock_until = session.get("lock_until")

    if lock_until and time.time() < lock_until:
        return redirect('/locked')
    

    captcha_type = random.choice(
        ['text', 'image']
    )

    session['captcha_type'] = captcha_type
    session["captcha_attempts"] = 0
    error = session.pop(
    "login_error",
    None
    )
    if captcha_type == 'text':
        return render_template(
        'captcha.html',
        error=error
        )

    session["attempts"] = 0
    session["available"] = CAPTCHAS.copy()

    captcha = get_new_captcha()

    session["image_captcha"] = captcha

    return render_template(
        "image_captcha.html",
        image=captcha["image"],
        instruction=captcha["instruction"],
        result="",
        error=error
    )


@app.route('/verify_captcha', methods=['POST'])
def captcha_check():

    captcha_type = session.get(
        'captcha_type'
    )

    if captcha_type == 'text':

        user_input = request.form.get(
            'captcha'
        )

        if verify_captcha(user_input):

            session["captcha_verified"] = True

            return redirect('/login')

        session["captcha_attempts"] += 1

        if session["captcha_attempts"] >= 3:

            session["lock_until"] = (
                time.time() + 30
            )

            return redirect('/locked')

        return render_template(
            'captcha.html',
            error=f"Wrong CAPTCHA ({3 - session['captcha_attempts']} attempts left)"
        )

    else:

        captcha = session.get(
            "image_captcha"
        )

        if not captcha:
            return "CAPTCHA Session Expired"

        selected = request.form.getlist(
            "boxes"
        )

        selected = [
            int(x)
            for x in selected
        ]

        if set(selected) == set(
            captcha["correct"]
        ):
            session["captcha_verified"] = True
            return redirect('/login')

        session["attempts"] += 1

        if session["attempts"] >= 3:

            session["lock_until"] = (
                time.time() + 30
            )

            return redirect('/locked')

        new_captcha = get_new_captcha()

        if new_captcha is None:
            return redirect('/')

        session["image_captcha"] = new_captcha

        return render_template(
            "image_captcha.html",
            image=new_captcha["image"],
            instruction=new_captcha["instruction"],
            result="Incorrect Selection"
        )

    

@app.route('/login')
def login():

    if not session.get("captcha_verified"):
        return redirect('/')

    return render_template('login.html')

@app.route('/login_verify', methods=['POST'])
def login_verify_route():

    email = request.form['email']
    password = request.form['password']
    if verify_password(email, password):

        otp, otp_time = send_otp(email)

        session['email'] = email
        session["login_verified"] = True
        session['otp'] = otp
        session['otp_time'] = otp_time
        session['resend_count'] = 0
        session['otp_attempts'] = 0

        return redirect('/otp')


    session['login_error'] = "Invalid Email or Password"

    return redirect('/')

@app.route('/forgot_password')
def forgot_password():

    return render_template(
        'forgot_password.html'
    )

@app.route(
    '/verify_reset_otp',
    methods=['POST']
)
def verify_reset_otp_route():

    otp = request.form['otp']

    email = session.get(
        'reset_email'
    )

    if verify_reset_otp(
        email,
        otp
    ):

        return redirect(
            '/reset_password'
        )

    return render_template(
        'reset_otp.html',
        error="Invalid OTP"
    )
@app.route(
    '/send_reset_otp',
    methods=['POST']
)
def send_reset_otp_route():

    email = request.form['email']

    if not email_exists(email):

        return render_template(
            'forgot_password.html',
            error="Email not found"
        )

    send_reset_otp(email)

    session['reset_email'] = email

    return redirect('/reset_otp')
@app.route('/reset_otp')
def reset_otp():

    return render_template(
        'reset_otp.html'
    )

@app.route('/reset_password')
def reset_password():

    return render_template(
        'reset-password.html'
    )

@app.route(
    '/update_password',
    methods=['POST']
)
def update_password_route():

    new_password = request.form[
        'new_password'
    ]

    confirm_password = request.form[
        'confirm_password'
    ]

    if new_password != confirm_password:

        return render_template(
            'reset_password.html',
            error="Passwords do not match"
        )

    email = session.get(
        'reset_email'
    )

    update_password(
        email,
        new_password
    )

    session.pop(
        'reset_email',
        None
    )

    return render_template(
        'login.html',
        success="Password Updated Successfully"
    )

@app.route('/otp')
def otp():

    if not session.get("login_verified"):
        return redirect('/')
    

    remaining = 60

    if session.get('otp_time'):

        remaining = max(
            0,
            60 - int(
                time.time() -
                session['otp_time']
            )
        )

    return render_template(
        'otp.html',
        seconds=remaining
    )


@app.route('/verify_otp', methods=['POST'])
def verify_otp_route():

    user_otp = request.form['otp']

    success, message = verify_otp(
        user_otp,
        session.get('otp'),
        session.get('otp_time')
    )

    if success:

        session.pop(
            'otp_attempts',
            None
        )

        session['auth_attempts'] = 0
        session["otp_verified"] = True

        return redirect('/authenticator')

    if message == "OTP Expired":

        count = session.get(
            'resend_count',
            0
        )

        if count >= 3:

            session.clear()

            return redirect('/')

        email = session.get('email')

        otp, otp_time = send_otp(
            email
        )

        session['otp'] = otp
        session['otp_time'] = otp_time
        session['resend_count'] = count + 1
        session['otp_attempts'] = 0

        remaining = 60

        return render_template(
            'otp.html',
            error="OTP expired. New OTP sent to your email.",
            seconds=remaining
        )

    session['otp_attempts'] = (
        session.get(
            'otp_attempts',
            0
        ) + 1
    )

    if session['otp_attempts'] >= 3:

        session.clear()

        return redirect('/')

    remaining = max(
        0,
        60 - int(
            time.time() -
            session['otp_time']
        )
    )

    return render_template(
        'otp.html',
        error=f"{message} ({3 - session['otp_attempts']} attempts left)",
        seconds=remaining
    )

@app.route('/resend_otp', methods=['POST'])
def resend_otp():

    count = session.get('resend_count', 0)

    if count >= 3:
        return "Maximum resend limit reached"

    email = session.get('email')

    otp, otp_time = send_otp(email)

    session['otp'] = otp
    session['otp_time'] = otp_time
    session['resend_count'] = count + 1

    return redirect('/otp')


@app.route('/authenticator')
def authenticator():

    email = session.get('email')
    session['auth_attempts'] = 0
    if not session.get("otp_verified"):
        return redirect('/')

    new_user = get_secret(email) is None

    return render_template(
        'authenticator.html',
        new_user=new_user
    )

@app.route('/qr_code')
def qr_code():
    
    if not session.get("otp_verified"):
        return redirect('/')
    
    email = session.get('email')

    qr_buffer = generate_qr(email)

    print("SESSION EMAIL =", email)
    return send_file(
        qr_buffer,
        mimetype='image/png'
    )

@app.route(
    '/verify_authenticator',
    methods=['POST']
)
def verify_authenticator_route():

    code = request.form['code']

    email = session['email']

    if verify_authenticator(
        email,
        code
    ):

        session.pop(
            'auth_attempts',
            None
        )
        session["authenticated"] = True
        return redirect('/success')

    session['auth_attempts'] = (
        session.get(
            'auth_attempts',
            0
        ) + 1
    )

    if session['auth_attempts'] >= 3:

        session["lock_until"] = (
            time.time() + 60
        )

        return redirect('/')

    return render_template(
        'authenticator.html',
        error=f"Invalid Authenticator Code ({3 - session['auth_attempts']} attempts left)",
        new_user=False
    )

@app.route(
    '/reset_qr',
    methods=['POST']
)
def reset_qr_route():

    email = session.get(
        'email'
    )

    reset_qr(email)

    return redirect(
        '/authenticator'
    )

@app.route('/success')
def success():

    if not session.get("authenticated"):
        return redirect('/')

    return """
    <h1>MFA Authentication Successful</h1>
    """
     
@app.route('/locked')
def locked():

    lock_until = session.get(
        "lock_until"
    )

    if not lock_until:
        return redirect('/')

    remaining = int(
        lock_until - time.time()
    )

    if remaining < 0:
        remaining = 0

    return render_template(
        "locked.html",
        seconds=remaining
    )

@app.route('/unlock')
def unlock():

    session.pop(
        "lock_until",
        None
    )

    return redirect('/')
if __name__ == "__main__":
    app.run(debug=True)

