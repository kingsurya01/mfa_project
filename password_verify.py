import bcrypt
import sqlite3
import random
import smtplib
import os
from email.message import EmailMessage

conn = sqlite3.connect(
    "users.db",
    check_same_thread=False
)

cursor = conn.cursor()

SENDER = os.getenv("APP_EMAIL")
APP_PASSWORD = os.getenv("APP_PASSWORD")

otp_store = {}
def create_user(
    email,
    password
):

    conn = sqlite3.connect(
        "users.db"
    )

    cur = conn.cursor()

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    cur.execute(
        """
        INSERT INTO users
        (email, password_hash)
        VALUES (?, ?)
        """,
        (
            email,
            password_hash
        )
    )

    conn.commit()

    conn.close()

    return True
def verify_password(email,password):

    email = email
    password = password.encode("utf-8")

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    cur.execute(
        "SELECT password_hash FROM users WHERE email=?",
        (email,)
    )

    row = cur.fetchone()

    conn.close()

    if row is None:
        print("User not found")
        return None

    stored_hash = row[0].encode("utf-8")

    if bcrypt.checkpw(password, stored_hash):
        return True

    
    return False

def email_exists(email):

    cursor.execute(
        """
        SELECT email
        FROM users
        WHERE email=?
        """,
        (email,)
    )

    return cursor.fetchone() is not None


def send_reset_otp(receiver):

    otp = str(
        random.randint(
            100000,
            999999
        )
    )

    msg = EmailMessage()

    msg["Subject"] = "Password Reset OTP"
    msg["From"] = SENDER
    msg["To"] = receiver

    msg.set_content(
        f"""
Your OTP is:

{otp}

Use this OTP to reset your password.
"""
    )

    try:

        with smtplib.SMTP(
            "smtp.gmail.com",
            587
        ) as server:

            server.starttls()

            server.login(
                SENDER,
                APP_PASSWORD
            )

            server.send_message(msg)

        otp_store[receiver] = otp

        return True

    except Exception as e:

        print("Mail Error:", e)

        return False


def verify_reset_otp(
    email,
    entered_otp
):

    return (
        otp_store.get(email)
        == entered_otp
    )


def update_password(
    email,
    new_password
):

    password_hash = bcrypt.hashpw(
        new_password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    cursor.execute(
        """
        UPDATE users
        SET password_hash=?
        WHERE email=?
        """,
        (
            password_hash,
            email
        )
    )

    conn.commit()

    otp_store.pop(
        email,
        None
    )

    return True