import sqlite3
import pyotp
import qrcode
import smtplib
import os

from email.message import EmailMessage
from io import BytesIO

conn = sqlite3.connect(
    "QR_auth.db",
    check_same_thread=False
)

cursor = conn.cursor()


def get_secret(email):

    cursor.execute(
        "SELECT secret FROM QR_auth WHERE email=?",
        (email,)
    )

    data = cursor.fetchone()

    return data[0] if data else None


def create_user(email):


    secret = pyotp.random_base32()



    cursor.execute(
        "INSERT INTO QR_auth VALUES (?, ?)",
        (email, secret)
    )

    conn.commit()

    return secret


def generate_qr(email):



    secret = get_secret(email)

  

    if not secret:
        secret = create_user(email)

    totp = pyotp.TOTP(secret)

    uri = totp.provisioning_uri(
        name=email,
        issuer_name="TANGEDCO"
    )

    img = qrcode.make(uri)

    buffer = BytesIO()

    img.save(
        buffer,
        format="PNG"
    )

    buffer.seek(0)

    return buffer


def verify_authenticator(
    email,
    code
):

    secret = get_secret(email)

    if not secret:
        return False

    totp = pyotp.TOTP(secret)

    return totp.verify(code)


def reset_qr(email):

    sender = os.getenv(
        "APP_EMAIL"
    )

    app_password = os.getenv(
        "APP_PASSWORD"
    )

    new_secret = pyotp.random_base32()

    cursor.execute(
        "UPDATE QR_auth SET secret=? WHERE email=?",
        (new_secret, email)
    )

    conn.commit()

    totp = pyotp.TOTP(
        new_secret
    )

    uri = totp.provisioning_uri(
        name=email,
        issuer_name="TANGEDCO"
    )

    img = qrcode.make(uri)

    buffer = BytesIO()

    img.save(
        buffer,
        format="PNG"
    )

    buffer.seek(0)

    msg = EmailMessage()

    msg["Subject"] = "TANGEDCO QR Reset"
    msg["From"] = sender
    msg["To"] = email

    msg.set_content(
        "Scan the attached QR code."
    )
    msg.add_attachment(
        buffer.read(),
        maintype="image",
        subtype="png",
        filename="qr.png"
    )

    server = smtplib.SMTP(
        "smtp.gmail.com",
        587
    )

    server.starttls()

    server.login(
        sender,
        app_password
    )

    server.send_message(msg)

    server.quit()

    return True

