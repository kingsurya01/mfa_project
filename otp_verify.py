
import smtplib
import random
import time
import os
import socket

sender = os.getenv("APP_EMAIL")
app_password = os.getenv("APP_PASSWORD")

OTP_VALIDITY = 60
MAX_RESENDS = 3


def send_otp(receiver):
    if not sender or not app_password:
        raise ValueError(
            "APP_EMAIL or APP_PASSWORD environment variables are not set."
        )

    otp = str(random.randint(100000, 999999))

    try:
        server = smtplib.SMTP(
            "smtp.gmail.com",
            587,
            timeout=10
        )

        server.ehlo()
        server.starttls()
        server.ehlo()

        server.login(
            sender,
            app_password
        )

        message = (
            f"Subject: OTP Verification\n\n"
            f"Your OTP is {otp}\n"
            f"This OTP is valid for {OTP_VALIDITY} seconds."
        )

        server.sendmail(
            sender,
            receiver,
            message
        )

        server.quit()

        return otp, time.time()

    except socket.timeout:
        raise Exception("SMTP connection timed out.")

    except smtplib.SMTPAuthenticationError:
        raise Exception("Invalid Gmail App Password.")

    except Exception as e:
        raise Exception(f"Unable to send OTP: {e}")


def verify_otp(
    user_otp,
    stored_otp,
    otp_time
):
    if time.time() - otp_time > OTP_VALIDITY:
        return False, "OTP Expired"

    if user_otp == stored_otp:
        return True, "OTP Verified"

    return False, "Invalid OTP"
