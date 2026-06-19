import smtplib
import random
import time
import os

sender = os.getenv("APP_EMAIL")
app_password = os.getenv("APP_PASSWORD")

OTP_VALIDITY = 60
MAX_RESENDS = 3


def send_otp(receiver):

    otp = str(
        random.randint(
            100000,
            999999
        )
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

