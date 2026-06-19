from flask import session, send_file
from captcha.image import ImageCaptcha
import random
import string
import io

def generate_captcha():

    captcha_text = ''.join(
        random.choices(
            string.ascii_uppercase + string.digits,
            k=6
        )
    ).lower()

    session['captcha'] = captcha_text

    image = ImageCaptcha(
        width=450,
        height=150
    )

    data = image.generate(captcha_text)

    return send_file(
        io.BytesIO(data.read()),
        mimetype='image/png'
    )


def verify_captcha(user_input):

    stored_captcha = session.get('captcha')

    if not stored_captcha:
        return False

    return user_input.lower() == stored_captcha.lower()