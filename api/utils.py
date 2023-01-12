from django.conf import settings
from django.core.mail import send_mail, EmailMessage


def send_email(email, token):
    try:
        subject = "Verify Your Account"
        message = f'Click on the link to verify  http://127.0.0.1:8000/verify?token={token}'
        email_from = settings.EMAIL_HOST_USER
        to = [email]
        send_mail(subject, message, email_from, to)

    except Exception as e:
        return False
    return True

@staticmethod
def send_reset_mail(data):
    email = EmailMessage(
        subject=data['email_subject'], body=data['email_body'], to=[data['to_email']]
    )
    email.send()