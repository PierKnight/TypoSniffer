from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typosniffer.config.config import cfg
import smtplib


def send_email(subject: str, body: str) -> bool:

    if not cfg.email:
        return False

    server = smtplib.SMTP(cfg.email.smpt_server, cfg.email.smtp_port)
    server.starttls()  # Secure the connection
    server.login(cfg.email.sender_email, cfg.email.smtp_password)

    msg = MIMEMultipart()
    msg["From"] = cfg.email.sender_email
    msg["To"] = cfg.email.receiver_email
    msg["Subject"] = subject

    # Attach the body text
    msg.attach(MIMEText(body, "plain"))
    return True