from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typosniffer.config.config import get_config
import smtplib


def send_email(subject: str, body: str) -> bool:

    cfg = get_config()

    if not cfg.email:
        return False

    server = None

    if cfg.email.starttls:
        server = smtplib.SMTP(cfg.email.smtp_server, cfg.email.smtp_port)
        server.starttls()  # Secure the connection
    else:
        server = smtplib.SMTP_SSL(cfg.email.smtp_server, cfg.email.smtp_port)

    server.login(cfg.email.smtp_username, cfg.email.smtp_password)

    msg = MIMEMultipart()
    msg["From"] = cfg.email.sender_email
    msg["To"] = cfg.email.receiver_email
    msg["Subject"] = subject

    # Attach the body text
    msg.attach(MIMEText(body, "plain"))
    server.send_message(msg)

    # Close the connection
    server.quit()
    return True