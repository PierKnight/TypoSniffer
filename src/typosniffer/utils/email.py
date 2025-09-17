from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any
from typosniffer.config.config import get_config
import smtplib
from jinja2 import Environment, FileSystemLoader, Template

from typosniffer.utils.utility import to_serializable

    
def get_body(context: Any):

    serialized = to_serializable(context)

    template_file = get_config().email.template

    env = Environment(
        loader=FileSystemLoader(template_file.parent),
        autoescape=True, 
    )

    template: Template = env.get_template(template_file.name)

    html_content = template.render(serialized)

    return html_content



def send_email(subject: str, html: str) -> bool:

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
    msg.attach(MIMEText(html, "html"))
    server.send_message(msg)

    # Close the connection
    server.quit()
    return True