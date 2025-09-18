from email.message import EmailMessage
from typing import Any, List, Optional, Tuple
from typosniffer.config.config import get_config
import smtplib
from jinja2 import Environment, FileSystemLoader, Template

from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.utils.utility import to_serializable

def datetime_format(value, fmt="%Y-%m-%d %H:%M"):
    return value.strftime(fmt)

    
def get_body(context: Any):

    serialized = to_serializable(context)

    template_file = get_config().email.template

    env = Environment(
        loader=FileSystemLoader(template_file.parent),
        autoescape=True, 
    )

    env.filters['datetime'] = datetime_format

    template: Template = env.get_template(template_file.name)

    html_content = template.render(serialized)

    return html_content



def send_email(subject: str, text: str, html_body: str,
               attachments: Optional[List[Tuple[str, bytes, str, str]]] = None) -> bool:
    """
    Send an email with text, HTML body, and optional attachments.
    
    Args:
        subject (str): Email subject
        text (str): Plain text body
        html_body (str): HTML body
        attachments (list, optional): List of tuples (filename, content_bytes, maintype, subtype)
    
    Returns:
        bool: True if email sent, False otherwise
    """
    cfg = get_config()

    if not cfg.email:
        return False

    # Choose STARTTLS or SSL
    if cfg.email.starttls:
        server = smtplib.SMTP(cfg.email.smtp_server, cfg.email.smtp_port)
        server.starttls()
    else:
        server = smtplib.SMTP_SSL(cfg.email.smtp_server, cfg.email.smtp_port)

    server.login(cfg.email.smtp_username, cfg.email.smtp_password)

    msg = EmailMessage()
    msg["From"] = cfg.email.sender_email
    msg["To"] = cfg.email.receiver_email
    msg["Subject"] = subject

    # Body
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")

    # Attachments (if any)
    if attachments:
        for filename, content_bytes, maintype, subtype in attachments:
            msg.add_attachment(content_bytes,
                               maintype=maintype,
                               subtype=subtype,
                               filename=filename)

    # Send and close
    server.send_message(msg)
    server.quit()
    return True
