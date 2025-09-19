

from typing import Optional
from zipfile import Path
from typosniffer.config.config import get_config
from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.data.tables import Domain, SuspiciousDomain, WebsiteRecord
from sqlalchemy.orm import Session, joinedload


def add_record(session: Session, record: WebsiteRecord):
    return session.add(record)


def get_last_record_of_domain(session: Session, domain: SuspiciousDomainDTO) -> Optional[WebsiteRecord]:
    return session.query(WebsiteRecord) \
        .join(WebsiteRecord.suspicious_domain) \
        .filter(SuspiciousDomain.name == domain.name) \
        .order_by(WebsiteRecord.creation_date.desc()) \
        .first()

def get_screenshot_from_record(record: WebsiteRecord) -> Path:

    timestamp = record.creation_date.strftime("%Y%m%d_%H%M%S")
    image_file = get_config().inspection.screenshot_dir / record.suspicious_domain.name / f"{timestamp}.png"
    return image_file



def get_domain_records(session: Session, domain_names: list[str]):
    return (
        session.query(WebsiteRecord)
        .options(
            joinedload(WebsiteRecord.suspicious_domain)
            .joinedload(SuspiciousDomain.original_domain)
        )
        .join(WebsiteRecord.suspicious_domain)
        .join(SuspiciousDomain.original_domain)
        .filter(Domain.name.in_(domain_names))
        .all()
    )

def get_suspicious_domain_records(session: Session, suspicious_domains: list[str]):
    return (
        session.query(WebsiteRecord)
        .options(joinedload(WebsiteRecord.suspicious_domain))
        .join(WebsiteRecord.suspicious_domain) 
        .filter(SuspiciousDomain.name.in_(suspicious_domains))
        .all()
    )

def remove_records_screenshot(records: list[WebsiteRecord]):
    """given a list of records delete saved screenshots"""

    for record in records:
        domain_screenshot_file: Path = get_screenshot_from_record(record)

        if domain_screenshot_file.exists():
            domain_screenshot_file.unlink()

            if not any(domain_screenshot_file.parent.iterdir()):
                domain_screenshot_file.parent.rmdir()

def remove_all_screenshots():
    pass #TODO remove all screenshots from folder
        
    