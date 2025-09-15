

from typing import Optional
from typosniffer.data.dto import DomainDTO
from typosniffer.data.tables import SuspiciousDomain, WebsiteRecord
from sqlalchemy.orm import Session


def add_record(session: Session, record: WebsiteRecord):
    return session.add(record)


def get_last_record_of_domain(session: Session, domain: DomainDTO) -> Optional[WebsiteRecord]:
    return session.query(WebsiteRecord) \
        .join(WebsiteRecord.suspicious_domain) \
        .filter(SuspiciousDomain.name == domain.name) \
        .order_by(WebsiteRecord.creation_date.desc()) \
        .first()
    