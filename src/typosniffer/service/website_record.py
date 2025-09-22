

import os
from typing import Optional
from zipfile import Path
from typosniffer.config.config import get_config
from typosniffer.data.database import DB
from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.data.tables import SuspiciousDomain, WebsiteRecord
from sqlalchemy.orm import Session
from sqlalchemy import event

from typosniffer.utils.logger import log

@event.listens_for(Session, "before_flush")
def delete_screenshots(session, flush_context, instances):

    for obj in session.deleted:
        
        if isinstance(obj, WebsiteRecord):
            remove_record_screenshot(obj)


def add_record(session: Session, record: WebsiteRecord):
    return session.add(record)


def get_last_record_of_domain(session: Session, domain: SuspiciousDomainDTO) -> Optional[WebsiteRecord]:
    return session.query(WebsiteRecord) \
        .join(WebsiteRecord.suspicious_domain) \
        .filter(SuspiciousDomain.name == domain.name) \
        .order_by(WebsiteRecord.creation_date.desc()) \
        .first()

def suspicious_domain_records(domain: SuspiciousDomainDTO):
    with DB.get_session() as session, session.begin():
        return (
            session.query(WebsiteRecord)
            .join(WebsiteRecord.suspicious_domain) 
            .filter(SuspiciousDomain.name == domain.name)
            .first()
        )

def get_screenshot_from_record(record: WebsiteRecord) -> Path:

    timestamp = record.creation_date.strftime("%Y%m%d_%H%M%S")
    image_file = get_config().inspection.screenshot_dir / record.suspicious_domain.name / f"{timestamp}.png"
    return image_file

def remove_record_screenshot(record: WebsiteRecord):
    domain_screenshot_file: Path = get_screenshot_from_record(record)
    log.debug(f"Removing screenshot in {domain_screenshot_file}")
    if domain_screenshot_file.exists():
        domain_screenshot_file.unlink()

        if not any(domain_screenshot_file.parent.iterdir()):
            domain_screenshot_file.parent.rmdir()

def remove_all_screenshots():
    for dirpath, dirnames, filenames in os.walk(get_config().inspection.screenshot_dir, topdown=False):
        # Remove all .png files
        for filename in filenames:
            if filename.lower().endswith(".png"):
                file_path = os.path.join(dirpath, filename)
                try:
                    os.remove(file_path)
                    log.debug(f"Deleted: {file_path}")
                except Exception as e:
                    log.debug(f"Failed to delete {file_path}: {e}")

        try:
            if not os.listdir(dirpath):
                os.rmdir(dirpath)
                log.debug(f"Removed empty folder: {dirpath}")
        except Exception as e:
            log.debug(f"Failed to remove {dirpath}: {e}")
        
    