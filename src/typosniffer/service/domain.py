
from sqlalchemy.exc import IntegrityError
from typosniffer.data.database import DB
from typosniffer.data.dto import DomainDTO
from typosniffer.data.service import dto_to_orm, orm_to_dto
from typosniffer.data.tables import Domain
from typosniffer.service.suspicious_domain import delete_entity_orphan
from typosniffer.utils.exceptions import ServiceFailure


class DomainResult:
    domain: DomainDTO
    msg: str
    error: bool

def get_domains() -> list[DomainDTO]:
    """Retrieve all domains that need to be scanned"""

    with DB.get_session() as session:

        domains = session.query(Domain).all()

        domain_dtos = [orm_to_dto(domain, DomainDTO) for domain in domains]

        return domain_dtos


def add_domains(domains: list[DomainDTO]):
    """Add list of validated domains to DB"""
    
    with DB.get_session() as session:
        for domain in domains:
            orm_domain = dto_to_orm(domain, Domain)
            session.add(orm_domain)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                raise ServiceFailure(f"Failed adding domains: '{orm_domain.name}' already exists.")

def remove_domains(domains: list[DomainDTO]):
    """Remove list of domains from DB"""

    domain_names = [domain.name for domain in domains]

    with DB.get_session() as session:
        
        deleted_count = session.query(Domain).filter(Domain.name.in_(domain_names)).delete()
        delete_entity_orphan(session)
        session.commit()
        
    return deleted_count

def clear_domains():
    
    with DB.get_session() as session:
        session.query(Domain).delete()
        delete_entity_orphan(session)
        session.commit()