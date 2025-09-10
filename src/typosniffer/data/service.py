from typing import Type
from pydantic import BaseModel
from typosniffer.data.dto import DomainDTO
from typosniffer.data.database import Session
from typosniffer.data.tables import *
from sqlalchemy.exc import IntegrityError

from typosniffer.utils.console import console


def dto_to_orm(dto: BaseModel, orm_cls):
    return orm_cls(**dto.model_dump())


def orm_to_dto(orm, dto: Type[BaseModel]):
    return dto.model_validate(orm)


def get_domains() -> list[DomainDTO]:
    """Retrieve all domains that need to be scanned"""

    with Session() as session:

        domains = session.query(Domain).all()

        domain_dtos = [orm_to_dto(domain, DomainDTO) for domain in domains]

        return domain_dtos


def add_domains(domains: list[DomainDTO]):
    """Add list of validated domains to DB"""

    with Session() as session:
        for domain in domains:
            orm_domain = dto_to_orm(domain, Domain)
            session.add(orm_domain)
            try:
                session.commit()
                console.print(f"Added domain: {orm_domain.name}")
            except IntegrityError:
                session.rollback()
                console.print(f"Domain '{orm_domain.name}' already exists, skipping.")

def remove_domains(domains: list[DomainDTO]):
    """Remove list of domains from DB"""

    domain_names = [domain.name for domain in domains]

    with Session() as session:
        
        deleted_count = session.query(Domain).filter(Domain.name.in_(domain_names)).delete(synchronize_session=False)
        session.commit()
        
    return deleted_count





        



