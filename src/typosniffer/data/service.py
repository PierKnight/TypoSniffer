from pydantic import BaseModel
from typosniffer.data.dto import DomainDTO
from typosniffer.data.database import Session
from typosniffer.data.tables import *


def dto_to_orm(dto: BaseModel, orm_cls):
    return orm_cls(**dto.model_dump())


def add_domains(domains: list[DomainDTO]):

    with Session() as session:
        
        session.add_all([dto_to_orm(domain, Domain) for domain in domains])
        session.commit()
        



