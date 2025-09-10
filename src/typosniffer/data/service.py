from typing import Type
from pydantic import BaseModel
from typosniffer.data.dto import DomainDTO
from typosniffer.data.database import Session
from typosniffer.data.tables import *
from sqlalchemy.exc import IntegrityError
from typosniffer.sniffing.sniffer import SniffResult
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


def _get_domain(session, domain_name: str) -> Domain:
    return session.query(Domain).filter_by(name=domain_name).first()


def _get_or_create_entity(session, type_: EntityType, **kwargs) -> Entity:
    name = kwargs["name"]
    entity = session.query(Entity).filter_by(name=name, type=type_).first()
    if entity is None:
        entity = Entity(name=name, type=type_, **kwargs)
        session.add(entity)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            entity = session.query(Entity).filter_by(name=name, type=type_).first()
    return entity



def get_or_create_suspicious_domain(
    session,
    name: str,
    original_domain_name: str,  # Only the name is known
    whois_server: str,
    url: str,
    nameservers: list[str] | None = None,
    dnssec: bool = False,
    entities: list[Entity] | None = None,
) -> SuspiciousDomain:

    # Get original domain
    original_domain = _get_domain(session, original_domain_name)

    if original_domain is None:
        raise ValueError(f"Original domain '{original_domain_name}' not found")
    

    # Check if suspicious domain already exists
    suspicious = (
        session.query(SuspiciousDomain)
        .filter_by(name=name, original_domain_id=original_domain.id)
        .first()
    )

    if suspicious:
        suspicious.whois_server = whois_server
        suspicious.url = url
        suspicious.nameservers = nameservers
        suspicious.dnssec = dnssec
    else:
        suspicious = SuspiciousDomain(
            name=name,
            whois_server=whois_server,
            url=url,
            nameservers=nameservers,
            dnssec=dnssec,
            original_domain=original_domain
        )
        session.add(suspicious)

    # Link entities
    if entities:
        for entity in entities:
            if entity not in suspicious.entities:
                suspicious.entities.append(entity)

    
    session.commit()
   

    return suspicious


def add_suspicious_domain(sniff_results: dict[SniffResult, dict]):
    """Add Suspicious domain given sniff result and domain data"""

    with Session() as session:
        for result, data in sniff_results.items():

            entities: list[Entity] = []

            for entityType in EntityType:
                entity = data['entities'].get(entityType.name.lower())
                if entity:
                    entities.append(_get_or_create_entity(session, entityType, entity))


            get_or_create_suspicious_domain(
                session=session,
                name=result.domain,
                original_domain_name=result.original_domain_name,
                nameservers=data['nameservers'],
                url=data['url'],
                dnssec=data['dnssec'],
                whois_server=data['whois_server'],
                entities=entities
            )












        



