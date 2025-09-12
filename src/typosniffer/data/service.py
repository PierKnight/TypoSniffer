from typing import Dict, Type
from pydantic import BaseModel
from typosniffer.data.dto import DomainDTO
from typosniffer.data.database import DB
from typosniffer.data.tables import *
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from typosniffer.sniffing.sniffer import SniffResult
from typosniffer.utils.console import console


def dto_to_orm(dto: BaseModel, orm_cls):
    return orm_cls(**dto.model_dump())


def orm_to_dto(orm, dto: Type[BaseModel]):
    return dto.model_validate(orm)


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
                console.print(f"Added domain: {orm_domain.name}")
            except IntegrityError:
                session.rollback()
                console.print(f"Domain '{orm_domain.name}' already exists, skipping.")

def remove_domains(domains: list[DomainDTO]):
    """Remove list of domains from DB"""

    domain_names = [domain.name for domain in domains]

    with DB.get_session() as session:
        
        deleted_count = session.query(Domain).filter(Domain.name.in_(domain_names)).delete()
        _delete_entity_orphan(session)
        session.commit()
        
    return deleted_count

def clear_domains():
    with DB.get_session() as session:
        session.query(Domain).delete()
        _delete_entity_orphan(session)
        session.commit()

def _get_domain(session: Session, domain_name: str) -> Domain:
    """Get a domain given its name"""
    return session.query(Domain).filter_by(name=domain_name).first()


def _delete_entity_orphan(session: Session):
    """Delete all the entities without any suspicious domains"""

    orphans = session.query(Entity).filter(~Entity.suspicious_domains.any()).all()
    for orphan in orphans:
        session.delete(orphan)

def _get_or_create_entity(session: Session, entity_type: EntityType, entity_data: dict) -> Entity:
    """create or get a domain entity based on a dictionary containing the relevant data"""

    name = entity_data.get("name", "")
    url = entity_data.get("url", "")
    entity = session.query(Entity).filter_by(name=name, type=entity_type, url=url).first()
    if entity is None:

        flat_data = entity_data.copy()
        address_data = flat_data.pop("address", {})
        flat_data.update(address_data)

        valid_fields = {col.name for col in Entity.__table__.columns}
        filtered_data = {k: v for k, v in flat_data.items() if k in valid_fields}
        filtered_data['type'] = entity_type

        entity = Entity(**filtered_data)
        session.add(entity)
        try:
            session.flush()  # ensures it has an id
        except IntegrityError:
            session.rollback()
    return entity





def create_suspicious_domain(
    session: Session,
    original_domain_name: str, 
    suspicious_domain: SuspiciousDomain,
    entities: list[Entity] | None = None, 
) -> SuspiciousDomain:
    """Create a new suspicious domain in the database"""
    
    # Get original domain
    original_domain = _get_domain(session, original_domain_name)
    if original_domain is None:
        raise ValueError(f"Original domain '{original_domain_name}' not found")
    
    # Check if suspicious domain already exists
    suspicious = (
        session.query(SuspiciousDomain)
        .filter_by(name=suspicious_domain.name, original_domain_id=original_domain.id)
        .first()
    )

    if suspicious is None:
        # Add suspicious domain to session BEFORE setting relationships
        suspicious = suspicious_domain
        suspicious.original_domain = original_domain
        session.add(suspicious)
        session.flush() 
    # Link entities (existing or new)
    for entity in entities:
        if entity not in suspicious.entities:
            suspicious.entities.append(entity)

    session.commit()
    return suspicious



def add_suspicious_domain(sniff_results: set[SniffResult], whois_data: Dict):
    """Add Suspicious domain given sniff result and domain data"""

    with DB.get_session() as session:
        for result in sniff_results:
            
            data = whois_data.get(result.domain)

            if data:

                #list of entities present in the whois data
                found_entities: list[Entity] = []
                
                for entityType in EntityType:
                    entities = data['entities'].get(entityType.name.lower(), [])
                    
                    for entity in entities:
                        found_entities.append(_get_or_create_entity(session, entityType, entity))
                        
                create_suspicious_domain(
                    session=session,
                    original_domain_name=result.original_domain,
                    entities=found_entities,
                    suspicious_domain=SuspiciousDomain(
                        name=result.domain,
                        nameservers=data['nameservers'],
                        url=data['url'],
                        dnssec=data['dnssec'],
                        whois_server=data['whois_server'],
                        entities=found_entities,
                        updated_date = data['last_changed_date'],
                        creation_date = data['registration_date'],
                        expiration_date = data['expiration_date'],
                        status = data['status']
                    )
                )













        



