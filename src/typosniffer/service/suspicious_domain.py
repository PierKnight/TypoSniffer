from sqlite3 import IntegrityError
from sqlalchemy.orm import Session

from typosniffer.data.database import DB
from typosniffer.data.dto import EntityType
from typosniffer.data.tables import Domain, Entity, SuspiciousDomain
from typosniffer.sniffing.sniffer import SniffResult
from typosniffer.utils.exceptions import ServiceFailure

def delete_entity_orphan(session: Session):
    """Delete all the entities without any suspicious domains"""

    session.query(Entity).filter(~Entity.suspicious_domains.any()).delete(synchronize_session=False)

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
            session.flush()
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
    original_domain = session.query(Domain).filter_by(name=original_domain_name).first()

    if original_domain is None:
        raise ServiceFailure(f"Original domain '{original_domain_name}' not found")
    
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



def add_suspicious_domain(sniff_results: set[SniffResult], whois_data: dict):
    """Add Suspicious domain given sniff result and domain data"""

    with DB.get_session() as session:
        for result in sniff_results:
            
            data = whois_data.get(result.domain)

            if data:

                #list of entities present in the whois data
                found_entities: list[Entity] = []
                
                for entityType, entities in data['entities'].items():
                    if not entities:
                        continue
                    for entity_data in entities:
                        found_entities.append(_get_or_create_entity(session, EntityType[entityType.upper()], entity_data))

                        
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






