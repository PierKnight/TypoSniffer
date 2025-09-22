from sqlalchemy.orm import Session

from typosniffer.data.database import DB
from typosniffer.data.dto import EntityType, SuspiciousDomainDTO
from typosniffer.data.tables import Domain, Entity, SuspiciousDomain
from typosniffer.sniffing.sniffer import SniffResult
from typosniffer.utils.exceptions import ServiceFailure
from typosniffer.utils.logger import log


def get_suspicious_domains() -> list[SuspiciousDomainDTO]:

    with DB.get_session() as session:
        
        suspicious_domains = session.query(SuspiciousDomain).all()

        return [SuspiciousDomainDTO(id = sd.id, name = sd.name, original_domain=sd.original_domain.name) for sd in suspicious_domains]

        
def delete_entity_orphan(session: Session):
    """Delete all the entities without any suspicious domains"""
    session.query(Entity).filter(~Entity.suspicious_domains.any()).delete(synchronize_session=False)


def remove_suspicious_domain(suspicious_domains: list[str]) -> int:


    with DB.get_session() as session, session.begin():

        to_delete = session.query(SuspiciousDomain).filter(SuspiciousDomain.name.in_(suspicious_domains)).all()
        deleted_count = len(to_delete)
        for d in to_delete:
            session.delete(d)
        delete_entity_orphan(session)

    return deleted_count


def _get_or_create_entity(session: Session, entity_type: EntityType, entity_data: dict) -> Entity:
    """create or get a domain entity based on a dictionary containing the relevant data"""


    log.debug(f"Adding new entity: {entity_data}")

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

        log.debug(f"Added new entity: {entity}")
    else:
        log.debug(f"Entity already persisted {entity}")


    return entity


def create_suspicious_domain(
    session: Session,
    original_domain_name: str, 
    suspicious_domain: SuspiciousDomain,
    entities: list[Entity] | None = None, 
) -> SuspiciousDomain:
    """Create or get a SuspiciousDomain and attach entities"""
    log.debug(f"Creating new suspicious domain: {suspicious_domain.name}")


    entities = entities or []

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
        # Assign original domain and entities at creation
        suspicious_domain.original_domain = original_domain
        suspicious_domain.entities = entities
        session.add(suspicious_domain)
        suspicious = suspicious_domain
        log.debug(f"Added new suspicious domain: {suspicious}")
    else:
        # Add any new entities that are not already linked
        for entity in entities:
            if entity not in suspicious.entities:
                suspicious.entities.append(entity)
        log.debug(f"Suspicious domain already persisted: {suspicious}")

    return suspicious




def add_suspicious_domain(sniff_results: set[SniffResult], whois_data: dict):
    """Add Suspicious domain given sniff result and domain data"""

    log.info(f"Adding {len(sniff_results)} to database")


    with DB.get_session() as session, session.begin():
        for result in sniff_results:
    
            log.debug(f"Init {result.domain} persistance")

            
            data = whois_data.get(result.domain, {})

            #list of entities present in the whois data
            found_entities: list[Entity] = []
            
            for entityType, entities in data.get('entities', {}).items():
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
                    nameservers=data.get('nameservers'),
                    url=data.get('url'),
                    dnssec=data.get('dnssec'),
                    whois_server=data.get('whois_server'),
                    entities=found_entities,
                    updated_date = data.get('last_changed_date'),
                    creation_date = data.get('registration_date'),
                    expiration_date = data.get('expiration_date'),
                    status = data.get('status')
                )
            )
            log.debug(f"End {result.domain} persistance")





