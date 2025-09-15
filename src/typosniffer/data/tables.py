from sqlalchemy import Column, Integer, Enum, ForeignKey, String, Table, UniqueConstraint,DateTime, ARRAY, Boolean
from sqlalchemy.orm import relationship, declarative_base

from typosniffer.data.dto import EntityType



Base = declarative_base()

class Domain(Base):
    __tablename__ = "domain"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    suspicious_domains = relationship("SuspiciousDomain", backref='original_domain', cascade='all, delete-orphan, delete', passive_deletes=True)


suspicious_domain_entity = Table(
    'suspicious_domain_entity',
    Base.metadata,
    Column('suspicious_domain_id', ForeignKey('suspicious_domain.id', ondelete='CASCADE'), primary_key=True),
    Column('entity_id', ForeignKey('entity.id', ondelete='CASCADE'), primary_key=True)
)


class SuspiciousDomain(Base):
    __tablename__ = "suspicious_domain"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    original_domain_id = Column(Integer, ForeignKey('domain.id', ondelete='CASCADE'), nullable=False)


    whois_server = Column(String(100), nullable=False)
    updated_date = Column(DateTime, nullable=True)
    creation_date = Column(DateTime, nullable=True)
    expiration_date = Column(DateTime, nullable=True)
    url = Column(String(100), nullable=False)

    status = Column(ARRAY(String(50)))
    nameservers = Column(ARRAY(String(50)))
    dnssec= Column(Boolean())

    entities = relationship("Entity", secondary=suspicious_domain_entity, back_populates="suspicious_domains")
    records = relationship("WebsiteRecord", backref='suspicious_domain', cascade='all, delete-orphan, delete', passive_deletes=True)




class Entity(Base):
    __tablename__ = "entity"

    id = Column(Integer, primary_key=True)

    type = Column(Enum(EntityType), nullable=False)

    url = Column(String(100), nullable=False, default='')
    name = Column(String(100), nullable=False, default='')
    email = Column(String(100), nullable=True)
    po_box = Column(String(100), nullable=True)
    ext_address = Column(String(100), nullable=True)
    street_address = Column(String(100), nullable=True)
    locality = Column(String(100), nullable=True)
    region = Column(String(100), nullable=True)
    postal_code = Column(String(10), nullable=True)
    country = Column(String(100), nullable=True)

    __table_args__ = (
        UniqueConstraint('name', 'type', 'url', name='uix_entity_type'),
    )

    suspicious_domains = relationship("SuspiciousDomain", secondary=suspicious_domain_entity, back_populates="entities")

class WebsiteRecord(Base):
    __tablename__ = "website_record"

    id = Column(Integer, primary_key=True)  
    suspicious_domain_id = Column(Integer, ForeignKey('suspicious_domain.id', ondelete='CASCADE'), nullable=False)

    website_url = Column(String, nullable=False)  
    screenshot_id = Column(Integer, nullable=False),
    screenshot_hash = Column(Integer(), nullable=False)
    creation_date = Column(DateTime, nullable=False)
    website_exists = Column(Boolean, nullable=False)

    __table_args__ = (
        UniqueConstraint('suspicious_domain_id', 'screenshot_id'),
    )
    


    