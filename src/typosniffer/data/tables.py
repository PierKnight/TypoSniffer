from sqlalchemy import Column, Integer, Enum, ForeignKey, String, Table, UniqueConstraint,DateTime
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    pass

class Domain(Base):
    __tablename__ = "domain"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    suspicious_domains = relationship("SuspiciousDomain", back_populates='original_domain', cascade='all, delete-orphan')


suspicious_domain_entity = Table(
    'suspicious_domain_entity',
    Base.metadata,
    Column('suspicious_domain_id', ForeignKey('suspicious_domain.id'), primary_key=True),
    Column('entity_id', ForeignKey('entity.id'), primary_key=True)
)


class SuspiciousDomain(Base):
    __tablename__ = "suspicious_domain"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    original_domain_id = Column(Integer, ForeignKey('domain.id'), nullable=False)


    whois_server = Column(String(100), nullable=False)
    updated_date = Column(DateTime, nullable=True)
    creation_date = Column(DateTime, nullable=True)
    expiration_date = Column(DateTime, nullable=True)
    url = Column(String(100), nullable=False)

    
    original_domain = relationship("Domain", back_populates='suspicious_domains')
    entities = relationship("Entity", secondary=suspicious_domain_entity, back_populates="suspicious_domains")


class EntityType(enum.Enum):
    REGISTRANT = "a"
    ADMINISTRATIVE = "b"
    TECHNICAL = "c"


class Entity(Base):
    __tablename__ = "entity"

    id = Column(Integer, primary_key=True)

    type = Column(Enum(EntityType), nullable=False)

    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    po_box = Column(String(100), nullable=False)
    ext_address = Column(String(100), nullable=False)
    street_address = Column(String(100), nullable=False)
    locality = Column(String(100), nullable=False)
    region = Column(String(2), nullable=False)
    postal_code = Column(String(10), nullable=False)
    country = Column(String(100), nullable=False)

    __table_args__ = (
        UniqueConstraint('name', 'type', name='uix_entity_type'),
    )

    suspicious_domains = relationship("SuspiciousDomain", secondary=suspicious_domain_entity, back_populates="entities")
    



