import enum
from pydantic import BaseModel, ConfigDict, Field
from dnstwist import VALID_FQDN_REGEX

class DomainDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    name: str = Field(pattern=VALID_FQDN_REGEX)


class EntityType(enum.Enum):
    REGISTRAR = "REGISTRAR"
    ADMINISTRATIVE = "ADMINISTRATIVE"
    TECHNICAL = "TECHNICAL"
    ABUSE = "ABUSE"
    

"""
class EntityDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    type: EntityType = EntityType.TECHNICAL
    name: str = Field(min=1, max=100)
    email = Field(min=1, max=100)
    po_box = Field(min=1, max=100)
    ext_address = Field(min=1, max=100)
    street_address = Field(min=1, max=100)
    locality = Field(min=1, max=100)
    region = Field(min=1, max=100)
    postal_code = Field(min=1, max=100)
    country = Field(min=1, max=100)

    __table_args__ = (
        UniqueConstraint('name', 'type', name='uix_entity_type'),
    )
"""