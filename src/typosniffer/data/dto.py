import enum
from typing import Type
from pydantic import BaseModel, ConfigDict, Field
from dnstwist import VALID_FQDN_REGEX

class DomainDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    name: str = Field(pattern=VALID_FQDN_REGEX)


class EntityType(enum.Enum):
    REGISTRANT= "REGISTRANT"
    RESELLER= "RESELLER"
    REGISTRAR = "REGISTRAR"
    ADMINISTRATIVE = "ADMINISTRATIVE"
    TECHNICAL = "TECHNICAL"
    ABUSE = "ABUSE"
    BILLING = "BILLING"

class SuspiciousDomain(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    name: str = Field(pattern=VALID_FQDN_REGEX)
    original_domain: str = Field(pattern=VALID_FQDN_REGEX)



def dto_to_orm(dto: BaseModel, orm_cls):
    return orm_cls(**dto.model_dump())


def orm_to_dto(orm, dto: Type[BaseModel]):
    return dto.model_validate(orm)