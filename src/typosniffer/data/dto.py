import idna
import enum
from enum import Enum
from typing import Optional, Type
from pydantic import BaseModel, ConfigDict, Field, field_validator
from dnstwist import VALID_FQDN_REGEX


def punycode_validator(value: str) -> str:
    """Convert a domain name to punycode (IDNA ASCII)."""
    return idna.encode(value).decode("ascii")

class DomainDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)
    
    id: Optional[int] = None
    name: str = Field(pattern=VALID_FQDN_REGEX)

    @field_validator("name", mode="before")
    @classmethod
    def name_to_punycode(cls, v: str) -> str:
        return punycode_validator(v)


class EntityType(enum.Enum):
    REGISTRANT= "REGISTRANT"
    RESELLER= "RESELLER"
    REGISTRAR = "REGISTRAR"
    ADMINISTRATIVE = "ADMINISTRATIVE"
    TECHNICAL = "TECHNICAL"
    ABUSE = "ABUSE"
    BILLING = "BILLING"
    SPONSOR = "SPONSOR"



class SuspiciousDomainDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    id: int
    name: str = Field(pattern=VALID_FQDN_REGEX)
    original_domain: DomainDTO

    @field_validator("name", mode="before")
    @classmethod
    def name_to_punycode(cls, v: str) -> str:
        return punycode_validator(v)

class SniffCriteria(BaseModel):

    model_config = ConfigDict(frozen=True)

    damerau_levenshtein: Optional[int] = Field(1, ge=1)
    hamming: Optional[int] = Field(None, ge=1)
    jaro: Optional[float] = Field(0.9, ge=0, le=1)
    jaro_winkler: Optional[float] = Field(None, ge=0, le=1)
    levenshtein: Optional[int] = Field(None, ge=1)
    tf_idf: Optional[float] = Field(None, ge=0, le=1)

    tf_idf_ngram: list[int] = Field([1, 2])

class WebsiteStatus(Enum):
    CHANGED = 'CHANGED'
    DOWN = 'DOWN'
    UP = 'UP'

    def is_website_up(self) -> bool:
        return self in (WebsiteStatus.UP, WebsiteStatus.CHANGED)

def dto_to_orm(dto: BaseModel, orm_cls):
    return orm_cls(**dto.model_dump())

def orm_to_dto(orm, dto: Type[BaseModel]):
    return dto.model_validate(orm)
