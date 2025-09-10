from pydantic import BaseModel, ConfigDict, Field
from dnstwist import VALID_FQDN_REGEX

class DomainDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)
    
    name: str = Field(pattern=VALID_FQDN_REGEX)
    