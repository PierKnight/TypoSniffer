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








        



