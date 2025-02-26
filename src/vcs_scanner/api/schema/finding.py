# Standard Library
import datetime
import sys
from typing import Annotated

# Third Party
from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class FindingBase(BaseModel):
    file_path: Annotated[str, StringConstraints(max_length=500)]
    line_number: Annotated[int, Field(gt=-1)]
    column_start: Annotated[int, Field(gt=-1)]
    column_end: Annotated[int, Field(gt=-1)]
    commit_id: Annotated[str, StringConstraints(max_length=120)]
    commit_message: str
    commit_timestamp: datetime.datetime
    author: Annotated[str, StringConstraints(max_length=200)]
    email: Annotated[str, StringConstraints(max_length=100)]
    event_sent_on: datetime.datetime | None = None
    rule_name: Annotated[str, StringConstraints(max_length=400)]


class FindingPatch(BaseModel):
    event_sent_on: datetime.datetime


class FindingCreate(FindingBase):
    repository_id: Annotated[int, Field(gt=0)]

    @classmethod
    def create_from_base_class(cls, base_object: FindingBase, repository_id: int):
        return cls(**(dict(base_object)), repository_id=repository_id)


class Finding(FindingBase):
    pass


class FindingRead(FindingCreate):
    id_: Annotated[int, Field(gt=0)]
    scan_ids: Annotated[list[Annotated[int, Field(gt=0)]], Field(min_length=None, max_length=sys.maxsize)] | None = None
    model_config = ConfigDict(from_attributes=True)

