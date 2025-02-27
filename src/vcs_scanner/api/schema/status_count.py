# Third Party
from pydantic import BaseModel

# First Party
from vcs_scanner.api.schema.finding_status import FindingStatus


class StatusCount(BaseModel):
    status: FindingStatus
    count: int = 0
