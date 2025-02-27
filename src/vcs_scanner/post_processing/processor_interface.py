# Standard Library
import abc
from enum import Enum

# Third Party
from vcs_scanner.api.schema.finding import FindingBase


class PostProcessingStatus(Enum):
    NOT_PROCESSED = 1
    FALSE_POSITIVE = 2
    TRUE_POSITIVE = 3


class Processor(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def process_finding(self, finding: FindingBase) -> PostProcessingStatus:
        raise NotImplementedError
