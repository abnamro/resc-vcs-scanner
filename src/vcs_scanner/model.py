# pylint: disable=no-name-in-module
# Standard Library
import logging
import os
from typing import Annotated

# Third Party
from pydantic import BaseModel, Field, StringConstraints, field_validator
from resc_backend.resc_web_service.schema.repository import Repository
from resc_backend.resc_web_service.schema.vcs_provider import VCSProviders

logger = logging.getLogger(__name__)


class RepositoryRuntime(BaseModel):
    repository_name: str
    repository_id: str
    repository_url: str
    project_key: str
    vcs_instance_name: str
    latest_commit: str | None = None

    def convert_to_repository(self, vcs_instance_id: int) -> Repository:
        return Repository(
            project_key=self.project_key,
            repository_id=self.repository_id,
            repository_name=self.repository_name,
            repository_url=self.repository_url,
            vcs_instance=vcs_instance_id,
            latest_commit=self.latest_commit,
        )


class VCSInstanceRuntime(BaseModel):
    id_: int | None = None
    name: Annotated[str, StringConstraints(max_length=200)]
    provider_type: VCSProviders
    hostname: Annotated[str, StringConstraints(max_length=200)]
    port: Annotated[int, Field(gt=-0, lt=65536)]
    scheme: str
    username: Annotated[str, StringConstraints(max_length=200)]
    token: Annotated[str, StringConstraints(max_length=200)]
    exceptions: list[str] | None = []
    scope: list[str] | None = []
    organization: str | None = None
    include_tags: list[str] = []
    ignore_tags: list[str] = []

    @field_validator("scheme", mode="before")
    @classmethod
    def check_scheme(cls, value):
        allowed_schemes = ["http", "https"]
        if value not in allowed_schemes:
            raise ValueError(f"The scheme '{value}' must be one of the following {', '.join(allowed_schemes)}")
        return value

    @field_validator("organization", mode="before")
    @classmethod
    def check_organization(cls, value, values):
        if not value:
            if values.data["provider_type"] == VCSProviders.AZURE_DEVOPS:
                raise ValueError("The organization field needs to be specified for Azure devops vcs instances")
        return value

    @field_validator("scope", mode="before")
    @classmethod
    def check_scope_and_exceptions(cls, value, values):
        if value and values.data["exceptions"]:
            raise ValueError(
                "You cannot specify bot the scope and exceptions to the scan, only one setting is supported."
            )
        return value

    @field_validator("username", mode="before")
    @classmethod
    def check_presence_of_username(cls, value, values):
        if not os.environ.get(value, ""):
            logger.info(
                f"Username for VCS Instance {values.data['name']} "
                "could not be found in the environment variable {value}"
            )
        return os.environ.get(value, "")

    @field_validator("token", mode="before")
    @classmethod
    def check_presence_of_token(cls, value, values):
        if not os.environ.get(value, ""):
            logger.info(
                f"Token for VCS Instance {values.data['name']} "
                "could not be found in the environment variable {value}"
            )
        return os.environ.get(value, "")

    @field_validator("include_tags", "ignore_tags", mode="before")
    @classmethod
    def check_tag_list(cls, value, validation_info):
        if not value:
            logger.debug(f"[{validation_info.field_name}] empty for VCS [{validation_info.data['name']}].")
            return []
        return value
