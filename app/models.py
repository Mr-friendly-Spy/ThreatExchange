"""Domain validation layered over generated models; regeneration never overwrites this file."""

import re
from datetime import UTC
from typing import Self

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from app.generated.models import ThreatCreateRequest as GeneratedCreate
from app.generated.models import ThreatUpdateRequest as GeneratedUpdate

RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$")


class ThreatValidation(BaseModel):
    model_config = ConfigDict(validate_default=True)

    @field_validator("name", check_fields=False)
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Name must contain non-whitespace characters")
        return value

    @field_validator("md5", check_fields=False)
    @classmethod
    def normalize_md5(cls, value: str) -> str:
        return value.lower()

    @field_validator("tags", mode="before", check_fields=False)
    @classmethod
    def unique_tags(cls, value):
        if (
            isinstance(value, list)
            and all(isinstance(item, str) for item in value)
            and len(set(value)) != len(value)
        ):
            raise ValueError("Tags must be unique")
        return value

    @field_validator("first_seen", "last_seen", mode="before", check_fields=False)
    @classmethod
    def require_rfc3339(cls, value):
        if value is not None and (not isinstance(value, str) or not RFC3339.fullmatch(value)):
            raise ValueError("Use an RFC 3339 date-time string with a timezone")
        return value

    @field_validator("first_seen", "last_seen", check_fields=False)
    @classmethod
    def normalize_time(cls, value):
        return value.astimezone(UTC) if value is not None else None

    @model_validator(mode="after")
    def chronological_observations(self) -> Self:
        if self.last_seen is not None:
            if self.first_seen is None:
                raise ValueError("last_seen requires first_seen")
            if self.last_seen < self.first_seen:
                raise ValueError("last_seen must not precede first_seen")
        return self


class ThreatCreateRequest(ThreatValidation, GeneratedCreate):
    """Create payload with normalized MD5 and validated observation metadata."""


class ThreatUpdateRequest(ThreatValidation, GeneratedUpdate):
    """Full replacement payload; MD5 and server timestamps are not writable."""
