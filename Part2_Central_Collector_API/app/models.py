from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EventType = Literal[
    "connection", "login_attempt", "login_success", "command",
    "file_download", "session_end", "heartbeat"
]

class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: UUID
    node_id: Literal["node-01", "node-02", "node-03"]
    event_type: EventType
    timestamp: datetime
    session_id: str | None
    attacker_ip: str | None
    protocol: str | None
    details: dict[str, Any]

    @field_validator("attacker_ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        if value is not None:
            ip_address(value)
        return value

    @model_validator(mode="after")
    def validate_event_contract(self):
        if self.event_type == "heartbeat":
            if any(value is not None for value in (self.session_id, self.attacker_ip, self.protocol)):
                raise ValueError("heartbeat requires session_id, attacker_ip, and protocol to be null")
            if not isinstance(self.details.get("status"), str) or not self.details["status"].strip():
                raise ValueError("heartbeat requires details.status")
            return self

        if not all((self.session_id, self.attacker_ip, self.protocol)):
            raise ValueError("non-heartbeat events require session_id, attacker_ip, and protocol")
        required_keys = {
            "login_attempt": ("username",),
            "command": ("command",),
            "session_end": ("status",),
        }
        for key in required_keys.get(self.event_type, ()):
            if not isinstance(self.details.get(key), str) or not self.details[key].strip():
                raise ValueError(f"{self.event_type} requires details.{key}")
        if self.event_type == "file_download":
            if not self.details.get("download_url") and not self.details.get("file_hash"):
                raise ValueError("file_download requires details.download_url or details.file_hash")
        return self

class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[Event] = Field(min_length=1)

class BatchResult(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    errors: list[dict[str, str]] = Field(default_factory=list)
