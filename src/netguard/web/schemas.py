"""API response models: they document the v1 contract in the OpenAPI schema."""

from __future__ import annotations

from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")

Status = Literal["queued", "running", "done", "failed", "cancelled"]
SeverityName = Literal["LOW", "MEDIUM", "HIGH"]


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(description="Number of matching items, ignoring limit/offset")
    limit: int
    offset: int


class Health(BaseModel):
    status: Literal["ok"]
    version: str
    schema_version: int


class Rule(BaseModel):
    rule_id: str
    detector: str
    title: str
    technique: str | None
    enabled: bool
    settings: dict[str, Any] = Field(description="The rule's configuration section in the server's base config")
    doc: str


class Capture(BaseModel):
    id: str
    filename: str
    sha256: str
    size_bytes: int
    format: Literal["pcap", "pcapng"]
    created_at: str


class AnalysisSummary(BaseModel):
    id: str
    capture_id: str
    status: Status
    created_at: str
    started_at: str | None
    finished_at: str | None
    error: str | None
    attempts: int
    netguard_version: str
    alert_count: int
    flow_count: int
    flows_truncated: bool


class Analysis(AnalysisSummary):
    config: dict[str, Any]
    capture_info: dict[str, Any] | None
    stats: dict[str, Any] | None


class AnalysisRequest(BaseModel):
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Overrides of the server's base configuration, TOML-shaped, "
        'e.g. {"portscan": {"min_distinct_ports": 30}}',
    )


class Technique(BaseModel):
    id: str
    name: str
    url: str


class AlertOut(BaseModel):
    id: int
    analysis_id: str
    schema_version: str
    alert_id: str
    rule_id: str
    detector: str
    title: str
    severity: SeverityName
    first_seen: str
    last_seen: str
    src: str | None
    dst: str | None
    summary: str
    technique: Technique | None
    evidence: dict[str, Any]


class FlowOut(BaseModel):
    id: int
    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: str
    last_seen: str
    duration_seconds: float
    state: str
    history: str
    orig_packets: int
    orig_bytes: int
    orig_payload_bytes: int
    resp_packets: int
    resp_bytes: int
    resp_payload_bytes: int
    retransmissions: int
    seq_gaps: int
    end_reason: str
