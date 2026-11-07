"""Contratos publicos do MVP FARO."""
from typing import Literal
from pydantic import BaseModel, Field, field_validator


class AnalysisRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    observed_html: str | None = Field(default=None, max_length=100_000, description="HTML fornecido pelo analista; nunca coletado remotamente pelo MVP.")

    @field_validator("url")
    @classmethod
    def trim_url(cls, value: str) -> str:
        return value.strip()


class Evidence(BaseModel):
    id: str
    code: str
    title: str
    detail: str
    source: str
    impact: int
    confidence: Literal["low", "medium", "high"]


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Literal["inconclusive", "low", "moderate", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    coverage: Literal["lexical_only", "lexical_and_submitted_html", "lexical_and_feed", "lexical_html_and_feed"]
    classification: Literal["suspicion_only"] = "suspicion_only"
    recommendation: str


class DNSRecord(BaseModel):
    type: Literal["A", "AAAA", "MX", "NS"]
    value: str
    ttl: int = Field(ge=0, le=86400)


class DNSObservation(BaseModel):
    status: Literal["disabled", "observed", "partial", "unavailable"]
    resolver: str
    checked_at: str | None = None
    records: list[DNSRecord] = Field(default_factory=list)
    error_codes: list[str] = Field(default_factory=list)
    note: str


class RDAPObservation(BaseModel):
    status: Literal["disabled", "unsupported", "observed", "unavailable"]
    source: str
    checked_at: str | None = None
    registered_on: str | None = None
    expires_on: str | None = None
    changed_on: str | None = None
    nameservers: list[str] = Field(default_factory=list)
    error_codes: list[str] = Field(default_factory=list)
    note: str


class CTObservation(BaseModel):
    status: Literal["disabled", "observed", "partial", "unavailable"]
    source: str
    checked_at: str | None = None
    certificates_matched: int = Field(default=0, ge=0)
    latest_not_before: str | None = None
    issuers: list[str] = Field(default_factory=list)
    error_codes: list[str] = Field(default_factory=list)
    note: str


class ThreatIntelMatch(BaseModel):
    indicator_type: Literal["url", "hostname"]
    category: Literal["phishing", "malware", "scam", "brand_impersonation", "other"]
    source: str
    observed_at: str
    expires_at: str


class ThreatIntelObservation(BaseModel):
    status: Literal["disabled", "matched", "no_match"]
    source: str
    checked_at: str | None = None
    snapshot_sha256: str | None = None
    matches: list[ThreatIntelMatch] = Field(default_factory=list)
    note: str


class AnalysisResult(BaseModel):
    analysis_id: str
    created_at: str
    normalized_url: str
    hostname: str
    registrable_domain: str
    status: Literal["completed"] = "completed"
    assessment: RiskAssessment
    evidence: list[Evidence]
    limitations: list[str]
    passive_dns: DNSObservation | None = None
    rdap: RDAPObservation | None = None
    certificate_transparency: CTObservation | None = None
    threat_intel: ThreatIntelObservation | None = None


class GraphNode(BaseModel):
    id: str
    kind: str
    label: str
    status: Literal["observed", "reference"]


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    certainty: Literal["observed", "hypothesis"]
    evidence_id: str | None = None


class GraphResult(BaseModel):
    analysis_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    notice: str
