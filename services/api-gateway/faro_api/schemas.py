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
    coverage: Literal["lexical_only", "lexical_and_submitted_html"]
    classification: Literal["suspicion_only"] = "suspicion_only"
    recommendation: str


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
