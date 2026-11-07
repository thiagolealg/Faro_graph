"""Validated inputs for case review and evidence export."""
from __future__ import annotations

import re
import uuid
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=5, max_length=120)
    analysis_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        cleaned = value.strip()
        if not 5 <= len(cleaned) <= 120 or any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
            raise ValueError("Titulo invalido")
        # Case titles are not intended as storage for raw sensitive URLs or PII.
        if re.search(r"https?://|@|[?&#=]", cleaned, re.I):
            raise ValueError("Nao inclua links, emails ou parametros no titulo")
        return cleaned

    @field_validator("analysis_ids")
    @classmethod
    def unique_analyses(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(set(value)) != len(value):
            raise ValueError("IDs de analise duplicados")
        return value


class CaseLinkRequest(BaseModel):
    analysis_id: uuid.UUID


class CaseReviewRequest(BaseModel):
    decision: Literal["inconclusive", "suspected", "false_positive", "requires_escalation"]
    rationale: str = Field(min_length=20, max_length=1000)

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 20 or any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in cleaned):
            raise ValueError("Fundamentacao invalida")
        # Avoid accidental retention of identifying or secret material.
        if re.search(r"https?://|\b[\w.+-]+@[\w.-]+\.\w+\b|(?:token|password|senha|secret|apikey)\s*[:=]", cleaned, re.I):
            raise ValueError("Remova URLs, emails e segredos da fundamentacao")
        return cleaned


class CaseStatusRequest(BaseModel):
    status: Literal["open", "triage", "under_review", "closed"]
    expected_version: int = Field(ge=1)
