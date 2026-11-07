"""Reputacao por snapshot local, autorizado e de validade limitada.

Nao faz download, consultas remotas, resolucao DNS nem transmite URLs a fornecedores.
Um match e um indicador reportado, nao prova de autoria ou de fraude atual.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .schemas import ThreatIntelMatch, ThreatIntelObservation
from .url_security import SafeURL, URLValidationError, normalize_url

_MAX_BYTES = 2_000_000
_MAX_ITEMS = 10_000
_KINDS = {"phishing", "malware", "scam", "brand_impersonation", "other"}
_SOURCE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,63}$")


def _utc_date(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("data ISO 8601 invalida")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("data ISO 8601 invalida") from exc
    if result.tzinfo is None:
        raise ValueError("data sem timezone nao e aceita")
    return result.astimezone(timezone.utc)


@dataclass(frozen=True)
class _Record:
    indicator_type: str
    indicator: str
    source: str
    category: str
    observed_at: datetime
    expires_at: datetime


class ThreatIntelSnapshot:
    """Snapshot fechado e validado no bootstrap; alteracoes exigem reinicio.

    Um arquivo malformado deve impedir o inicio quando a integracao estiver ativa.
    """

    def __init__(self, file_path: str):
        path = Path(file_path)
        if not path.is_file() or path.is_symlink():
            raise ValueError("feed deve ser um arquivo regular nao simbolico")
        if path.stat().st_size > _MAX_BYTES:
            raise ValueError("feed excede tamanho permitido")
        raw = path.read_bytes()
        if len(raw) > _MAX_BYTES:
            raise ValueError("feed excede tamanho permitido")
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.loaded_at = datetime.now(timezone.utc).isoformat()
        try:
            content = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("feed deve ser UTF-8") from exc
        self.records: list[_Record] = []
        now = datetime.now(timezone.utc)
        for number, line in enumerate(content.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if len(line) > 4096 or len(self.records) >= _MAX_ITEMS:
                raise ValueError("limites do feed excedidos")
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError("item nao e objeto")
                if set(obj) != {"type", "indicator", "source", "category", "observed_at", "expires_at"}:
                    raise ValueError("campos inesperados ou obrigatorios ausentes")
                source, category, kind = obj["source"], obj["category"], obj["type"]
                if not isinstance(source, str) or not _SOURCE.fullmatch(source):
                    raise ValueError("source invalida")
                if category not in _KINDS or kind not in {"url", "hostname"}:
                    raise ValueError("tipo ou categoria invalido")
                observed = _utc_date(obj["observed_at"])
                expires = _utc_date(obj["expires_at"])
                if observed > now + timedelta(minutes=5) or expires <= observed or expires - observed > timedelta(days=90):
                    raise ValueError("intervalo de validade invalido")
                indicator = obj["indicator"]
                if not isinstance(indicator, str) or not indicator or len(indicator) > 2048:
                    raise ValueError("indicador invalido")
                if kind == "url":
                    parts = urlsplit(indicator)
                    if parts.query or parts.fragment:
                        raise ValueError("URLs com query/fragment nao sao aceitas no snapshot")
                    normalized = normalize_url(indicator)
                    # A sanitizacao de credenciais nao pode alargar correspondencias.
                    if normalized.url != indicator or "[REDACTED]" in normalized.url:
                        raise ValueError("URL precisa estar previamente normalizada, sem dados sensiveis")
                    indicator = normalized.url
                else:
                    if "/" in indicator or ":" in indicator or "@" in indicator or indicator.startswith("."):
                        raise ValueError("hostname invalido")
                    normalized = normalize_url("https://" + indicator)
                    if normalized.hostname != indicator:
                        raise ValueError("hostname deve estar em formato IDNA minusculo")
                self.records.append(_Record(kind, indicator, source, category, observed, expires))
            except (ValueError, TypeError, URLValidationError) as exc:
                raise ValueError(f"feed invalido na linha {number}: {exc}") from exc

    def check(self, target: SafeURL) -> ThreatIntelObservation:
        now = datetime.now(timezone.utc)
        matched: list[ThreatIntelMatch] = []
        # Evitar duplicatas e nao permitir matching de subdominio por sufixo.
        seen: set[tuple[str, str, str]] = set()
        for record in self.records:
            if now >= record.expires_at:
                continue
            if record.indicator_type == "url" and record.indicator != target.url:
                continue
            if record.indicator_type == "hostname" and record.indicator != target.hostname:
                continue
            key = (record.indicator_type, record.source, record.category)
            if key in seen:
                continue
            seen.add(key)
            matched.append(ThreatIntelMatch(indicator_type=record.indicator_type,
                category=record.category, source=record.source,
                observed_at=record.observed_at.isoformat(), expires_at=record.expires_at.isoformat()))
            if len(matched) == 10:
                break
        return ThreatIntelObservation(status="matched" if matched else "no_match", source="local_licensed_snapshot",
            checked_at=now.isoformat(), snapshot_sha256=self.sha256,
            matches=matched, note=("Indicadores reportados no feed; nao constituem prova de fraude atual ou autoria."
                if matched else "Sem correspondencia ativa no snapshot; isso nao representa garantia de seguranca."))


def configured_snapshot() -> ThreatIntelSnapshot | None:
    flag = os.getenv("FARO_TI_ENABLED", "0").lower()
    if flag not in {"0", "1", "true", "false", "yes", "no"}:
        raise RuntimeError("FARO_TI_ENABLED deve ser booleano explicito")
    if flag in {"0", "false", "no"}:
        return None
    if os.getenv("FARO_TI_LICENSE_ACK") != "1":
        raise RuntimeError("FARO_TI_LICENSE_ACK=1 e obrigatorio; confirme autorizacao/licenca antes de usar feed")
    path = os.getenv("FARO_TI_PATH", "")
    if not path or not os.path.isabs(path):
        raise RuntimeError("FARO_TI_PATH deve ser caminho absoluto para feed autorizado")
    try:
        return ThreatIntelSnapshot(path)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Falha ao carregar feed local de reputacao: {exc}") from exc
