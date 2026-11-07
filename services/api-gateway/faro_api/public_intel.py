"""OSINT via endpoints publicos fixos, sem acesso ao website investigado.

- Apenas hosts HTTPS de provedores explicitamente permitidos.
- Sem proxies, redirects, URLs arbitrarias ou dados pessoais de RDAP.
- Saida minimizada para o armazenamento (nenhuma resposta bruta).
- Ausencia de resultados nunca significa reputacao limpa.

A rede do deployment deve impor uma allowlist de egress adicional; o MVP
continua inadequado para exposicao publica sem esse controle.
"""
from __future__ import annotations

import json
import re
import ssl
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .schemas import CTObservation, RDAPObservation


# Provedores verificados para os TLDs suportados; sem discovery dinamico no MVP.
RDAP_ENDPOINTS = {
    "br": "https://rdap.registro.br/domain/",
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
}
_CT_HOST = "crt.sh"
_ALLOWED_HOSTS = frozenset({"rdap.registro.br", "rdap.verisign.com", _CT_HOST})
_HOSTNAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.ASCII)
_DATE = re.compile(r"^\d{4}-\d\d-\d\d(?:[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)?$", re.ASCII)
_MAX_BODY = 300_000


class PublicIntelError(RuntimeError):
    """Erro sanitizado; nao transporta detalhes do fornecedor para a resposta."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _validate_provider_url(url: str) -> None:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.fragment):
        raise PublicIntelError("ProviderNotAllowed")
    if parsed.hostname == _CT_HOST:
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path not in {"", "/"} or set(query) != {"q", "output"} or query.get("output") != ["json"]:
            raise PublicIntelError("ProviderNotAllowed")
        if len(query["q"]) != 1 or not _HOSTNAME.fullmatch(query["q"][0]):
            raise PublicIntelError("ProviderNotAllowed")
    else:
        prefix = "https://rdap.registro.br/domain/" if parsed.hostname == "rdap.registro.br" else None
        if parsed.hostname == "rdap.verisign.com":
            valid_prefix = ("https://rdap.verisign.com/com/v1/domain/", "https://rdap.verisign.com/net/v1/domain/")
        else:
            valid_prefix = (prefix,)
        if parsed.query or not any(url.startswith(base) for base in valid_prefix if base):
            raise PublicIntelError("ProviderNotAllowed")
        domain = url.rsplit("/", 1)[-1]
        if not _HOSTNAME.fullmatch(domain) or ".." in domain:
            raise PublicIntelError("ProviderNotAllowed")
        if parsed.hostname == "rdap.verisign.com" and domain.rsplit(".", 1)[-1] != parsed.path.split("/")[1]:
            raise PublicIntelError("ProviderNotAllowed")


def fetch_provider_json(url: str) -> Any:
    """GET estritamente limitado a provedores de OSINT publicos.

    O destino nunca e uma URL fornecida pelo usuario. Respostas HTTP 3xx e
    tamanhos excessivos falham fechados. Proxies ambientais sao ignorados.
    """
    _validate_provider_url(url)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
    request = Request(url, headers={"User-Agent": "FaroGraph-OSINT/0.4", "Accept": "application/rdap+json, application/json"})
    try:
        with opener.open(request, timeout=3.0) as response:
            # A biblioteca nunca deve seguir 3xx (defesa adicional ao handler).
            if response.status != 200:
                raise PublicIntelError("ProviderStatusError")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower().strip()
            if content_type not in {"application/json", "application/rdap+json"}:
                raise PublicIntelError("InvalidContentType")
            payload = response.read(_MAX_BODY + 1)
            if len(payload) > _MAX_BODY:
                raise PublicIntelError("ResponseTooLarge")
            return json.loads(payload.decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise PublicIntelError("NotFound") from None
        raise PublicIntelError("ProviderHTTPError") from None
    except (URLError, TimeoutError, OSError):
        raise PublicIntelError("NetworkUnavailable") from None
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise PublicIntelError("MalformedProviderResponse") from None


def _domain(value: str) -> str:
    value = value.lower().rstrip(".")
    if not _HOSTNAME.fullmatch(value) or ".." in value or len(value) > 253:
        raise ValueError("Dominio invalido")
    return value


def _event_date(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40 or not _DATE.fullmatch(value):
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).date().isoformat()
    except ValueError:
        return None


def _error_code(exc: Exception) -> str:
    return str(exc) if isinstance(exc, PublicIntelError) else "InvalidProviderData"


class RDAPCollector:
    def __init__(self, fetcher: Callable[[str], Any] = fetch_provider_json):
        self.fetcher = fetcher

    def collect(self, registrable_domain: str) -> RDAPObservation:
        checked_at = datetime.now(timezone.utc).isoformat()
        try:
            registrable_domain = _domain(registrable_domain)
            tld = registrable_domain.rsplit(".", 1)[-1]
            base = RDAP_ENDPOINTS.get(tld)
            if base is None:
                return RDAPObservation(status="unsupported", source="registry_rdap", checked_at=checked_at,
                    error_codes=["TldNotSupported"], note="TLD sem endpoint RDAP homologado nesta versao.")
            payload = self.fetcher(base + quote(registrable_domain, safe=".-"))
            if not isinstance(payload, dict) or payload.get("objectClassName") != "domain":
                raise ValueError("Resposta RDAP nao corresponde a um dominio")
            reported = payload.get("ldhName", "")
            if not isinstance(reported, str) or reported.lower().rstrip(".") != registrable_domain:
                raise ValueError("Dominio da resposta RDAP divergente")
            event_dates: dict[str, str] = {}
            events = payload.get("events") or []
            if not isinstance(events, list):
                raise ValueError("Eventos RDAP invalidos")
            for event in events[:50]:
                if not isinstance(event, dict):
                    continue
                kind = event.get("eventAction")
                if kind in {"registration", "expiration", "last changed"}:
                    date = _event_date(event.get("eventDate"))
                    if date and kind not in event_dates:
                        event_dates[kind] = date
            nameservers = payload.get("nameservers") or []
            if not isinstance(nameservers, list):
                raise ValueError("Nameservers RDAP invalidos")
            sanitized_ns: list[str] = []
            for ns in nameservers[:20]:
                if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str):
                    try:
                        hostname = _domain(ns["ldhName"])
                    except ValueError:
                        continue
                    if hostname not in sanitized_ns:
                        sanitized_ns.append(hostname)
            return RDAPObservation(status="observed", source="registry_rdap", checked_at=checked_at,
                registered_on=event_dates.get("registration"), expires_on=event_dates.get("expiration"),
                changed_on=event_dates.get("last changed"), nameservers=sanitized_ns[:8],
                note="Dados publicos de registro; contato do titular e outros dados pessoais nao sao armazenados.")
        except Exception as exc:
            return RDAPObservation(status="unavailable", source="registry_rdap", checked_at=checked_at,
                error_codes=[_error_code(exc)],
                note="Consulta RDAP indisponivel; nenhuma inferencia de legitimidade foi realizada.")


class CertificateTransparencyCollector:
    """Consulta historica a crt.sh (nao verifica TLS servido no momento)."""

    def __init__(self, fetcher: Callable[[str], Any] = fetch_provider_json):
        self.fetcher = fetcher

    def collect(self, registrable_domain: str) -> CTObservation:
        checked_at = datetime.now(timezone.utc).isoformat()
        try:
            domain = _domain(registrable_domain)
            # Somente dominio registravel: nunca compartilhar paths, tokens ou HTML.
            url = "https://crt.sh/?" + urlencode({"q": domain, "output": "json"})
            payload = self.fetcher(url)
            if not isinstance(payload, list):
                raise ValueError("Formato CT invalido")
            # Sem emitir lista de SANs: minimizar exposicao e nao inventar participantes.
            cert_ids: set[str] = set()
            issuers: list[str] = []
            latest_date: str | None = None
            for entry in payload[:2000]:
                if not isinstance(entry, dict):
                    continue
                name_value = entry.get("name_value", "")
                if not isinstance(name_value, str):
                    continue
                names = {x.strip().lower().removeprefix("*.").rstrip(".") for x in name_value.splitlines()[:40]}
                if not any(n == domain or n.endswith("." + domain) for n in names):
                    continue
                cert_id = str(entry.get("id", ""))
                if not cert_id.isdigit() or len(cert_id) > 32 or cert_id in cert_ids:
                    continue
                cert_ids.add(cert_id)
                date = _event_date(entry.get("not_before"))
                if date and (latest_date is None or date > latest_date):
                    latest_date = date
                issuer = entry.get("issuer_name")
                if isinstance(issuer, str) and 0 < len(issuer) <= 120 and "\n" not in issuer:
                    if issuer not in issuers:
                        issuers.append(issuer)
            truncated = len(payload) > 2000
            return CTObservation(status="partial" if truncated else "observed", source="crt_sh_ct_index",
                checked_at=checked_at, certificates_matched=len(cert_ids), latest_not_before=latest_date,
                issuers=issuers[:5], error_codes=["ResultLimitReached"] if truncated else [],
                note="Indice historico CT; nao confirma o certificado TLS atualmente servido ou titularidade da pagina.")
        except Exception as exc:
            return CTObservation(status="unavailable", source="crt_sh_ct_index", checked_at=checked_at,
                error_codes=[_error_code(exc)], note="Consulta CT indisponivel; ausencia de dados nao significa site seguro.")
