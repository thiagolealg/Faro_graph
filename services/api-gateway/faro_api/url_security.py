"""Validacao e normalizacao: nao faz requisicoes ao destino informado."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit, quote

import idna


class URLValidationError(ValueError):
    """Endereco invalido ou inseguro para a triagem."""


@dataclass(frozen=True)
class SafeURL:
    url: str
    hostname: str
    registrable_domain: str
    scheme: str
    port: int | None
    is_idn: bool


def _registrable_domain(hostname: str) -> str:
    # Lista conservadora; versao completa devera usar Public Suffix List atualizada.
    multi = {"com.br", "net.br", "org.br", "gov.br", "edu.br", "co.uk", "org.uk", "com.au", "co.jp"}
    parts = hostname.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in multi:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def normalize_url(raw: str) -> SafeURL:
    if not isinstance(raw, str) or not raw or len(raw) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise URLValidationError("URL ausente, longa demais ou com caracteres de controle")
    raw = raw.strip()
    if raw.startswith("//") or "\\" in raw or "\x00" in raw:
        raise URLValidationError("Formato de URL ambiguo nao permitido")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise URLValidationError("Somente HTTP e HTTPS sao permitidos")
        if parsed.username is not None or parsed.password is not None:
            raise URLValidationError("Credenciais embutidas na URL sao proibidas")
        host = parsed.hostname
        if not host or host.endswith(".") or "%" in host or "@" in parsed.netloc:
            raise URLValidationError("Hostname invalido")
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise URLValidationError("URL malformada") from exc
    if port is not None and port not in {80, 443}:
        raise URLValidationError("Porta nao permitida na triagem")
    host = host.lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            raise URLValidationError("Enderecos IP privados, locais ou reservados nao sao permitidos")
        raise URLValidationError("Analise de IP literal nao faz parte do MVP")
    try:
        ascii_host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii").lower()
        decoded_host = idna.decode(ascii_host)
    except (idna.IDNAError, UnicodeError) as exc:
        raise URLValidationError("Nome de dominio invalido") from exc
    if len(ascii_host) > 253 or not re.fullmatch(r"[a-z0-9.-]+", ascii_host) or "." not in ascii_host:
        raise URLValidationError("E necessario fornecer dominio completo valido")
    if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in ascii_host.split(".")):
        raise URLValidationError("Rotulo de dominio invalido")
    if ascii_host.endswith((".localhost", ".local", ".internal", ".invalid")) or ascii_host == "localhost":
        raise URLValidationError("Dominio local ou reservado nao permitido")
    # Fragmentos e consultas podem conter tokens. Nunca sao persistidos no resultado.
    path = parsed.path or "/"
    # Mascarar segmentos com aparencia de token (UUID, JWT ou segredo longo).
    segments = path.split("/")
    redacted = []
    for seg in segments:
        if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", seg) or (len(seg) >= 24 and re.fullmatch(r"[A-Za-z0-9_~.+-]+", seg)):
            redacted.append("[REDACTED]")
        else:
            redacted.append(seg)
    sanitized_path = quote("/".join(redacted), safe="/%:@!$&'()*+,;=-._~[]")
    safe_netloc = ascii_host + ((":" + str(port)) if port is not None else "")
    normalized = urlunsplit((parsed.scheme.lower(), safe_netloc, sanitized_path, "", ""))
    return SafeURL(normalized, ascii_host, _registrable_domain(ascii_host), parsed.scheme.lower(), port, decoded_host != ascii_host)
