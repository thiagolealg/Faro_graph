"""Validacao e normalizacao: nao faz requisicoes ao destino informado."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit, quote, unquote

from .psl import registrable_domain

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


_SECRET_PATH_KEYS = {"token", "access_token", "refresh_token", "apikey", "api_key", "key", "secret", "session", "sessionid", "session_id", "reset", "recover", "recovery", "password", "passwd", "forgot_password", "reset_password", "password_reset", "magic_link", "verify_email", "signin", "otp", "auth", "authorization", "activate", "activation", "verify", "verification", "invite", "invitation", "code", "login", "email", "user", "usuario", "cpf", "cnpj"}
_SECRET_VALUE = re.compile(r"(?i)(token|secret|key|code|auth|session|password|otp|cpf|email)[_:-]?=.+")
_EMAIL = re.compile(r"[^/@\s]+@[^/@\s]+\.[^/@\s]+")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _redact_path(path: str) -> str:
    parts = path.split('/')
    redacted: list[str] = []
    previous_is_secret_key = False
    for raw_part in parts:
        plain = unquote(raw_part)
        # One more layer catches common double-encoded secrets without decoding output URLs.
        plain = unquote(plain)
        key_name = plain.strip().lower().replace('-', '_')
        secret_key = key_name in _SECRET_PATH_KEYS
        if raw_part and (previous_is_secret_key or _SECRET_VALUE.fullmatch(plain) or _EMAIL.fullmatch(plain)
                         or _UUID.fullmatch(plain) or (len(plain) >= 20 and re.fullmatch(r'[A-Za-z0-9_~.+-]+', plain))
                         or re.fullmatch(r'\d{11,14}', plain)):
            redacted.append('[REDACTED]')
        else:
            # Always percent-encode user-controlled path content to avoid ambiguity.
            redacted.append(quote(raw_part, safe='%:@!$&\'()*+,;=-._~'))
        previous_is_secret_key = secret_key
    return '/'.join(redacted)


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
    # Consultas e fragmentos nunca sao persistidos; tokens no caminho sao mascarados.
    sanitized_path = _redact_path(parsed.path or "/")
    safe_netloc = ascii_host + ((":" + str(port)) if port is not None else "")
    normalized = urlunsplit((parsed.scheme.lower(), safe_netloc, sanitized_path, "", ""))
    registrable = registrable_domain(ascii_host)
    if registrable is None:
        raise URLValidationError("Forneca um dominio registravel, nao apenas sufixo publico")
    return SafeURL(normalized, ascii_host, registrable, parsed.scheme.lower(), port, decoded_host != ascii_host)
