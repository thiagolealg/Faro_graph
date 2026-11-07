"""Deteccao heuristica inicial: sinais, nao imputacoes ou provas de fraude."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .schemas import Evidence, RiskAssessment
from .url_security import SafeURL

# Referencias de exemplo para detectar possiveis imitacoes; nao estabelecem autoria.
KNOWN_BRANDS = {
    "paypal": {"paypal.com"},
    "nubank": {"nubank.com.br"},
    "mercadolivre": {"mercadolivre.com.br"},
    "amazon": {"amazon.com", "amazon.com.br"},
    "google": {"google.com", "google.com.br"},
}
HIGH_RISK_TOKENS = re.compile(r"(?:^|[-.])(verify|verifica|verificacao|confirm|confirmar|recuperar|senha|password|login|secure|seguranca|autenticacao|atualizacao|update|desbloqueio)(?:[-.]|$)", re.I)


class HTMLSignals(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.passwords = 0
        self.payment_fields = 0
        self.forms = 0
        self.actions: list[str] = []
        self.brand_hints: set[str] = set()
        self.text_fragments: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms += 1
            if a.get("action"):
                self.actions.append(a["action"][:1000])
        if tag == "input":
            t = (a.get("type") or "").lower()
            name = " ".join((a.get("name") or "", a.get("id") or "")).lower()
            if t == "password":
                self.passwords += 1
            if any(x in name for x in ("credit_card", "cardnumber", "cvv", "cvc", "cartao")):
                self.payment_fields += 1

    def handle_data(self, data):
        if len(self.text_fragments) < 1000:
            self.text_fragments.append(data[:300])


def evaluate(target: SafeURL, html: str | None) -> tuple[RiskAssessment, list[Evidence], dict]:
    evidence: list[Evidence] = []
    extra: dict = {"brand_candidates": [], "form_action_hosts": []}

    def add(code: str, title: str, detail: str, impact: int, source: str = "local_lexical", confidence: str = "low"):
        evidence.append(Evidence(id=f"ev-{len(evidence)+1:03d}", code=code, title=title, detail=detail, impact=impact, source=source, confidence=confidence))

    if target.scheme == "http":
        add("http_only", "Conexao sem HTTPS", "O endereco informado usa HTTP, sem criptografia de transporte.", 8, confidence="high")
    if target.is_idn or "xn--" in target.hostname:
        add("internationalized_domain", "Dominio internacionalizado", "O dominio utiliza codificacao IDN/Punycode; isso nao comprova fraude.", 10, confidence="high")
    if HIGH_RISK_TOKENS.search(target.hostname):
        add("sensitive_hostname_terms", "Termos sensiveis no hostname", "O hostname contem termos frequentes em paginas de autenticacao ou verificacao.", 15)
    if len(target.hostname) > 55:
        add("long_hostname", "Hostname extenso", "A extensao do hostname merece revisao manual em conjunto com outros indicadores.", 7)
    if target.hostname.count("-") >= 3:
        add("hyphenated_hostname", "Muitos separadores", "O hostname contem multiplos hifens.", 6)

    for brand, official in KNOWN_BRANDS.items():
        if brand in target.hostname.replace("-", "").replace(".", "") and target.registrable_domain not in official:
            extra["brand_candidates"].append(brand)
            add("possible_brand_impersonation", "Possivel imitacao de marca", f"O hostname faz referencia a '{brand}', mas nao usa um dos dominios de referencia cadastrados. Parceria legitima e possivel.", 40, confidence="medium")

    signals = HTMLSignals()
    if html is not None:
        signals.feed(html)
        signals.close()
        if signals.passwords and extra["brand_candidates"]:
            add("login_on_brand_like_domain", "Formulario sensivel em dominio semelhante", "HTML fornecido contem campo de senha em dominio semelhante a marca de referencia.", 26, "user_supplied_html", "medium")
        elif signals.passwords:
            add("password_form", "Formulario de senha", "HTML fornecido contem campo de senha; comum tambem em sites legitimos.", 5, "user_supplied_html")
        if signals.payment_fields and extra["brand_candidates"]:
            add("payment_on_brand_like_domain", "Pagamento em dominio semelhante", "HTML fornecido contem campos relacionados a cartao em dominio semelhante a marca.", 22, "user_supplied_html", "medium")
        for action in signals.actions[:10]:
            try:
                parsed = urlsplit(urljoin(target.url, action))
                hostname = (parsed.hostname or "").lower()
            except ValueError:
                continue
            if hostname and hostname != target.hostname:
                # Host externo apenas citado no HTML fornecido, nunca contatado.
                if hostname not in extra["form_action_hosts"]:
                    extra["form_action_hosts"].append(hostname)
        if extra["form_action_hosts"] and (signals.passwords or signals.payment_fields):
            add("cross_domain_sensitive_form", "Formulario sensivel aponta para outro dominio", "O HTML enviado indica envio de dados sensiveis para hostname diferente.", 25, "user_supplied_html", "medium")

    # Cap e ponderacao transparentes; pontuacao nao representa probabilidade calibrada.
    score = min(100, sum(e.impact for e in evidence))
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 35:
        level = "moderate"
    elif score >= 15:
        level = "low"
    else:
        level = "inconclusive"
    confidence = "medium" if html is not None and len(evidence) >= 2 else "low"
    coverage = "lexical_and_submitted_html" if html is not None else "lexical_only"
    recommendation = (
        "Nao forneca credenciais nem efetue pagamentos. Confira o canal oficial da organizacao por fonte independente."
        if level in {"moderate", "high", "critical"}
        else "Analise limitada: nao e possivel afirmar que o site e seguro. Verifique sua legitimidade por canais oficiais."
    )
    return RiskAssessment(score=score, level=level, confidence=confidence, coverage=coverage, recommendation=recommendation), evidence, extra
