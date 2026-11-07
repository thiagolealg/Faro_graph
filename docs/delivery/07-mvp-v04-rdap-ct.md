# FARO v0.4 — RDAP e Certificate Transparency opt-in

**Estado:** implementado e testado com provedores simulados. A execução real deve ser validada com política de privacidade e limites de acesso por fornecedor. **Não é serviço pronto para exposição pública.**

## Entregas

- Enriquecimento **RDAP** (Registro.br para `.br`, Verisign para `.com`/`.net`) consultado exclusivamente para o **domínio registrável**. Sem TLD suportado, resultado `unsupported`, não ``limpo``.
- Seleção de campos: datas de registro/atualização/expiração e até oito nameservers; informações pessoais de titular, contatos e respostas brutas são descartadas.
- **Certificate Transparency histórico** (`crt.sh`): deduplicação de IDs de certificados, recorte por nomes que pertencem ao domínio, data da emissão mais recente e até cinco emissores. SANs brutos, e-mails e identificadores de titulares não são persistidos. Sem confiabilidade de cobertura/latência de SLA no provedor gratuito.
- Fontes HTTPS fixas, nenhuma navegação ao site investigado, proxies desabilitados, sem redirecionamentos, payload máximo de 300 KB e timeout de 3 segundos por requisição.
- Observações separadas de score: evidências de `impact=0`; erro, falta de cobertura e ausência de certificados não tornam site seguro nem definem suspeita.
- Grafo de nameservers RDAP com vínculos `observed` e registro de evidência; relacionamento técnico não atribui identidade ou autoria.
- Integração de API, persistência SQLite multi-tenant, testes com fixtures e visualização no dashboard.

## Habilitação local

**Padrão:** `FARO_RDAP_ENABLED=0` e `FARO_CT_ENABLED=0`. Configurar explicitamente cada uma:

```bash
export FARO_RDAP_ENABLED=1
export FARO_CT_ENABLED=1
```

RDAP/CT enviam o **domínio registrável** aos provedores externos. Não habilite sem revisão da política de privacidade, contratos/limites de acesso, justificativa legal, firewall e egress de rede. Para execução em escala, a próxima etapa deve incorporar cache, backoff, limites por fornecedor, histórico com retenção curta e autorização por tenant.

## Contratos

- `AnalysisResult.rdap`: `status=disabled|unsupported|observed|unavailable`, `source`, `checked_at`, datas e nameservers sanitizados, erros controlados.
- `AnalysisResult.certificate_transparency`: `status=disabled|observed|partial|unavailable`, `source`, `checked_at`, `certificates_matched`, `latest_not_before`, emissores e erros controlados.
- `healthz`: flags `rdap_enabled`, `ct_enabled`, `live_tls_enabled=false`.

**Não foi implementado:** inspeção TLS ao vivo, navegação em website, RDAP discovery geral via bootstrap IANA, feeds comerciais, cache distribuído, validação de CN/SAN de conexão ao destino, monitoramento contínuo ou atribuição de responsáveis. A inspeção TLS ao vivo exige sandbox e controles de egress/SSRF validados (#16).

## Evidências técnicas e fontes

- Registro.br: https://rdap.registro.br/
- Verisign RDAP: https://www.verisign.com/news-insights/registration-data-access-protocol/help/
- IANA bootstrap para expansão futura: https://www.iana.org/assignments/rdap-dns
- Índice CT de terceiros: https://crt.sh/
- Contratos de API: `services/api-gateway/faro_api/schemas.py`.
