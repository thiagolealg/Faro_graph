# Roadmap, backlog e critérios por fase

## Fase 0 — Discovery e governança (P0)

- Aprovar visão, escopo, personas e riscos legais.
- Mapear fontes e licenças; definir métricas de avaliação.
- Formalizar modelo de dados e contratos, arquitetura do sandbox, RBAC e regras de divulgação.
- Prova de conceito técnica de SSRF, sandbox e custo por análise.

**Saída:** ADRs aprovadas, mapa de dependências, base legal e dataset de avaliação definidos.

## Fase 1 — MVP de risco e estrutura investigativa (P0)

| ID | Entrega | Dependências |
|---|---|---|
| EP-01 | Auth, tenant, escopos e auditoria | Fase 0 |
| EP-02 | URL parser seguro, cache e jobs | EP-01 |
| EP-03 | DNS, RDAP, TLS e uma fonte licenciada | EP-02 |
| EP-04 | Sandbox de navegação limitado | segurança validada |
| EP-05 | Motor de regras, coverage/confidence | EP-03 e EP-04 |
| EP-06 | Dashboard Consumer e relatórios | EP-05 |
| EP-07 | Casos, evidências e entidade/aresta básica | EP-01–04 |
| EP-08 | Painel analista e revisão mínima | EP-07 |
| EP-09 | API, observabilidade e aceitação | todos |

**Saída:** URL analisada, evidências versionadas, risco explicável, grafo de relações observáveis e revisão de possíveis envolvidos sem atribuição automática de pessoas.

## Fase 2 — Investigações profissionais e marcas (P1)

- Similaridade visual, DOM e brand detection com validação.
- Monitoramento de marcas verificadas; alertas e casos.
- Correlação temporal e grafos multi-hop com filtro.
- Dossiê investigativo, cadeia de custódia e exportação revisada.
- Entidade resolution, hypotheses/contraevidence e contestação.
- APIs em lote, webhooks e expansão de provedores.

**Saída:** analistas operam campanha multi-domínio com relações auditáveis e exportações autorizadas.

## Fase 3 — Inteligência de campanhas (P2)

- Anomaly detection, detecção de clusters recorrentes e drift.
- Monitoramento avançado de artefatos e campanhas.
- APIs de inteligência de ameaças orientadas a grafo.
- QR Codes e mensagens com escopo apropriado.
- Extensão de navegador e integrações SIEM/SOAR.

## Dependências prioritárias

Segurança do sandbox precede análise dinâmica; evidência/proveniência precede score e correlação; políticas LGPD precedem dados pessoais e exportações; autorização de marca precede monitoramento; dataset validado precede alegações de precision/recall.

## Riscos de execução

Custo de feeds, incidentes de atribuição, falsos positivos, egress não seguro, datasets contaminados, visibilidade pública inadvertida de URL, excesso de microsserviços e complexidade prematura de grafo. Todo risco deve possuir owner, mitigação e gate.
