# Contratos de API — especificação HTTP e eventos (sem implementação)

## 1. Convenções

REST `/v1`, JSON, timestamps RFC3339 UTC, IDs opacos, autenticação empresarial, escopos explícitos e rate limits por tenant. Requisições de mutação suportam idempotency key. Retornos estruturados com `code`, `message`, `details`, `correlation_id`. Versionamento sem mudanças incompatíveis silenciosas.

## 2. Endpoints

| Método | Caminho | Entrada | Saída / restrição |
|---|---|---|---|
| POST | `/v1/analyses` | URL, modo, referência cliente | `analysis_id`, `status_url`, `status` |
| GET | `/v1/analyses/{id}` | auth | status, progresso, erro ou score |
| GET | `/v1/analyses/{id}/evidence` | auth e escopo | evidências filtradas |
| GET | `/v1/analyses/{id}/report` | auth e escopo | relatório versionado |
| POST | `/v1/analyses/{id}/recheck` | motivo | novo job e ligação histórica |
| POST | `/v1/cases` | finalidade, escopo, tenant | case_id |
| GET | `/v1/cases/{id}` | auth | resumo e controles |
| GET | `/v1/cases/{id}/entities` | filtros/paginação | entidades permitidas |
| GET | `/v1/cases/{id}/graph` | janela, tipos, confiança | nós/arestas + evidências |
| POST | `/v1/cases/{id}/hypotheses` | alegação, suporte e contraevidência | hipótese pendente de revisão |
| POST | `/v1/cases/{id}/reviews` | decisão, justificativa | revisão auditada |
| GET | `/v1/cases/{id}/dossier` | audiência/exportação | dossiê com política de redaction |
| POST | `/v1/brands` | domínio e prova de autorização | marca aguardando verificação |
| GET | `/v1/brands/{id}/alerts` | filtros | alertas |
| POST | `/v1/batches` | lista de URLs | job lote |
| POST | `/v1/webhooks` | URL de callback, eventos e secrets | integração |
| GET | `/v1/audit` | filtros, admin | trilha de auditoria |

## 3. Estrutura conceitual do resultado

**AnalysisResult:** `analysis_id`, `status`, `submitted_at`, `analyzed_at`, `normalized_url`, `risk_score` (0–100 ou nulo), `risk_level`, `confidence`, `coverage`, `threat_categories`, `top_findings`, `recommended_action`, `evidence_summary`, `model_version`, `policy_version`, `is_inconclusive`, `report_version`.

**GraphNode:** `node_id`, `entity_type`, `display_label`, `classification`, `visibility`, `first_seen`, `last_seen`, `aliases_count`.

**GraphEdge:** `edge_id`, `from_id`, `to_id`, `edge_type`, `assertion_class`, `confidence`, `evidence_refs`, `observed_window`, `review_status`.

**AttributionHypothesis:** `hypothesis_id`, `case_id`, `entity_refs`, `claim`, `supporting_evidence`, `contradicting_evidence`, `alternatives`, `confidence`, `review_state`, `release_policy`.

Nenhuma resposta deverá devolver credenciais, tokens de URL em claro, dados vazados, e-mails particulares não necessários ou dados pessoais sem autorização apropriada.

## 4. Assincronismo e webhooks

- HTTP 202 para jobs pendentes; HTTP 200 para leitura; 4xx para validação/permissão; 429 para quota; 5xx transitórios com `Retry-After` quando relevante.
- Webhook assinado (HMAC ou mecanismo equivalente), replay protection, timeout e retries com backoff.
- Eventos: `analysis.completed`, `analysis.partial`, `analysis.failed`, `case.relations_changed`, `case.reviewed`, `alert.created`, `report.ready`.
- Garantia **at-least-once** exige consumidores idempotentes.

## 5. Autorização

Escopos: `analysis:create`, `analysis:read`, `case:create`, `case:read`, `case:investigate`, `case:review`, `dossier:export`, `brand:manage`, `admin:audit`. Escopos não substituem autorização por objeto/tenant. Dados de atribuição pessoal só para roles com treinamento, finalidade e registro de acesso.

## 6. Aceitação do contrato

- OpenAPI final gerado e versionado quando houver implementação.
- Filtros e paginação determinísticos; idempotência; campos opcionais explícitos.
- Nulos significam não disponível, não risco baixo.
- Testes negativos contra IDOR, over-posting, disclosure e enumeração de casos.
