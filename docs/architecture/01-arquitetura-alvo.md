# Arquitetura-alvo da plataforma

**ADR de referência:** ADR-001, ADR-002 e ADR-003. Arquitetura proposta; nenhuma implementação foi criada.

## 1. Estilo e restrições

Recomenda-se **monólito modular para domínio transacional + workers isolados** para coleta, enriquecimento, análise dinâmica, correlação e ML. A separação física de browsers hostis é obrigatória. API-first, SaaS multi-tenant, event-driven para tarefas longas. Não transformar cada módulo em microsserviço prematuramente.

## 2. Topologia funcional

1. **Client Apps:** Consumer, Analyst, Enterprise e painel de revisão.
2. **API Gateway:** autenticação, autorização, validação, quotas, idempotência e rate limit.
3. **Analysis Orchestrator:** estado da investigação, seleção de fontes, deadlines, cache e retries.
4. **Passive OSINT Workers:** DNS, RDAP, TLS/CT, reputação, registros públicos e conteúdo indexado acessível legitimamente.
5. **Dynamic Browser Workers:** Chromium/Playwright em sandbox efêmero com egress controlado.
6. **Entity Resolution:** normalização de indicadores, desambiguação e registro de proveniência.
7. **Relationship & Campaign Engine:** grafo temporal, correlação entre recursos, agrupamento e atribuição conservadora.
8. **Risk Engine:** regras, heurísticas, ML versionado, coverage/confidence e explicação.
9. **Case Management:** investigação, hipóteses, anotações, revisões e contestação.
10. **Report & Export:** versões de relatórios, filtragem de dados pessoais e trilha de evidências.
11. **Monitoring:** marcas, mudanças, certificados, alertas e agregação de campanhas.
12. **Platform:** IAM/RBAC, tenant, billing, auditação, conformidade e telemetria.

## 3. Stack tecnológica sugerida

| Camada | Candidato | Motivação |
|---|---|---|
| Web | Next.js + TypeScript | UX e modularidade de frontend |
| API | Python + FastAPI + Pydantic | validação de contratos e integração com ciência de dados |
| Jobs | Celery ou Dramatiq | processamento assíncrono, retries e fila |
| Broker/cache | Redis com broker apropriado | estado efêmero e coordenação |
| Transacional | PostgreSQL | integridade e queries consistentes |
| Evidências | Object Storage S3-compatible | versionamento, criptografia, retenção |
| Grafo | PostgreSQL no MVP; Neo4j opcional posterior | iniciar simples, migrar por métricas |
| Sandbox | Containers endurecidos ou microVM + Playwright | contenção de conteúdo hostil |
| ML | modelos tabulares + embeddings visuais, registro de modelos | explicabilidade e avaliação |
| Telemetria | OpenTelemetry | logs, métricas e traces |
| IaC futuro | Terraform/OpenTofu, Kubernetes apenas se necessário | provisionamento reprodutível |

Não existe obrigação de adotar todas as ferramentas: escolhas serão validadas em ADRs e benchmarks.

## 4. Fronteiras de confiança

- Rede pública → gateway: todo input é não confiável.
- Gateway → domínio: identidades, autorização e política de tenant verificadas.
- Worker → sites externos: sem acesso a segredos, banco de dados ou metadados cloud.
- Provedor externo → sistema: respostas são evidências de origem específica, não verdade absoluta.
- Conteúdo HTML/DOM → ML/LLM: instruções de sites não podem controlar o fluxo do sistema.
- Grafo → dossiê exportado: revisão de dados pessoais, classificação e política de liberação.

## 5. Processamento e eventos de domínio

Eventos lógicos (especificação sem broker fixado): `AnalysisRequested`, `PassiveCollected`, `DynamicCollected`, `EntityResolved`, `RelationsUpdated`, `AssessmentCalculated`, `ReviewRecorded`, `ReportPublished`, `BrandAlertRaised`, `EvidenceExpired`, `DeletionRequested`.

Cada evento precisa de: `event_id`, `event_type`, `version`, `tenant_id`, `correlation_id`, `occurred_at`, `actor_type`, `subject_id` e política de retenção. Payload mínimo e sem segredos em claro.

## 6. Operação dos jobs

- Máquina de estados: queued → running_passive → running_dynamic (opcional) → correlating → assessing → completed/partial/failed/cancelled/expired.
- Retry por provedor; não repetir operações irreversíveis.
- Idempotência por `tenant + input_fingerprint + policy_version + idempotency_key`.
- Concurrency caps por tenant e provider; dead-letter, circuit breaker, budget guard e timeout.
- Diferenciar indisponibilidade do provedor de “zero matches”.
- Cache por classe de indicador e TTL/validade; nunca revogar evidência histórica sem rastreabilidade.

## 7. Infraestrutura e dados

`PostgreSQL` para tenants, jobs, investigações, observações e relacionamentos estruturados. `Object Storage` para capturas e artefatos saneados com integridade. Grafo projetado a partir de tabelas de nós/arestas no MVP; índice especializado após testes de profundidade e latência. Segregar metadados de usuário e dados sensíveis de casos, com encryption e auditação.

## 8. Requisitos de resiliência

SLO alvo: 99,9% disponibilidade API; quick scan p95 < 8s sem cache em condições normais; deep scan p95 < 180s dentro de limites configurados. Quotas, circuit breakers, degraded mode e observabilidade por estágio. Recuperar jobs interrompidos; preservar artefatos de auditoria conforme política.

## 9. Decisões que exigem prova de conceito

1. Containers vs microVM para isolamento de browser.
2. Query de grafo SQL vs motor dedicado.
3. Estratégia de extração de documentos e logos sem riscos de execução.
4. Custo/precisão de provedores de reputação e histórico.
5. Observabilidade e custo por análise em escala projetada.
