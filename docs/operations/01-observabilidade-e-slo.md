# Operação, observabilidade, custos e SLO

## 1. SLOs propostos

| Serviço | Meta inicial | Notas |
|---|---|---|
| API | 99,9% disponibilidade mensal | fora de erro de cliente |
| Quick scan, sem cache | p95 < 8 s | quando dependências disponíveis |
| Deep scan | p95 < 180 s | dentro dos limites e jobs concluídos |
| Isolamento | nenhum acesso a destinos proibidos | gate bloqueante |
| Evidência rastreável | 100% de evidências usadas em classificação com origem | gate bloqueante |

## 2. Telemetria

Métricas por estágio: latência, throughput, fila, erro, custos por fonte, fallback, bloqueios SSRF, memória e tráfego por sandbox, classificações inconclusivas, proveniência ausente, falsos positivos, reversões de classificação, tokens descartados e taxa de revisão.

Tracing por `correlation_id`, sem URL privada em atributos ou logs. Logs estruturados com categorias de dados e proteção de acesso; alertas para mudança de perfil de consumo e egress.

## 3. Qualidade da inteligência

Dashboards: percentual de fontes disponíveis, idade média das evidências, cobertura de análise, precision por classe em amostras revisadas, falsos merges de entidades, estabilidade de clusters, taxa de atribuições rejeitadas e incidentes reclassificados.

## 4. Resiliência

- Circuit breaker por provedor, retry com backoff e jitter, dead-letter queue.
- Isolamento de pools de workers por função e risco.
- Backpressure e quotas por tenant, tier e capacidade do sandbox.
- Retenção de jobs e idempotência no reprocessamento.
- Plano de recuperação de banco/artefatos e simulações regulares de restore.
- Runbooks para indisponibilidade de inteligência, erro de scoring, falha de sandbox e suspeita de exfiltração.

## 5. FinOps

Custo por quick/deep scan, por caso, por tenant, por provedores/licenças, bytes transferidos, capturas, inferência e armazenamento. Alertas para custo anômalo, limitação de orçamentos e caching baseado em validade.

## 6. Release e incidentes

Feature flags, mudanças de modelo canary, validação antes de promover, rollback de classifier, auditoria de configurações e exercícios periódicos de resposta a incidentes. Dados de atribuição pessoal exigem monitoramento especial de acessos e exportações.
