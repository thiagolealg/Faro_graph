# SERVICES — Mapa de módulos

Diretórios reservados para implementação futura. **Nenhum código está presente.**

| Módulo | Responsabilidade |
|---|---|
| [api-gateway](api-gateway/) | Entrada REST e controle de borda. Autenticação de requisições, quotas, validação e versionamento. |
| [identity-access](identity-access/) | Identidade e autorização. RBAC, papéis, MFA, autorizações por caso e tenant. |
| [analysis-orchestrator](analysis-orchestrator/) | Orquestração de análises. Estado de jobs, idempotência, deadlines e fan-out para workers. |
| [evidence-registry](evidence-registry/) | Inventário e integridade de evidências. Fontes, proveniência, hashes, validade, confidencialidade. |
| [entity-resolution](entity-resolution/) | Normalização conservadora de entidades. Aliases, homônimos, merge controlado e origem das identidades. |
| [relationship-graph](relationship-graph/) | Relações temporais e grafo de campanhas. Arestas tipadas, caminhos, filtros de confiança e dados temporais. |
| [attribution-review](attribution-review/) | Atribuição e revisão de envolvidos. Hipóteses, alternativas, contraevidências e divulgação restrita. |
| [threat-intelligence](threat-intelligence/) | Inteligência de ameaças. Agregação de feeds, validação de licenças e idade do indicador. |
| [risk-engine](risk-engine/) | Classificação de risco e explicabilidade. Score, confiança, cobertura, inconclusão e histórico de versões. |
| [case-management](case-management/) | Gestão de casos investigativos. Escopo, finalidade, estados, incidentes, trilhas e revisão. |
| [brand-monitoring](brand-monitoring/) | Proteção de marcas. Ativos oficiais, verificação de autorização e monitoramento. |
| [alerting](alerting/) | Notificações e alertas. Regras, prioridades, deduplicação e canais autorizados. |
| [reporting](reporting/) | Relatórios e dossiês. Views por audiência, redaction, exportações e integridade. |
| [integrations](integrations/) | Adaptadores e integrações externas. Contratos de terceiros, licenças, rates, webhooks. |
| [tenant-billing](tenant-billing/) | Organizações e políticas de uso. Planos, unidades de custo, quotas, limites e retenção. |
