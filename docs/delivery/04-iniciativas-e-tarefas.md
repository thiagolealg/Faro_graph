# Plano de iniciativas do FARO Graph

## I1. MVP de triagem de URLs e evidências (P0)
**Entregue no v0.1:** normalização, validação, score heurístico, evidências, API, banco SQLite.
**Próximo:** robustecer Public Suffix List, modelagem das fontes, verificação de reputação e auditoria de persistência.

## I2. Interface e grafo investigativo (P0)
**Entregue no v0.1:** UI de consulta, grafo tipado, relação com marcas de referência, distinção hipótese/observação.
**Próximo:** explorador interativo, entidade empresarial pública verificada, investigação de campanhas, revisão humana.

## I3. Segurança, privacidade e qualidade (P0)
**Entregue no v0.1:** exigência de chave da API, bloqueio de IPs locais/reservados, remoção de query e fragment, testes locais e CI.
**Próximo:** proteção real contra SSRF para futuros coletores remotos, RBAC/multi-tenant, detecção/redação de tokens em caminhos, isolamento de sandbox, SAST/DAST, métricas e gestão de segredos.

## I4. OSINT passivo e inteligência de ameaças (P1)
**Pendente:** adaptadores DNS/RDAP/TLS, reputação por feeds licenciados, ingestão com proveniência, deduplicação e TTL por evidência.

## I5. Investigação profunda e operações (P1–P2)
**Pendente:** worker Playwright efêmero em rede isolada, inspeção visual e DOM, descoberta de campanhas, exportação e revisão humana auditada.

## Critérios de aceite do v0.1
- `POST /v1/analyses` oferece resultado persistido e explicável sem HTTP remoto.
- `GET /v1/analyses/{id}/graph` retorna nós e arestas tipadas, sem afirmação de culpabilidade.
- Endereços locais, IPs e esquemas não permitidos são rejeitados.
- Chave inválida gera HTTP 401.
- Testes automatizados passam em ambiente local e são executados por CI.

## Atualizacao v0.4 — consulta RDAP e CT historico (07/11/2026)

**I4 parcialmente entregue:** coleta DNS opt-in (v0.3), RDAP `.br`/`.com`/`.net` e indice historico CT via crt.sh (v0.4), com estados de disponibilidade e proveniencia. Nao alteram o score heuristico, nao analisam certificados TLS em conexao viva e nao identificam operadores.

**Controles implementados em v0.4:** bloqueio de provedores fora de hosts HTTPS autorizados, redirecionamentos proibidos, timeouts e tamanho maximo de resposta, nao armazenamento de respostas brutas RDAP/CT nem dados de titular, testes de dados malformados e salvamento multi-tenant.

**Pendencias da I4:** verificar contratos/licencas, cache/backoff/limites por fornecedor, bootstrap IANA com aprovacao explicita de endpoints, feeds licenciados de reputacao e telemetria. Issue #14 continua aberta para TLS em sandbox e cobertura RDAP adicional.

**Dependencias bloqueantes:** #16 (sandbox efemero, egress/SSRF); #20 (autenticacao web adequada); #21 (observabilidade, politicas de retencao, atualizacao PSL). Nao expor a API publicamente ate a revisao desses controles.


## Atualização v0.5 — snapshots locais de reputação (07/11/2026)

**I4 em andamento:** ingestão de inteligência de phishing/malware **por arquivo autorizado** com formato estrito, expiração, fonte, hash, match exato, classificação explicável e zero saída de URLs de clientes. Esta entrega cobre parcialmente #15 (TASK 10); a integração comercial via provedores, gestão de licença e atualizações remotas ficam pendentes.

**I3:** o padrão continua sem requisições remotas. Dados malformados bloqueiam o startup quando a integração está ativa. Logs não devem registrar feeds e URLs completas sensíveis. Implementar futuramente assinatura de feeds, limites de retenção e rotação sem reinício (#21).

**Critérios antes de produção pública:** #20 autenticação OIDC/sessão web e proteção contra abuso, #16 sandbox, contratos de uso dos fornecedores, telemetria e políticas LGPD.


## Atualização v0.6 — gestão investigativa e dossiês (07/11/2026)

**I5 parcialmente entregue:** casos persistidos e isolados por organização, até 20 análises por caso, revisão humana imutável via API, fluxo de estados com versão otimista, grafo consolidado com proveniência e dossiê JSON com SHA-256. Os pareces humanos são hipóteses, não comprovação de envolvimento. Não há automação de atribuição pessoal.

- **#18 (TASK 13):** parcialmente entregue. Faltam gestão avançada de campanhas, contraditório empresarial estruturado, triagem institucional, atribuição com fontes independentes.
- **#19 (TASK 14):** parcialmente entregue. Hash de conteúdo e exportação JSON pronta; faltam assinatura digital, armazenamento WORM, política formal de cadeia de custódia e PDF.
- **#20 (TASK 15):** aberto, bloqueia produção pública.
- **#16 (TASK 11):** aberto, bloqueia investigação dinâmica remota.
- **#21 (TASK 16):** aberto, políticas de retenção/custos/observabilidade de produção.

**Qualidade:** testes de isolamento multi-tenant e papéis, anti-exfiltração nos relatórios, integridade reprodutível, validação de inputs e fluxo de estados.
