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
