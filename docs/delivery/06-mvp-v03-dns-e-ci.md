# FARO v0.3 — Entrega técnica

## Escopo

- `passive_dns.py`: consulta passiva A/AAAA/MX/NS via resolvedor externo controlado, sem visitar o website. Por padrão `FARO_DNS_ENABLED=0`.
- `schemas.py`: contrato de observação DNS com `status`, `records`, `ttl`, `error_codes`, `checked_at` e `resolver`.
- `graph.py`: arestas de resolução e anúncios de serviço DNS observados naquele instante, sem afirmação de atribuição.
- `main.py`: saída opcional `passive_dns` e evidência de impacto 0 para evitar classificações falsas; multi-tenant funciona também com `FARO_TENANTS_JSON` sem `FARO_API_KEY`.
- Rate limiting inicial por minuto no SQLite e quota horária de análises; sem garantia de prevenção de DDoS.
- `pyproject.toml`: pacote Python delimitado a `faro_api` e dados PSL, corrigindo o conflito de setuptools no CI remoto da versão 0.2.
- UI mostra status da coleta e vínculos DNS em linguagem cautelosa.

## Critérios

- 59+ testes locais, incluindo DNS com respostas simuladas sem consultas de rede, RBAC multi-tenant, quotas, URL/privacy e regressão das análises existentes.
- Para confirmar o CI remoto, verificar execução de Actions correspondente ao commit desta versão (não presumir sucesso apenas por testes locais).

## Limitações e operação

- DNS público pode revelar que uma organização está pesquisando determinado domínio. O resolvedor deverá ser aprovado conforme políticas do cliente.
- O motor não visita URL remota nem utiliza navegador; as consultas a resolver público não garantem consistência com o DNS visto pela vítima.
- Não há validação de atribuição pessoal, verificação empresarial, CT, RDAP, TLS, feed de reputação ou evidência financeira nesta fase.
- Arestas para IPs são correlações de infraestrutura temporárias, não evidência suficiente de controle, operação ou participação fraudulenta.
- Sandbox e SSRF com egress isolado continuam bloqueantes para futuras consultas HTTP ativas.
