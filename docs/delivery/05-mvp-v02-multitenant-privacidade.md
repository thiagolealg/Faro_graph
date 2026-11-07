# FARO v0.2 — Entrega de hardening de segurança

## Implementado

- Registro de credenciais por `tenant_id`, `actor_id`, `role` e `key_id` via variável de ambiente, com múltiplas chaves para rotação sem downtime.
- Chaves comparadas pelo hash SHA-256 em memória e nunca escritas no banco de dados (o provisionamento de segredos permanece responsabilidade do operador).
- `reader` consulta; `analyst` consulta e cria análises; `admin` adicionalmente consulta registros de auditoria.
- Filtro obrigatório `tenant_id` em GET/lista/evidências/grafo e gravação; retorno `404` para IDs de outras organizações.
- Quota de análises horária e transacional via SQLite; `429` quando excedida.
- Log de auditoria sem conteúdo analisado, segredo, URL ou HTML.
- Redação de segmentos sensíveis de caminho e descarte de query/fragment; dedução do domínio registrável via PSL.
- Compatibilidade de migração com base SQLite v0.1 (`tenant_id=local`).

## Não implementado / riscos residuais

- Proteção de exaustão por *requests* (limite por segundo), autenticação OIDC, identidade de usuário real por sessão, gestão de segredos, TLS externo, banco distribuído, observabilidade central e contenção de coletores ativos.
- Chaves ainda são inseridas manualmente pelo dashboard local e podem ficar expostas se implantado na internet. Exigir proxy/autenticação web antes de abrir ao público.
- PSL é snapshot local versionado; atualizar a partir do projeto `publicsuffix/list`, respeitando MPL 2.0.
- Não foi realizada auditoria externa de segurança; testes são automatizados locais.

## Critérios e testes

`PYTHONPATH=services/api-gateway python -m pytest`: integração, segurança, isolamento de tenants, quotas, migração e regressão da classificação.
