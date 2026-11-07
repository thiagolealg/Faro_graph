# FARO Graph MVP v0.1

O projeto possui um **MVP funcional para execução local**, preservando a arquitetura documental original.

- [Visão geral e limites](docs/delivery/03-mvp-implementado.md)
- [Iniciativas e tarefas](docs/delivery/04-iniciativas-e-tarefas.md)
- [Especificação e arquitetura](docs/product/01-visao-e-prd.md)

**Não é um detector definitivo de phishing:** apenas URL e HTML fornecido pelo solicitante são avaliados nesta fase. Nenhuma navegação remota é realizada. Não há atribuição de identidade ou culpabilidade.

## Começar

```sh
python -m pip install '.[dev]'
export FARO_API_KEY='chave-local-segura'
PYTHONPATH=services/api-gateway uvicorn faro_api.main:app --host 127.0.0.1 --port 8000
```

Abra `http://127.0.0.1:8000/`. Para testar, execute `PYTHONPATH=services/api-gateway python -m pytest`.

## v0.2 — segurança e privacidade (nova entrega)

- Isolamento real de leituras/gravações por organização em SQLite; IDs de outra organização retornam `404`.
- Credenciais rotacionáveis por configuração e papéis `reader`, `analyst`, `admin`, com quota horária atômica por organização.
- Auditoria de criação sem armazenar a URL integral, HTML, API keys ou dados de formulários.
- Normalização por Public Suffix List (inclui PRIVATE/wildcards/exceções), distribuída como snapshot local com data e licença.
- Redação de parâmetros de consulta e segmentos sensíveis de caminho antes de qualquer persistência.

Exemplo de configuração multi-organização (substitua credenciais e não envie este JSON para logs):

```sh
export FARO_TENANTS_JSON='[{"tenant_id":"sua_empresa","hourly_quota":100,"keys":[{"key_id":"v1","actor_id":"analista01","role":"admin","key":"SUBSTITUA_POR_SEGREDO_ALEATORIO_COM_32_CHARS"}]}]'
PYTHONPATH=services/api-gateway uvicorn faro_api.main:app --host 127.0.0.1 --port 8000
```

Para desenvolvimento local, `FARO_API_KEY` permanece disponível como compatibilidade. Em implantação multi-organização, utilize `FARO_TENANTS_JSON` armazenada em gerenciador de segredos. Não exponha a interface HTML com chave de serviço em ambiente compartilhado; autenticação web com sessão/OIDC e controles de produção continuam pendentes.

**Limites de v0.2:** ainda não há navegação remota, inspeção DNS/RDAP/TLS em produção, atribuição de pessoas, bloqueio de SSRF em coletores ativos ou rate limit distribuído por segundo. A quota horária em SQLite é somente uma proteção inicial contra consumo excessivo. O snapshot PSL deve ser atualizado periodicamente e acompanhado de data de origem.
