# FARO Graph MVP v0.7

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

## v0.4 — RDAP e CT (nova entrega)

- Coleta RDAP opcional por **provedor oficial fixo**: `.br`, `.com`, `.net`, sem navegação ao site nem coleta de contatos pessoais.
- Busca histórica de certificados no índice público CT (crt.sh), sem inspecionar a conexão TLS ao vivo.
- Status explicito `observed`, `partial`, `unsupported`, `unavailable` ou `disabled`; nenhuma ausência de dados é interpretada como legitimidade.
- Provedores externos consultados **somente quando** `FARO_RDAP_ENABLED=1` e/ou `FARO_CT_ENABLED=1`; o domínio registrável é transmitido a cada serviço.
- API, grafo temporal, UI e testes de integração exercitam os novos módulos de forma isolada, com transportes simulados.

Documentação: [07-mvp-v04-rdap-ct.md](docs/delivery/07-mvp-v04-rdap-ct.md).

**Risco pendente:** a aplicação ainda é destinada a uso local/ambiente protegido. Antes de acessar sites remotos, implementar sandbox, egress controlado, controle de destinos DNS e proteção completa contra SSRF. RDAP/CT requerem revisão de privacidade e rate limits por fornecedor.


## v0.5 — inteligência de ameaças por arquivo local autorizado

- Importação **opcional** e validada de arquivo JSONL, sem chamadas aos sites investigados nem envio das URLs de clientes a terceiros.
- Indicadores URL/hostname, origem, prazo de validade, hash SHA-256 do snapshot, relatório persistido e relação rastreável no grafo.
- Match de URL exata eleva o risco heurístico mínimo para 80; match só de hostname para 55. Não prova fraude atual ou autoria.
- O operador deve confirmar licença/uso de dados antes de habilitar; nenhuma fonte comercial é incluída no repositório.

**Exemplo de ativação em ambiente local controlado:**

```sh
export FARO_TI_ENABLED=1
export FARO_TI_LICENSE_ACK=1
export FARO_TI_PATH=/caminho/absoluto/feed-autorizado.jsonl
```

Consulte [o contrato completo](docs/delivery/08-mvp-v05-threat-intelligence.md). Reinicie o processo após atualizar o arquivo. Nenhum endpoint remoto de fornecedor é acionado pelo módulo v0.5.


## v0.6 — Casos investigativos e dossiês

- Investigações por organização: casos com até 20 análises vinculadas, revisões humanas auditáveis e fluxo de estados administrativo.
- Grafo consolidado de indicadores compartilhados, **sem** atribuir mesma autoria ou operação por IP/DNS/CDN em comum.
- Dossiê JSON com análises, limitações, proveniência e SHA-256 sobre serialização estável. **Não é assinatura digital nem cadeia de custódia forense.**
- Interface local para criar casos, adicionar análises, registrar revisão e exportar relatório.
- Validação de permissões por tenant, estados concorrentes, conteúdo sensível e dados persistidos em SQLite.

Contratos e limitações: [docs/delivery/09-mvp-v06-casos-grafo-dossie.md](docs/delivery/09-mvp-v06-casos-grafo-dossie.md).

## v0.7 — Login corporativo OIDC e sessões web (opcional)

O painel pode usar **Authorization Code + PKCE**, sessão `Secure`/`HttpOnly`, CSRF e identidade vinculada a uma organização. Chaves de serviço seguem disponíveis para integrações, mas não precisam ser digitadas no navegador em modo OIDC.

**Configuração:** veja [documentação v0.7](docs/delivery/10-mvp-v07-oidc-sessoes.md) para `FARO_OIDC_CONFIG` e `FARO_OIDC_USERS_JSON`, contratos, modelos de usuário e políticas de segurança. Configuração errada interrompe o startup. É necessário HTTPS e provedor de identidade confiável. Nenhum segredo deve ser enviado ao GitHub.

**Não equivale a prontidão de produção:** integração de IdP real, hardening de proxy, mitigação de abuso no login, MFA no IdP, política de expurgo, revisão LGPD e auditoria de infraestrutura continuam pendentes (#20, #21). Navegação remota depende do sandbox #16.
