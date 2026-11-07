# MVP implementado — FARO Graph v0.1

## O que funciona
- API FastAPI com autenticação por `X-Faro-Api-Key` e OpenAPI em `/docs`.
- Análise lexical **offline** de URL e hostname (sem acesso remoto).
- Sinais de possível imitação de marca, conexão HTTP, hostname sensível e IDN.
- Inspeção opcional de HTML **fornecido pelo analista**: campos de senha, campos de cartão e hostname de destino do formulário.
- Score heurístico 0–100, classificação explicável, confiança e cobertura separados.
- Evidências identificadas e atribuídas a sua origem, sem acusar responsáveis.
- Grafo simples URL → hostname → domínio registrável; relações com marcas e destino de formulário, rotuladas como observação ou hipótese.
- Persistência SQLite de resultados e grafo (não armazena HTML bruto, parâmetros de consulta ou fragmentos).
- Frontend responsivo estático e testes automatizados, CI GitHub Actions.

## Fora do MVP — não confundir com proteção completa
- Não coleta DNS, RDAP, certificados, reputação comercial ou HTML remoto.
- Não executa sandbox, screenshot, comparações visuais ou verificação em listas de ameaças.
- Não atribui identidade civil, autoria ou participação criminosa de pessoas físicas.
- Não fornece veredito definitivo de fraude nem garantia de que sites com baixo score sejam seguros.
- Não contempla múltiplos tenants, autorização granular, quota e rate-limit de produção.

## Executar localmente

Requer Python 3.11+.

1. `python -m pip install '.[dev]'`
2. `export FARO_API_KEY='troque-por-chave-aleatoria-longa'`
3. `PYTHONPATH=services/api-gateway uvicorn faro_api.main:app --host 127.0.0.1 --port 8000`
4. Abrir `http://127.0.0.1:8000/` e informar a chave configurada.
5. `PYTHONPATH=services/api-gateway python -m pytest`

> Não publique este MVP diretamente na internet. Ele é um protótipo local para validação de mecanismos e experiência; produção exige proteção de borda, autenticação de usuários e organizações, controle de tráfego, observabilidade e monitoramento.

## Contrato mínimo
`POST /v1/analyses`: JSON `{ "url": "https://example.com", "observed_html": null }` com header `X-Faro-Api-Key`.

`GET /v1/analyses/{id}`, `GET /v1/analyses/{id}/evidence`, `GET /v1/analyses/{id}/graph`.

## Limitações de evidência
A presença de um domínio de referência em um hostname suspeito não identifica seu criador. Um formulário em HTML fornecido por um usuário não é evidência independente. Os relatórios devem sempre apresentar essas ressalvas.
