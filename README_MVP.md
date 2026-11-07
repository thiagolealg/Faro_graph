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
