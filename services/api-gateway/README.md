# FARO API Gateway — MVP

Implementado em `faro_api/` (FastAPI). Consulte [guia de execução](../../docs/delivery/03-mvp-implementado.md). As demais responsabilidades arquiteturais deste diretório são futuras.

# Entrada REST e controle de borda

**Situação:** especificação estrutural; sem código.

## Responsabilidades

Autenticação de requisições, quotas, validação e versionamento.

## Integrações previstas

IAM, orchestration.

## Condições antes da implementação

- Aprovar arquitetura, contratos, segurança e critérios de aceitação.
- Assegurar proveniência, autorização e segregação por tenant conforme aplicável.
- Criar testes, observabilidade e documentação antes de produção.

**Referência:** documentos em `docs/` e PRD principal.
