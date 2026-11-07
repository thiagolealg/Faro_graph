# FARO Graph v0.6 — Casos investigativos, revisão humana e dossiês

**Estado:** implementado para **execução local / ambiente controlado**. Não é plataforma de atribuição criminal, perícia forense nem serviço pronto para operação pública.

## Entrega técnica

- Casos persistentes em SQLite, segregados por `tenant_id` e limitados a **20 análises** por caso.
- Fluxo de trabalho `open → triage → under_review → closed`, com transições explícitas, reabertura administrativa e verificação de `expected_version` para evitar sobrescrita concorrente.
- Criação e vínculo de análises por `analyst/admin`; leitura por `reader`; alteração de estado por `admin`.
- Revisões humanas **imutáveis via API**, com autor, instante UTC, hipótese/parecer e justificativa. Uma revisão não altera o score da análise original e não constitui prova de autoria.
- Correlação entre grafos de análises do mesmo caso com referências às análises de origem. Nomes de feeds e marcas de referência não são tratados como vínculos entre suspeitos. IPs e DNS compartilhados são rotulados como contexto de confiabilidade fraca.
- Dossiê JSON determinístico com URL sanitizada, evidências, observações de provedores, limitações, grafo e histórico de revisões.
- SHA-256 sobre serialização JSON UTF-8 com chaves ordenadas; hash reproduzível para o **mesmo estado do caso**. **Não** é assinatura, prova de custódia ou integridade do sistema de origem.
- UI local para criar e selecionar casos, associar análise corrente, registrar revisão e exportar dossiê.
- Logs de auditoria para operações de casos (criação, vínculo, revisão e estado), persistidos junto com cada operação numa transação SQLite.

## Endpoints

| Operação | Endpoint | Perfil mínimo |
|---|---|---|
| Criar caso | `POST /v1/cases` | analyst |
| Listar casos | `GET /v1/cases` | reader |
| Detalhar caso | `GET /v1/cases/{id}` | reader |
| Vincular análise existente | `POST /v1/cases/{id}/analyses` | analyst |
| Registrar parecer | `POST /v1/cases/{id}/reviews` | analyst |
| Alterar estado | `PATCH /v1/cases/{id}/status` | admin |
| Grafo técnico do caso | `GET /v1/cases/{id}/graph` | reader |
| Dossiê JSON | `GET /v1/cases/{id}/dossier` | reader |

### Exemplo mínimo

```json
POST /v1/cases
{"title":"Investigação de domínios suspeitos","analysis_ids":["<UUID da análise já existente>"]}
```

```json
POST /v1/cases/{id}/reviews
{"decision":"inconclusive","rationale":"As observações ainda não permitem associar o operador ou validar autoria."}
```

```json
PATCH /v1/cases/{id}/status
{"status":"closed","expected_version":2}
```

Os dados são acessíveis apenas pela organização da chave informada. IDs de outra organização retornam `404`.

## Como verificar a integridade do dossiê

O endpoint retorna `{ "dossier": {...}, "integrity": {"algorithm":"sha256","digest":"...","digitally_signed":false} }`.
O hash é calculado sobre o objeto `dossier`, serializado como JSON com `sort_keys=True`, `ensure_ascii=False`, separadores `(',', ':')`, `allow_nan=False`, UTF-8. Um hash diferente indica alteração **entre as cópias comparadas**, não prova autenticidade dos fatos relatados.

## Guardrails investigativos

1. Coincidência de domínio/hostname pode indicar o mesmo recurso observado, **não** a mesma pessoa ou campanha.
2. IPs e nameservers compartilhados são sinais **fracos** em ambientes CDN, hospedagem ou provedores de infraestrutura.
3. Nenhuma inferência de responsabilidade criminal, identificação de pessoa física ou reputação pessoal a partir desses vínculos.
4. O relatório preserva a autoria humana do parecer como identidade operacional interna, não como identidade de possível suspeito.
5. A API não oferece coleta de dados pessoais, exploração de sistemas de terceiros, login automático ou solicitações financeiras.
6. Os casos continuam sujeitos à necessidade de finalidade legítima, retenção de dados, contestação, controle de acesso e revisão antes de qualquer distribuição pública.

## Validação

- Regressão da suíte v0.5.
- Criar/anexar/listar/consultar caso; estado concorrente e conflitos `409`.
- Leitor sem permissão de escrita; revisões somente por analista/administrador; encerramento só por administrador.
- Cases e análises de outro tenant retornam `404`; dados não são incorporados por referências cruzadas.
- Integridade SHA-256 reproduzível e sensível a alteração; relatórios sem segredos de URLs mascaradas.
- Casos persistem ao reiniciar a API.

## Pendências conhecidas

- **P0 para exposição pública:** autenticação web OIDC/sessão segura, CSRF, governança de segredos e gestão de políticas LGPD (#20).
- Análise profunda em sandbox seguro com egress validado (#16).
- Assinatura digital e sistema de custódia de artefatos, retenção configurável, trilhas imutáveis externas (#19, #21).
- Confirmação independente de campanhas, identificação legal de operadores, fontes licenciadas e processo de contestação antes de qualquer afirmação sobre envolvidos.
- Paginação/filtragem, alertas, busca avançada e visualizador de grafos dedicado.
