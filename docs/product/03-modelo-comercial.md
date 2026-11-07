# Modelo comercial, custos e planos

## Segmentação

**Consumer:** análise unitária, relatórios resumidos, limites de consulta, sem dados de atribuição pessoal.  
**Professional:** investigações, grafo, dossiês, revisões e APIs conforme contrato e finalidade legítima.  
**Enterprise:** monitoramento de marcas, filas de analistas, SLAs, integrações, retenção e conformidade por tenant.

## Variáveis de custo

- Cache vs. consulta externa; custo por fonte comercial.
- Captura dinâmica em sandbox (CPU, RAM, egress e armazenamento).
- Inferência visual/modelos; retenção e replicação de artefatos.
- Busca em grafo e índices; volume de monitoramento.
- Revisão humana e resposta a contestações.

## Medição sugerida

| Unidade | Definição | Controle |
|---|---|---|
| Quick scan | Análise passiva nova | Quota + cache |
| Deep scan | Navegação isolada e análise visual | Quota dedicada, timeout |
| Monitored brand | Marca com validação administrativa | Limite por plano |
| Case/dossier | Investigação conectada documentada | Auditoria + retenção |
| API request | Requisição de integração | Rate limit + chave |
| Evidence retention | Prazo/volume de artefatos | Política por tenant |

## Posicionamento e garantias

- Vender **inteligência de risco fundamentada**, não “descobrir todos os autores”.
- Contrato precisa definir limites da atribuição, confidencialidade e atualização de dados.
- Preços somente após aferir custo por análise e condições reais de provedores.
- Não monetizar divulgação de dados pessoais de terceiros ou resultados não revisados.
