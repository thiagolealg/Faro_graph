# Grafo de entidades, relações e campanhas

## 1. Objetivo

Visualizar e analisar relações de websites suspeitos, infraestrutura, domínios, marcas, contas públicas, organizações e campanhas, sem assumir automaticamente causalidade, controle ou culpa.

## 2. Ontologia de nós

- Recursos web: URL, website, domínio, subdomínio, redirect, asset.
- Infraestrutura: IP, ASN, DNS, certificado, CDN, registrar, hosting.
- Identidade: marca, organização legal, identidade empresarial alegada, perfil público, conta comercial, canal de contato.
- Pagamento: provedor/identificador **publicamente exibido**, condicionado à política.
- Inteligência: indicador, feed, evidência, campanha, incidente, hipótese, revisão.
- Pessoa: nó restrito, somente mediante finalidade e evidências apropriadas.

## 3. Tipos de arestas e semântica

| Aresta | Leitura correta | Não implica |
|---|---|---|
| `resolved_to` | DNS apontou ao IP em dado momento | dono comum |
| `hosted_on` | infra serviu conteúdo em janela observada | culpa do provedor |
| `shared_resource` | sites carregaram recurso idêntico | mesmo operador |
| `visually_similar` | layouts se parecem | fraude confirmada |
| `claimed_identity` | site diz pertencer à entidade | vínculo real |
| `redirects_to` | visita produziu redirect | controle do destino |
| `linked_public_contact` | contato público exposto na página | contato é autor |
| `references_public_payment` | identificador público exibido | titularidade ou fraude comprovada |
| `part_of_cluster` | agrupamento algorítmico | ator único |
| `verified_affiliation` | vínculo confirmado por prova e revisão | autoria penal |

## 4. Aresta como objeto de evidência

Campos: `edge_id`, `subject_id`, `predicate`, `object_id`, `observation_ids`, `assertion_class`, `confidence`, `first_seen`, `last_seen`, `collector_version`, `source_license`, `independence_group`, `review_state`, `tenant_visibility`.

Separar a confiança do **fato observado** (ex.: conteúdo contém texto) da confiança da **interpretação** (ex.: o texto identifica operador). Uma aresta pode ter observação forte e interpretação fraca.

## 5. Algoritmos e descobertas

- Busca BFS/DFS limitada por profundidade, tipo e orçamento de arestas.
- Caminho mais curto condicionado a confiança mínima, período e tipo de relacionamento.
- Comunidades e clusters para campanhas, sem atribuir pessoa real.
- Similaridade por Jaccard/MinHash em conjuntos de recursos, com verificação de contexto.
- Fingerprints visuais e DOM; indicadores com ponderação de popularidade para não supervalorizar bibliotecas comuns.
- Entropy/rare-feature weighting para sinais potencialmente distintivos, com validação estatística.
- Correlação temporal de registros, redirects e páginas.
- Negative evidence: parceiros autorizados, shared hosting, templates e falsificação possível.

## 6. Regras anticorrelação espúria

1. Não inferir vínculo direto entre dois websites só por mesmo IP público ou CDN.
2. Impor limite de grau para hubs (Google Analytics, Cloudflare, provedores comuns).
3. Não transitar `hosted_on` → `same_owner` sem evidências independentes.
4. Restrição de arestas por período para evitar vínculos históricos inválidos.
5. Aplicar scores por famílias de evidência para não duplicar o mesmo fato.
6. Distinguir identidade declarada por site de identidade validada externamente.
7. Não clusterizar pessoas físicas a partir de similaridade nominal.

## 7. Visualização analítica

- Painel central com grafo filtrável por categoria, relevância, data e fonte.
- Cores/legendas por classe de nó; espessura de aresta por confiança **interpretativa**.
- Clique em vínculo abre evidência e hipóteses alternativas.
- Nós provedores neutros têm rótulos explícitos.
- Timeline interativa com mudanças de IP, página, campanha e score.
- Exportação apenas com permissão, minimização e marca d'água de restrição de uso.

## 8. Métricas de qualidade

Taxa de falsos merges, pureza de clusters, cobertura de links rotulados, estabilidade temporal, taxa de relações sem fonte (meta zero), análise de casos de hubs, tempo p95 para subgrafos de N nós, custo por investigação e reversões humanas.

## 9. Evolução de storage

MVP em PostgreSQL com tabelas `entities`, `relationships`, `observations`, índices temporal/tenant. Só migrar para motor dedicado após benchmarks reais de exploração multi-hop, queries complexas e volume de arestas.
