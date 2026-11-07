# Estratégia de QA, avaliação de modelos e critérios de liberação

## 1. Tipos de teste

**Funcionais:** parsing, idempotência, jobs, evidências, score, grafo, revisão, exportação, quotas e permissões.

**Segurança:** SSRF (IP/IPv6/DNS rebinding/redirect), sandbox escape, egress, XSS, BOLA/IDOR, enumeração, exposição de tokens, prompt injection, exaustão de recursos e tenants cruzados.

**Inteligência:** reputação, divergência de fonte, registros ocultos, certificado HTTPS legítimo, novos domínios benignos, sites comprometidos, impersonação autorizada e false positives de marca.

**Atribuição:** homônimos, CDN compartilhada, tema repetido, analytics de agência, nomes plantados, identidade usurpada, sites em mesmo IP sem controle comum, mudança de controle temporal e hipóteses contraditórias.

**Operação:** timeouts, recuperação de jobs, indisponibilidade parcial de provedores, rate limit, dead-letter, latência, backup/restore.

## 2. Datasets de avaliação

Separar treino, validação e teste por **campanha e janela temporal** para evitar vazamento. Incluir classes benignas difíceis: novos sites, pequenos comércios, plataformas compartilhadas, parceiros e páginas de credenciais legítimas. Testes internacionais e brasileiros. Rótulos humanos com resolução de conflitos e rastreabilidade.

## 3. Metas iniciais

- Precision de alto/crítico >= 95% em amostra independente.
- Recall de phishing confirmado >= 90%.
- FPR de sites legítimos <= 1%, com estratificação por setor.
- Evidência usada em classificação com fonte e tempo: 100%.
- Arestas do grafo com proveniência: 100%.
- Atribuição nominativa exportada sem aprovação: **0**.
- Violação de egress e vazamento cross-tenant: **0**.

Esses números são gates propostos, a reavaliar por baseline real, não métricas já obtidas.

## 4. Cenários de aceite

| ID | Cenário | Esperado |
|---|---|---|
| QA-001 | Site malicioso confirmado por feed atual | risco compatível com evidência e fonte |
| QA-002 | Fonte externa falha | partial/inconclusivo e cobertura reduzida |
| QA-003 | Site legítimo novo | não alto risco apenas por idade |
| QA-004 | Dois sites no mesmo CDN | sem atribuição de operador comum |
| QA-005 | Site publica nome de pessoa inocente | declaração do site, não confirmação |
| QA-006 | URL com token | token não vaza a logs/provedores públicos |
| QA-007 | Redirect para localhost | bloqueio no destino efetivo |
| QA-008 | Cliente A tenta acessar caso B | 403/404 conforme política, log de incidente |
| QA-009 | Investigação contestada | histórico e estado disputado preservados |
| QA-010 | Dossiê exportado | audiência/redaction/revisor registrados |

## 5. Monitoramento pós-release

Amostragem de novas classes, revisão humana, análise de drift, falsos positivos por marca, clusters incorretos, reclassificações e custo por análise. Voltar versão quando regressão comprovada.
