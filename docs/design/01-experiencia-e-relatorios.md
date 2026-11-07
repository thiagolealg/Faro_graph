# UX, telas, linguagem e especificação de relatórios

## 1. Arquitetura de informação

**Consumer:** Início → análise de URL → resultado → evidências principais → orientação segura → histórico opcional.

**Professional:** Workbench → casos → busca e filtros → tela de URL → timeline → grafo → hipóteses → revisões → dossiê.

**Enterprise:** Organização → marcas → monitoramento → alertas → triagem → casos → relatórios → equipe → integrações.

## 2. Tela de resultado de URL

Hierarquia: URL sanitizada, data/hora, score/faixa, confiança, cobertura, riscos observados, fontes mais importantes, explicações, instruções preventivas e limitações. Links maliciosos jamais devem ser navegáveis sem aviso e proteção. Esconder termos absolutos como “100% seguro”.

## 3. Tela de investigação dos envolvidos

- Cabeçalho do caso: finalidade, escopo, status de revisão, nível de confidencialidade.
- Grafo: relações e nós por categoria, fontes e janelas temporais.
- Painel lateral: tipo de vínculo, força da evidência, documentos, alternativas e critérios de interpretação.
- Filtros: origem, data, marca, risco, vínculo observado/inferido/verificado/contestado.
- Timeline de mudanças: criação de domínio, redirects, alteracões DNS, screenshots e campanhas.
- Caixa de hipóteses: afirmação verificável, suporte, contraevidência, alternativas e checklist de revisão.
- Separador visível entre provedores neutros e possíveis operadores.

## 4. Modelo do relatório de consumidor

1. Site analisado e instante da análise.
2. Grau de risco e cobertura.
3. Três a cinco sinais mais relevantes com fonte e data.
4. Orientação concreta: não inserir dados, verificar serviço por canal conhecido, considerar denúncia às entidades apropriadas.
5. Incertezas: resultados incompletos ou podem mudar.

## 5. Modelo do dossiê profissional

1. Identificador e finalidade do caso.
2. Escopo e autorização.
3. Sumário das conclusões observáveis.
4. Inventário de URLs, domínios e entidades.
5. Tabela de relações técnicas com evidências.
6. Hipóteses de atribuição e seus níveis de confiança.
7. Linhas do tempo e grafo datado.
8. Contraevidências, ambiguidades e fontes indisponíveis.
9. Cadeia de custódia e hashes.
10. Revisões humanas e política de divulgação.
11. Ações recomendadas e limitações.

## 6. Rótulos padronizados

`Observado`, `Alegado pelo site`, `Inferência não confirmada`, `Verificado`, `Contestado`, `Indeterminado`. Evitar `golpista`, `laranja` e `criminoso` em resultados automatizados. Para scores, mostrar metodologia resumida em linguagem clara.

## 7. Acessibilidade e segurança visual

WCAG 2.2 AA como meta, suporte a teclado, leitores de tela, texto alternativo, contraste suficiente, layouts mobile, componentes de grafo com tabela textual alternativa e ausência de elementos visuais que induzam interpretação errada de certeza.

## 8. Estados de UX

`queued`, `running_passive`, `running_dynamic`, `correlating`, `completed`, `partial`, `inconclusive`, `failed`, `cancelled`. Informar o que foi realizado e o que não foi, sem prometer prazo exato ou acurácia absoluta.
