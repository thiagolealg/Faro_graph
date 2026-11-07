# Personas, jornadas e decisões

## Personas

| Persona | Contexto | Pergunta | Resultado |
|---|---|---|---|
| Consumidor | Recebeu link por WhatsApp | Posso inserir meus dados? | Alerta legível, canais oficiais e limitações |
| Comprador | Loja com desconto extremo | Há indicadores de loja falsa? | Semáforo cauteloso e evidências não sensacionalistas |
| Analista OSINT | Vários sites com mesmo visual | Pertencem à mesma campanha? | Grafo de relações, trilha e incerteza |
| Líder antifraude | Marca imitada | Quais domínios exigem triagem? | Fila, priorização e tendências |
| Jurídico/compliance | Solicitação de dossiê | Quais vínculos são sustentáveis? | Evidências, cadeia de custódia, classificação de divulgação |
| Admin SaaS | Clientes isolados | Quem acessou cada caso? | Auditoria e políticas de retenção |

## Jornadas e critérios

### J-01 Consulta avulsa
1. Usuário cola URL; sistema avisa para não compartilhar tokens e dados pessoais.
2. URL é validada; endereço interno/privado é recusado.
3. Tela mostra análise e progresso sem revelar URL perigosa como hiperlink comum.
4. Resultado contém risco, confiança, cobertura, evidências e próximos passos.
5. Usuário pode consultar detalhe técnico, mas não ver dados pessoais de terceiros.

**Aceitação:** resultado inteligível em uma tela móvel, sem promessa de segurança absoluta.

### J-02 Investigação com possível envolvimento
1. Analista autorizado inicia caso com finalidade e justificativa.
2. Sistema localiza entidades/recursos públicos da página, registros e ameaças relacionadas.
3. Grafo distingue relações técnicas, comerciais, declarações e atribuições humanas.
4. Analista filtra por janela temporal, qualidade da evidência e classe do vínculo.
5. Arestas fracas não são tratadas como autores comuns; hipóteses alternativas são registradas.
6. Dossiê passa por revisão para qualquer alegação sobre pessoa identificável.

**Aceitação:** caminhos explicáveis; nenhum “envolvido” decorrente apenas de co-hospedagem.

### J-03 Monitoramento de marca
1. Empresa comprova controle da marca/domínio monitorado.
2. Define conjunto de nomes oficiais, parceiros e domínios licenciados.
3. Recebe alertas por correspondência de identidade + sinais de fraude.
4. Relaciona campanhas, abre incidentes e acompanha a evolução.
5. Exporta relatório conforme controles de visibilidade.

### J-04 Contestação
1. Titular/organização comunica possível erro.
2. Produto preserva versão da decisão e registra protocolo.
3. Revisor independente reavalia evidências e exceções verificáveis.
4. Corrige classificação, notifica destinatários quando aplicável e registra revisão.

## Critérios de UX

- Distinguir **ameaça conhecida**, **suspeita**, **correlação** e **não determinado**.
- Exibir origem e atualidade de cada achado e não apenas a pontuação.
- Fornecer ações seguras: não inserir dados; verificar domínio oficial; contatar canal conhecido; preservar evidências sem clicar no site.
- Exibir listas de entidades com filtro por tipo e natureza do vínculo; evitar rótulos imputadores.
- Acessibilidade WCAG 2.2 AA, contraste, teclado, leitores de tela e linguagem em português brasileiro.
