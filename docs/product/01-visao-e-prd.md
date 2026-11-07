# PRD — Visão de produto e requisitos de negócio

**ID:** FARO-PRD-001 · **Versão:** 1.1 · **Status:** proposta para aprovação.

## 1. Visão e posicionamento

O FARO transforma URLs, domínios, páginas, marcas e indicadores públicos em avaliações técnicas de risco de fraude, phishing e impersonação. Seu diferencial é uma **investigação conectada**, destinada a descobrir relações entre campanhas, infraestrutura, sites, canais e potenciais participantes. Não promete identificar “todos os envolvidos”: registros ocultos, identidades falsas, serviços compartilhados e limitações legais podem impedir atribuição completa.

### Problemas prioritários
- Consumidores não conseguem diferenciar páginas oficiais e réplicas plausíveis.
- Equipes antifraude encontram sites suspeitos, mas têm dificuldade em relacionar episódios recorrentes.
- Resultados baseados apenas em blacklists deixam passar campanhas recém-criadas.
- Evidências dispersas não permitem explicar por que um domínio ou participante foi associado a uma investigação.
- Acusações equivocadas causam danos reputacionais e legais.

### Proposta de valor
- **Consumidor:** classificação prudente e orientação preventiva antes de informar dados.
- **Analista:** timeline e dossiê de evidências com proveniência.
- **Empresa:** monitoramento de marcas, identificação de clusters e priorização de incidentes.
- **Integrador:** API auditável de risco com metadados e atualização assíncrona.

## 2. Objetivos e indicadores

| Objetivo | Medida de sucesso inicial |
|---|---|
| Triar links suspeitos | Consulta rápida p95 < 8 s sem cache em condições normais |
| Detectar phishing relevante | Precision alto/crítico >= 95%, Recall phishing confirmado >= 90% em conjunto independente |
| Reduzir falsas imputações | 100% das atribuições pessoais publicáveis passam por revisão humana |
| Mostrar explicações | 100% dos achados relevantes com fonte, observação, timestamp e método |
| Controlar incerteza | 100% das análises com score, confiança e cobertura ou estado inconclusivo |
| Garantir isolamento | Testes de SSRF e segregação multi-tenant sem escape conhecido no lançamento |

Metas propostas, a validar empiricamente; não são promessas atuais.

## 3. Perfis

- **Consumer**: conferência de links e lojas.
- **Investigator**: coleta passiva, dossiê, grafo e documentação de vínculos.
- **Analyst/Reviewer**: triagem, hipóteses, decisões, falsos positivos, contestação.
- **Brand Protection**: monitoramento de marcas e campanhas imitadoras.
- **Admin/Compliance**: segregação, retention, uso legítimo, licenciamento e auditoria.
- **API Client**: análise síncrona cacheada ou jobs assíncronos.

## 4. Requisitos funcionais (IDs estáveis)

### Núcleo URL e detecção
- **RF-001** Entrada/normalização de URL e domínio, com sanitização de segredos.
- **RF-002** Triagem OSINT passiva de DNS, RDAP, TLS/CT e reputação.
- **RF-003** Inspeção dinâmica sob sandbox e proteção de rede.
- **RF-004** Identificação de typosquatting, IDN/homograph e impersonação.
- **RF-005** Análise de formulários, redirects, conteúdo e captura suspeita de credenciais.
- **RF-006** Detecção multimodal de clonagem visual com evidências.
- **RF-007** Risk score 0-100, confidence, coverage, explicações e inconclusão.
- **RF-008** Resultados, histórico, reanálise, diferenças e exportação.

### Inteligência de envolvidos
- **RF-009** Extração de entidades observadas: domínios, IPs, ASNs, certificados, emails públicos, telefones comerciais, identidades empresariais, contas públicas, provedores e canais de pagamento publicamente divulgados.
- **RF-010** Normalização, deduplicação e resolução de entidades, preservando homônimos e ambiguidades.
- **RF-011** Grafo de relações tipadas com evidência, temporalidade, confiança e status.
- **RF-012** Detecção de vínculos entre sites, campanhas, infraestrutura, marcas e contas com explicações.
- **RF-013** Suporte a hipóteses alternativas, revisão e contestação.
- **RF-014** Dossiê de investigação, timeline, origem e cadeia de custódia digital.
- **RF-015** Separação de facilitadores neutros (CDN, registrador, cloud, gateway) de operadores suspeitos.
- **RF-016** Modos de divulgação distintos: consumidor, profissional autorizado, jurídico/compliance.
- **RF-017** Monitoramento de redes/campanhas com alertas de novos nós e arestas.

### Plataforma
- **RF-018** Autenticação, autorização RBAC e isolamento por tenant.
- **RF-019** REST API com versões, jobs assíncronos e webhooks assinados.
- **RF-020** Permissões e quotas por plano, provedor e finalidade.
- **RF-021** Gestão de marcas verificadas e parceiros autorizados.
- **RF-022** Painel de analista e operação de revisão.
- **RF-023** Auditoria, governança, exclusão e retenção configuráveis.
- **RF-024** Exportação PDF/JSON/CSV de conteúdo permitido pela política.
- **RF-025** Integração com fontes e sistemas de resposta a incidentes.

## 5. Priorização

| Prioridade | Inclusão |
|---|---|
| P0 / MVP | RF-001–005, RF-007–010 básico, RF-011 básico, RF-013–016 básico, RF-018–020, RF-023 |
| P1 | RF-006, RF-012 avançado, RF-014 aprofundado, RF-017, RF-021–022, RF-024 |
| P2 | Detecção de campanhas, QR Code, extensão, grafo avançado e automação SIEM/SOAR |

## 6. Jornadas de referência

**Jornada A — URL suspeita:** enviar URL → validar segurança → OSINT passivo → opcional sandbox → correlação → risco + evidências → orientação preventiva.

**Jornada B — Investigar envolvidos:** abrir análise → extrair e resolver entidades → construir subgrafo → buscar relações adicionais permitidas → avaliar hipóteses → revisão humana → gerar dossiê com limitações.

**Jornada C — Marca sob ataque:** cadastrar marca autorizada → coletar sinais de impersonação → triagem → correlação com incidentes → alerta → revisão → resposta por canais legítimos.

## 7. Regras de produto

1. Não usar “site seguro”, “culpado” ou “responsável confirmado” sem base apropriada.
2. Não aceitar similaridade de identidade como conclusão exclusiva.
3. Serviços de hospedagem, registrar, DNS, CDN e pagamentos não são participantes presumidos da fraude.
4. Impossibilidade de determinar autoria deve resultar em **atribuição não determinada**.
5. Informação pessoal apenas com base, necessidade, acesso e finalidade legítima.
6. O cliente não executa automaticamente ações contra terceiros com base no score.
7. Evidências impossíveis de reproduzir recebem observação de proveniência/limitações.
8. Conteúdo remoto é não confiável, inclusive instruções ocultas e prompts.

## 8. Fora de escopo inicial

- Doxxing, coleta de endereços residenciais, perfis privados, contatos familiares ou dados vazados.
- Engenharia social ativa, pré-textos, login não autorizado e interações financeiras.
- Varredura intrusiva em infraestrutura de terceiros sem autorização.
- Envio automático de acusações ou remoções a partir de inferência.
- Determinação jurídica de autoria criminal.

## 9. Dependências e hipóteses

- Acesso comercial adequado às fontes; termos e preços podem mudar.
- Catálogo de marcas oficiais verificado e atualizado.
- Dataset rotulado com testes temporais e revisão humana.
- Definição formal do papel controlador/operador de dados em cada fluxo.
- Infraestrutura de sandbox capaz de garantir egress isolado.

## 10. Critérios de aceitação de produto

- CA-01: URL válida cria job e produz relatório ou erro claro.
- CA-02: reputação indisponível não equivale a classificação segura.
- CA-03: domínio novo não basta para acusação.
- CA-04: relatório diferencia risco, confiança e cobertura.
- CA-05: cada aresta do grafo apresenta evidência e tempo.
- CA-06: nó provedor neutro não aparece como “golpista”.
- CA-07: atribuição pessoal sem prova revisada não é publicada.
- CA-08: SSRF, DNS rebinding e redirecionamento interno são bloqueados.
- CA-09: tenant não acessa investigações de outro tenant.
- CA-10: usuário pode contestar e receber registro de decisão.

## 11. Definição de valor entregue

O produto só será considerado funcional quando a classificação permitir uma decisão preventiva informada, e uma investigação profissional for capaz de demonstrar **o que se observou, como, quando, onde, por que se conectou e o que permanece desconhecido**, sem transformar correlações em acusações.
