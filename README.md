> **MVP funcional v0.5 implementado:** consulte [README_MVP.md](README_MVP.md) para instalar, executar e testar a aplicação. O restante do repositório inclui o blueprint para versões futuras.

# FARO — OSINT, Antiphishing e Inteligência Investigativa de Fraudes

**Estado:** MVP local v0.4 em desenvolvimento + blueprint de engenharia (sem prontidão para produção).  
**Versão documental:** 1.1 · **Data:** 07/11/2026 · **Classificação:** arquitetura inicial para validação.  
**Escopo:** análise de sites/URLs suspeitos, detecção de phishing, monitoramento de marcas, mapeamento de redes de fraude e atribuição investigativa baseada em evidências.

## Propósito

O FARO é especificado como plataforma SaaS B2C/B2B, API-first e multi-tenant. O sistema responde a duas perguntas distintas: **(1) quais riscos este site apresenta?** e **(2) quais entidades, recursos e possíveis participantes estão relacionados à operação?**. Uma relação técnica não é prova de autoria, participação ou crime.

## Princípios inegociáveis

- Evidência antes de conclusão; origem, data, proveniência, licença e integridade registradas.
- **Identificação de envolvidos é probabilística e sujeita a revisão humana**; não prometer identificação exaustiva, nomes reais ou imputação criminal a partir de IP, ASN, hospedagem, analytics ou coincidências isoladas.
- Separar *observado*, *inferido*, *alegado*, *confirmado* e *contestado*; expor confiança e lacunas.
- OSINT passivo por padrão; investigação dinâmica apenas em sandbox, com limites e autorização adequada.
- Proteger dados pessoais; LGPD, propósito legítimo, minimização e direitos dos titulares.
- Evitar SSRF, exfiltração, coleta invasiva, transações e tentativas de autenticação.
- Pontuação de risco não é probabilidade de fraude nem veredito jurídico.

## Índice documental

| Documento | Conteúdo |
|---|---|
| [Visão de produto](docs/product/01-visao-e-prd.md) | PRD, requisitos, metas, escopo e critérios de aceite |
| [Personas e jornadas](docs/product/02-personas-e-jornadas.md) | Públicos, fluxos e experiências |
| [Modelo comercial](docs/product/03-modelo-comercial.md) | Planos, licenciamento, custos e posicionamento |
| [Arquitetura](docs/architecture/01-arquitetura-alvo.md) | Serviços, módulos, implantação e decisões |
| [Modelo de domínio](docs/architecture/02-modelo-de-dados.md) | Entidades, relacionamentos, histórico e retenção |
| [Contratos de API](docs/architecture/03-api-contracts.md) | Endpoints, campos, eventos e versionamento |
| [Especificação OSINT](docs/intelligence/01-osint-site-domain.md) | Coleta passiva e ativa, fontes, limites e evidências |
| [Investigação de envolvidos](docs/intelligence/02-investigacao-e-atribuicao.md) | Entidades, vínculos, classificação, garantias e atribuição |
| [Grafo de relações](docs/intelligence/03-grafo-e-correlacao.md) | Modelo de grafo, algoritmos, visualizações e critérios |
| [Phishing e marcas](docs/intelligence/04-deteccao-phishing-e-marcas.md) | Heurísticas, comportamento, conteúdo, similaridade |
| [Risk engine](docs/intelligence/05-scoring-e-explicabilidade.md) | Score, confidence, coverage e lógica de decisão |
| [Fontes e integrações](docs/integrations/01-fontes-e-provedores.md) | Conectores, permissões, licenças, privacidade |
| [Proteções técnicas](docs/security/01-seguranca-sandbox-e-ssrf.md) | Sandbox, egress, validação e modelo de ameaças |
| [LGPD e governança](docs/security/02-privacidade-etica-e-atribuicao.md) | Limites de investigação, contestação e acesso |
| [UX e relatórios](docs/design/01-experiencia-e-relatorios.md) | Painéis, alertas, dossiês e linguagem |
| [Operação](docs/operations/01-observabilidade-e-slo.md) | SLO, telemetria, resiliência, custo e incidentes |
| [Validação](docs/quality/01-estrategia-de-testes.md) | Segurança, qualidade do modelo, aceitação e vieses |
| [Roadmap](docs/delivery/01-roadmap-e-backlog.md) | Fases, prioridades, dependências e entregáveis |
| [Critérios de entrega](docs/delivery/02-definition-of-done.md) | Gates de release |
| [ADRs](docs/decisions/) | Registros de decisões de arquitetura |

## Implementação atual

Além dos documentos, há um **MVP local Python/FastAPI** com interface, análise lexical e HTML informado pelo cliente, armazenamento multi-tenant, controles de acesso e grafo técnico. As consultas externas DNS/RDAP/CT são **opcionais**. Nenhum coletor visita a URL investigada; não há TLS ao vivo, navegação isolada ou identificação de responsáveis.

- [Executar o MVP](README_MVP.md)
- [Notas v0.3: DNS](docs/delivery/06-mvp-v03-dns-e-ci.md)
- [Notas v0.4: RDAP e CT](docs/delivery/07-mvp-v04-rdap-ct.md)
- [Backlog e decisões](docs/delivery/04-iniciativas-e-tarefas.md)

Este repositório **não** é um detector pronto para comercialização nem comprova crimes. Evidências técnicas têm proveniência, limites e não sustentam atribuição de autoria isoladamente.

## Entrega v0.5 — reputacao por snapshot autorizado

Indicadores de URL/hostname com validade, origem e evidencia auditavel, carregados de um arquivo local sem enviar URLs a provedores externos. Configuracao opt-in com autorizacao manual; detalhes em [v0.5](docs/delivery/08-mvp-v05-threat-intelligence.md). Sem match nao comprova seguranca.
