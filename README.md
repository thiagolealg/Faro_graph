> **MVP funcional v0.1 implementado:** consulte [README_MVP.md](README_MVP.md) para instalar, executar e testar a aplicação. O restante do repositório inclui o blueprint para versões futuras.

# FARO — OSINT, Antiphishing e Inteligência Investigativa de Fraudes

**Estado:** blueprint integral de produto e engenharia — **sem código-fonte**.  
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

## Estrutura sem código

`apps/` (interfaces), `services/` (módulos), `workers/` (investigação), `models/` (ML), `infra/` (implantação), `contracts/` (esquemas), `tests/` (testes), `docs/` (especificações). Diretórios de implementação contêm somente `.gitkeep` — nenhum código implementado.

## Como usar este repositório

1. Revisar e aprovar PRD, fluxos de atribuição e requisitos legais.
2. Validar fontes e licenças comerciais antes de integrações.
3. Congelar contratos de dados e endpoints da versão 1.
4. Implementar gradualmente por fases, sem tratar especificação como sistema já operante.

**Importante:** este material não afirma que a ferramenta existe ou detecta fraudes em produção; é a especificação completa para sua construção.
