# Fontes OSINT, threat intelligence e integrações

## 1. Política de provedores

Selecionar e contratar provedores mediante finalidade, qualidade, licença, limitações geográficas, frequência, retenção, visibilidade pública da consulta, custos e disponibilidade. Não supor acesso gratuito ou uso comercial permitido apenas porque há API.

## 2. Catálogo candidato (sujeito a verificação vigente)

| Categoria | Exemplos a avaliar | Riscos e requisitos |
|---|---|---|
| Consulta de ameaças web | Google Web Risk, OpenPhish, PhishTank, URLhaus | condições comerciais e false positives |
| Enriquecimento malware | VirusTotal ou equivalentes licenciados | submissões podem expor URLs privadas |
| Site snapshots | urlscan.io ou captura própria | escolha de visibilidade e retenção |
| Domínio | RDAP e registries aplicáveis | campos ocultos, taxa e licenças |
| DNS histórico | passive DNS comercial/licenciado | precisão temporal e ownership |
| Certificados | Certificate Transparency | cobertura e interpretação |
| ASNs e alocação IP | RIRs/BGP públicos ou comerciais | cloud/CDN são hubs compartilhados |
| Marcas e empresas | registros oficiais e bases autorizadas | verificação de identidade, LGPD |
| Alertas externos | feeds licenciados, sistemas SIEM/SOAR | sanitização e autorização |

## 3. Contrato padrão de adaptador

`provider_id`, `provider_version`, `query_type`, `input_fingerprint`, `observed_at`, `queried_at`, `response_status`, `raw_ref` protegido, `normalized_findings`, `quality`, `license`, `ttl`, `is_public_submission`, `cost_estimate`, `retry_policy`.

## 4. Privacidade das consultas

- Não submeter URL contendo tokens/credenciais a serviços públicos.
- Verificar se consulta ao fornecedor torna o indicador público ou acessível a terceiros.
- Não redistribuir dados licenciados além do contrato.
- Informar mudanças de provedor que alterem transparência ou tratamento de dados.
- Ter degrade/fallback e sinalizar impacto em coverage.

## 5. Priorização de integração

MVP: RDAP, DNS, TLS/CT e pelo menos uma fonte apropriada de phishing conhecida + navegador próprio. P1: histórico DNS, reputação adicional, monitoramento contínuo, dados empresariais verificados. P2: inteligência avançada de campanhas e integração empresarial.

## 6. Governança do conector

Checklist: base de uso, contrato, chave, owner, armazenamento, limitações de rate, SLA, dados retornados, prazo de cache, benchmark de qualidade, tratamento de 429/5xx, descontinuação e monitoramento de custos.
