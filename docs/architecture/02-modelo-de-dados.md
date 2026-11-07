# Modelo de dados de domínio — especificação conceitual

## 1. Fundamentos

- IDs imutáveis; UTC para timestamps; distinção entre `observed_at`, `collected_at`, `valid_from`, `valid_to`.
- Isolamento por tenant em recursos privados; dados globais compartilháveis somente após controle de licença e privacidade.
- Evidência não é conclusão; observação, inferência e decisão são registros distintos.
- Entidade identificável não deve ser automaticamente mesclada a um identificador técnico.
- Toda mudança em classificação e hipóteses mantém versão anterior.

## 2. Agregados principais

| Entidade | Campos conceituais principais | Regras |
|---|---|---|
| `Tenant` | id, plano, estado, política de retenção, região | isolamento obrigatório |
| `User` | id, tenant, identidade, papel, MFA, status | menor privilégio |
| `ProtectedBrand` | id, titular, domínios verificados, marcas e parceiros | prova de autorização |
| `Case` | id, tenant, finalidade, escopo, status, owner, revisão | caso investigativo |
| `ScanJob` | id, idempotência, input, modo, política, progresso, falhas | assíncrono |
| `URLIndicator` | id, URL normalizada, hash, host, registro sensível saneado | segredos fora de logs |
| `Domain` | id, FQDN, registrável, Unicode/Punycode, fonte | desambiguação |
| `InfrastructureIndicator` | id, tipo IP/ASN/NS/certificado, valor, validade | pode ser compartilhado |
| `Observation` | id, sujeito, predicado, objeto, valores, tempo, coletor | dado bruto estruturado |
| `Evidence` | id, observação, source, hash, coleta, validade, licença | integridade e proveniência |
| `Entity` | id, tipo, nome exibível, aliases, contexto, privacidade | resolução conservadora |
| `Relationship` | id, origem, destino, tipo, evidências, temporalidade, status | arestas tipadas |
| `AttributionHypothesis` | id, suspeita, escopo, suporte, contraevidência, confidence | hipótese ≠ fato |
| `RiskAssessment` | id, scan, score, confiança, cobertura, versão do modelo | resultado de risco |
| `ThreatMatch` | id, indicador, provedor, data, validade, restrições | evitar dupla contagem |
| `Campaign` | id, cluster, intervalo, confiança, status | não equivale a grupo criminoso |
| `Incident` | id, marca, case, status, responsáveis internos | gestão operacional |
| `AnalystReview` | id, actor, decisão, motivos, evidence_snapshot | quatro-olhos |
| `Artifact` | id, tipo, checksum, storage-ref, classificação | retenção/criptografia |
| `ExportRecord` | id, audience, aprovado_por, redaction, checksum | rastrear divulgação |
| `AuditEvent` | id, ator, recurso, ação, timestamp, IP admin | protegido contra edição |
| `SourceConnector` | id, provider, licença, cota, política de visibilidade | governança |

## 3. Ontologia de entidades

`Website`, `URL`, `Domain`, `IP`, `ASN`, `Nameserver`, `Registrar`, `HostingProvider`, `CDNProvider`, `TLSCertificate`, `Brand`, `LegalEntity`, `PublicBusinessIdentity`, `PublicSocialAccount`, `PublicContactChannel`, `PublicEmail`, `PublicPhone`, `PaymentService`, `PublicPaymentIdentifier`, `Campaign`, `ThreatActorLabel`, `Incident`, `Person` (restrito e sujeito a requisitos reforçados), `EvidenceSource`, `Artifact`.

**Regra crítica:** `Person` só é criado/associado com justificativa legítima e fontes de identificação apropriadas. IP, telefone e email, isoladamente, não identificam autor. Registrar possibilidade de identidade compartilhada, terceirizada ou usurpada.

## 4. Tipos de relacionamento

`resolves_to`, `redirects_to`, `uses_certificate`, `hosted_on`, `served_by`, `registered_via`, `claims_to_represent`, `visually_similar_to`, `shares_public_contact`, `references_payment_channel`, `links_to`, `observed_in_campaign`, `asserted_affiliation`, `verified_affiliation`, `controlled_by` (somente prova forte), `provided_service_to` (neutro), `reviewed_as_false_positive`.

Aresta registra: `relationship_type`, `direction`, `confidence`, `assertion_class` (`observed|inferred|claimed|verified|contested`), `evidence_ids`, `first_seen`, `last_seen`, `validity`, `review_status`, `scope`, `tenant_access` e `algorithm_version`.

## 5. Proveniência e cadeia de custódia

- Evidência: URL/fonte consultada (sanitizada), consulta permitida, método, carimbo temporal, snapshot/hash, política de licença.
- Fonte humana: testemunho/declaração com credencial, contexto e confiabilidade; nunca confundir relato com verificação.
- Observação derivada: link de origem, transformação, versão da ferramenta, parâmetros relevantes, limitações.
- Exports: manifest de IDs de evidência, hashes, versão do relatório e redactions.

## 6. Política de retenção

Valores a definir com compliance; evitar números arbitrários como obrigação legal universal. Proposta de tiers: artefatos brutos temporários (curta retenção), observações técnicas com TTL por fonte, relatórios de incidentes sob contrato e logs de auditoria com prazo definido. Mecanismo para expurgo, restrição, bloqueio legal e rastreio de deleção.

## 7. Invariantes

1. Nenhuma relação sem evidência ou justificativa rastreável.
2. Nenhuma classificação pessoal publicada sem revisão registrada.
3. Nenhum tenant acessa dados privados de outro tenant.
4. Não mesclar entidades em silêncio diante de nomes/identificadores ambíguos.
5. Histórico e timestamps preservados mesmo se score mudar.
6. Dados externos podem estar desatualizados; manter status de frescor.
