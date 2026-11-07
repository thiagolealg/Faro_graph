# FARO Graph v0.5 — Threat Intelligence offline e rastreável

**Situação:** implementação do snapshot local de reputação, sem consultas externas ao fornecedor e sem tráfego ao domínio analisado. Este módulo **não comprova fraude, autoria ou envolvimento de pessoas**.

## Funcionalidades entregues

- Integração opt-in com arquivo JSONL de indicadores autorizados, carregado **uma vez no startup** e validado integralmente.
- Configuração `FARO_TI_ENABLED=1`, `FARO_TI_PATH=/caminho/absoluto/feed.jsonl`, `FARO_TI_LICENSE_ACK=1` (confirmação manual de licença/uso permitido; não equivale a verificação legal automática).
- Tipos `url` e `hostname`, apenas correspondência **exata**. Não existe matching de subdomínios por sufixo nem generalização automática para domínio registrável.
- Categorias `phishing`, `malware`, `scam`, `brand_impersonation`, `other`.
- Registros obrigatoriamente com fonte (`source`), data de observação (`observed_at`) e expiração (`expires_at`), com timezone. O prazo da evidência não pode superar 90 dias entre origem e expiração.
- Indicadores expirados são ignorados. Sem correspondência **não** significa que o site é seguro.
- Evidências possuem `impact=0`; a pontuação passa a refletir um piso determinístico quando há correspondência **exata de URL** (80) ou de hostname (55), sem alegar probabilidade calibrada.
- Registro `threat_intel` no resultado persistido, hash SHA-256 do snapshot e arestas rastreáveis no grafo de indicadores.
- Dados de fornecedores nunca são enviados para provedor terceirizado; queries e fragmentos não são aceitos nos indicadores do snapshot para evitar matching com perda de informação e vazamento de tokens.
- Frontend exibe a origem, a classe de risco reportada e a validade temporal da evidência.

## Esquema do feed

Uma linha JSON por indicador, sem dados pessoais ou segredos. **Exemplo sintético de formato**, não representa ameaça real:

```json
{"type":"hostname","indicator":"example.com","source":"fonte_autorizada","category":"phishing","observed_at":"2026-11-07T00:00:00Z","expires_at":"2026-11-10T00:00:00Z"}
```

Campos obrigatórios exatos: `type`, `indicator`, `source`, `category`, `observed_at`, `expires_at`. URLs completas devem ser HTTP(S), normalizadas pelo FARO e sem query, fragmento nem segmentos mascarados. Hostnames devem estar em minúsculas e IDNA ASCII. Carregamento rejeita JSON inválido, campos inesperados, fonte inválida, conteúdo com mais de 2 MB, mais de 10.000 registros, intervalos incoerentes, symlinks e dados sensíveis reconhecíveis pelo validador.

## Procedimento de uso local

1. Obter arquivo apenas de fonte com direito de acesso e processamento devidamente conferido; armazenar fora do repositório em diretório com permissões restritas.
2. Normalizar/minimizar os indicadores no processo de ingestão governado externamente. Não copiar URL de vítima nem dados pessoais.
3. Configurar as três variáveis (`FARO_TI_ENABLED`, `FARO_TI_PATH`, `FARO_TI_LICENSE_ACK`).
4. Reiniciar o serviço FARO para que a nova versão do snapshot seja carregada; verificar `GET /healthz` (booleano `reputation_snapshot_enabled`).
5. Executar um teste de comparação conhecido em ambiente controlado, sem usar URL de terceiro real.
6. Ao vencer o prazo, substituir o feed por material válido e reiniciar; monitorar data do arquivo e sua origem externamente.

## Limitações e decisões

- **Não** implementa download automático, API de URLhaus, OpenPhish ou Google Web Risk. Licenças, custos, autenticação e privacidade desses fornecedores devem ser homologados separadamente.
- Feed malformado com integração habilitada impede o startup (fail closed); ausência de match não reduz riscos anteriores.
- A correspondência URL é feita sobre URL já sanitizada pelo FARO; páginas que dependem de query específica podem gerar **não correspondência**, e um padrão de caminho generalizado não é aceito.
- Um registro de domínio em feed é menos preciso que URL exata e recebe pontuação menor; nenhum desses eventos constitui prova de operação atual ou de culpabilidade.
- A confiança continua marcada como `medium` mesmo com correspondência; esse valor não representa probabilidade estatística.
- `snapshot_sha256` permite auditoria da versão local, mas não autentica o fornecedor; a proveniência original e licença devem ser gerenciadas externamente.
- Não há mecanismo de atualização online, polling, assinatura digital do feed ou cache distribuído.
- Não expor o dashboard com chave de API para público; autenticação OIDC, sandbox dinâmico e integração de reputação remota continuam pendentes.

## Qualidade

Cobertura por testes automatizados para: correspondência exata, ausência de generalização, validade/expiração, falhas de esquema, limites de tamanho, privacidade, falha de inicialização, integrações API e grafo, risco resultante e configuração opcional.
