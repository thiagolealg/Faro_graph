# Segurança: modelo de ameaças, sandbox, SSRF e controle de abuso

## 1. Modelo de ameaças

Adversários podem fornecer URLs maliciosas, payloads de SSRF, redirecionamentos internos, DNS rebinding, JavaScript hostil, arquivos maliciosos, ataques de exaustão de recursos, prompt injection, dados falsos para incriminar terceiros e tentativas de acesso cross-tenant.

## 2. SSRF — requisitos obrigatórios

- Permitir HTTP e HTTPS somente para investigação web.
- Validar endereço com parser estrito; IDN normalizado; proibir credenciais embutidas na URL.
- Bloquear IPs privados, loopback, link-local, reservados, multicast e endpoint de metadados cloud em IPv4/IPv6.
- Resolver e verificar destino **no momento de cada conexão**; egress firewall não pode ser contornado por DNS rebinding.
- Revalidar cada redirect, host alternativo e conexão secundária iniciada pelo browser.
- Restringir portas, métodos e protocolos; impedir proxies não autorizados.
- Restringir `file://`, `ftp://`, `data:` e outros esquemas de navegação não permitidos.
- Sem sockets de rede interna ou permissões para Docker socket.
- Aplicar allow/deny list de acordo com escopo de autorização e ambiente de laboratório.

## 3. Sandbox de navegador

Worker efêmero, não privilegiado, rede segregada, seccomp/AppArmor ou microVM equivalente, filesystem limitado, sem segredos do serviço, sem cookies de cliente, sem montagem de credenciais, sem persistência de sessão, sem execução de binários baixados, permissões mínimas, bloqueio de extensões e downloads. Auditoria das políticas de egress. Destruição após cada job.

## 4. Limites propostos (revisáveis)

5 redirects, até 2 páginas dinâmicas, até 100 recursos, 30 MB de transferência total, deadlines por estágio, quota de CPU/RAM/banda e limite de captura de artefatos. Limites de tamanho de documento evitam compressão maliciosa/bombas de recursos. Browser deve abortar operações transacionais, submissão de formulários e solicitações indevidas de permissão.

## 5. Segurança de aplicação

- RBAC, MFA administrativo, mínimo privilégio e authorization by object.
- Proteção contra IDOR/BOLA, CSRF aplicável, XSS, injeção, path traversal e abuso de uploads.
- Sanitização de HTML/DOM/links perigosos antes de exibição; screenshots tratados como mídia, sem scripts.
- API keys curtas/rotacionáveis, hashing e cofre de segredos; criptografia de dados e backups.
- Logs estruturados sem tokens de URLs, headers privados e dados de identificação não necessários.
- Rate limiting, anomalia de padrões de consulta e mecanismo anti scraping.
- Prompt injection de sites externos não pode comandar LLM, API, ferramentas ou relatórios.

## 6. Uso abusivo como vetor de investigação indevida

Proibir uso para varredura de redes privadas, doxxing, identificação massiva de pessoas e coleta de dados de terceiros sem finalidade. Registrar escopo, tenant, operator e origem; impor políticas de acesso e detecção de abuso.

## 7. Plano de testes de segurança

SSRF com IP literal/encodado, DNS rebinding, IPv6, redirects em cadeia, DNS CNAME interno, redirecionamentos em JS, host Unicode, serviços de metadados, portas proibidas, manipulação de base64/URL, payloads DOM, uploads, webhooks, IDOR, tenants cruzados e prompt injection. Homologação é bloqueada diante de escape de sandbox ou divulgação de segredos.

## 8. Resposta a incidentes

Monitorar exfiltração, violações de egress, tentativas de enumerar casos, vazamento de artefatos e falhas de provedor. Isolar worker, preservar telemetria necessária, revogar credenciais, avaliar impacto e tratar notificações aplicáveis.
