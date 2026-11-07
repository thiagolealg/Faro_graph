# FARO Graph v0.7 — OIDC opcional, sessões e proteção CSRF

**Status:** implementação testada localmente; homologação com provedor de identidade real e segurança de infraestrutura **pendentes**. **Não habilita produção pública.**

## Escopo entregue

- Fluxo **Authorization Code + PKCE S256**; `state` vinculado a cookie efêmero, de uso único, e `nonce` verificado.
- Confiança no token de identidade somente após assinatura **RS256** verificada por JWKS, `iss`, `aud`, `exp`, `iat`, `nonce`, `azp` quando presente; nenhum algoritmo `none` ou `HS256` aceito.
- Mapeamento explícito `issuer + subject → tenant, actor, role` por allowlist de configuração. Nenhuma autoatribuição de papel por atributos do token, e-mail ou domínio corporativo.
- Sessões opacas de **8 horas**, com token armazenado apenas como SHA-256 em SQLite. Cookies de sessão com prefixo `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`.
- Token CSRF de sessão mantido em cookie separado `__Host-` (Secure, SameSite=Lax) para leitura pela interface, vinculado por hash ao registro do servidor e verificado pelo cabeçalho `X-Faro-CSRF` **e** pela origem HTTP configurada em todos os métodos de escrita autenticados via cookie.
- Logout revoga imediatamente a sessão em SQLite; alterações/remoção de conta, papel ou tenant na allowlist invalidam a sessão após reinício com a nova configuração.
- Segregação preservada entre chaves de API de integração e sessões de usuário do painel; API keys continuam sem exigir CSRF, pois não são credenciais enviadas automaticamente pelo navegador.
- Frontend detecta o modo OIDC, oferece login/logout e deixa de solicitar chave de API no painel quando OIDC está habilitado.
- Cabeçalhos de segurança `CSP`, `HSTS` em HTTPS, `X-Frame-Options`, `Referrer-Policy`, `nosniff` e `Cache-Control: no-store` em rotas de autenticação.
- Testes de estado/replay, PKCE, CSRF, origem cruzada, acesso por tenant, revogação, papéis e validação de JWT assinado.

## Configuração (exemplo com placeholders)

Credenciais e políticas devem ser armazenadas em um **gerenciador de segredos**, não no repositório, no console ou em relatórios. Configure o aplicativo OIDC como cliente autorizado com redirect URI exata. A identidade do usuário deve ter aprovação prévia.

```json
FARO_OIDC_CONFIG = {
  "issuer": "https://identity.example.org/realms/faro",
  "authorize_url": "https://identity.example.org/realms/faro/protocol/openid-connect/auth",
  "token_url": "https://identity.example.org/realms/faro/protocol/openid-connect/token",
  "jwks_url": "https://identity.example.org/realms/faro/protocol/openid-connect/certs",
  "client_id": "faro-web",
  "redirect_uri": "https://faro.example.org/v1/auth/callback",
  "ui_origin": "https://faro.example.org"
}
```

A variável contém **uma string JSON**. Para cliente confidencial, pode conter `"client_secret"`, com tamanho mínimo e proteção de segredo. Forneça também uma string JSON em `FARO_OIDC_USERS_JSON`:

```json
[
  {"subject":"SUB_INSTITUCIONAL_VERIFICADO","tenant_id":"empresa_1","actor_id":"analista01","role":"analyst","hourly_quota":50}
]
```

O campo `subject` deve ser o identificador estável emitido pelo provedor, e não o e-mail. Papéis válidos: `reader`, `analyst`, `admin`. O serviço pode iniciar só com OIDC (sem `FARO_API_KEY`) ou permitir chaves separadas de integração com `FARO_TENANTS_JSON`.

As rotas de login/callback exigem **HTTPS real** e cookies `Secure`: o fluxo OIDC não funcionará em HTTP simples em `localhost`. Para desenvolvimento local, mantenha autenticação por chave em loopback ou configure TLS local seguro. O provedor OIDC deve ser confiável e administrativamente configurado; nenhum endpoint é fornecido pelo usuário final.

## Contratos

| Endpoint | Descrição |
|---|---|
| `GET /v1/auth/config` | Modo `oidc` ou `api_key_local` (sem informações sigilosas) |
| `GET /v1/auth/login` | Inicia Authorization Code + PKCE |
| `GET /v1/auth/callback` | Consome estado e código, valida token, cria sessão |
| `GET /v1/auth/session` | Identidade autorizada, papel, organização e token CSRF para JS |
| `POST /v1/auth/logout` | Exige origem + token CSRF, revoga a sessão |

Em modo OIDC, escritas de análise e caso exigem `Origin` idêntica a `ui_origin` **e** `X-Faro-CSRF`. Leituras exigem apenas sessão válida. Credenciais de máquina permanecem segregadas por cabeçalho `X-Faro-Api-Key`.

## Segurança e pendências para produção

1. Homologar contra provedor OIDC real em **staging com HTTPS**, incluindo logout, rotação de certificados JWKS e falhas de disponibilidade. Os testes automatizados usam mocks e chaves locais; não são prova de integração com um provedor externo.
2. Instalar proxy confiável com restrição de `Host`, cabeçalhos `Forwarded`/`X-Forwarded-*` sob controle, TLS, HSTS e política de acesso.
3. Implementar mitigação de abuso nos endpoints **públicos** de login/callback, observabilidade sem parâmetros `code`/`state`, proteção de logs de acesso e critérios de contenção de incidentes.
4. Definir rotação de credenciais OIDC, resposta a compromissos e revogação central/SSO (quando aplicável) além do TTL local de sessão.
5. Aplicar MFA no provedor corporativo; complementar com testes de segurança do navegador, SAST/DAST, revisão de dependências, CSP ajustada e avaliação LGPD.
6. Adotar backend de sessão mais robusto para implantações distribuídas e retenção/expurgo agendados (#21).
7. Todos os coletores remotos de navegação continuam **desabilitados**; sandbox e egress seguro permanecem no escopo #16.

**Limites:** sessão OIDC não identifica envolvidos em fraude nem substitui revisão humana, controles de ambiente ou autorização investigativa.
