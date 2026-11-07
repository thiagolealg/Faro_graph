# Especificação OSINT — websites, domínios e evidências

## 1. Princípio de coleta

**Passivo primeiro; ativo apenas quando necessário e controlado.** O sistema coleta informações abertas, acessíveis legitimamente e contratualmente autorizadas. Fontes externas não são automaticamente precisas: coletar, datar, qualificar e cruzar evidências.

## 2. Pipeline de domínio e URL

1. **Parsing estrito**: esquema permitido, host normalizado, IDN/Punycode, remoção de fragmentos, canonicalização cuidadosa, máscara de query tokens.
2. **DNS**: A/AAAA/CNAME/NS/MX/TXT quando relevante; divergências com histórico; TTL apenas como contexto.
3. **RDAP**: registrador, datas disponíveis, eventos, entidades públicas; privacidade de registro é neutra.
4. **TLS**: validação de hostname/cadeia/tempo, emissores, SANs e eventos CT.
5. **Infrastructure**: ASN, alocação, provedores e relações observadas; CDN, cloud e host compartilhado são operadores de serviço neutros.
6. **Reputação**: cross-check de feeds de phishing/malware; explicitar data de detecção e política de uso.
7. **Lexical**: homograph, typosquatting, combosquatting, subdomínios enganosos, entropia e nomes de marca.
8. **Histórico**: mudanças públicas de resolução/certificados/páginas sob fontes permitidas, com janela temporal.
9. **Ativo controlado**: redirects, DOM, formulários, links de saída, recursos, screenshot e conteúdo visível.
10. **Correlação**: evidências independentes, conflitos, expiradas, frescor e cobertura efetiva.

## 3. Deteção ativa

Capturar: URL final, cadeia de redirecionamentos, HTTP status, título, meta tags relevantes, estrutura DOM, elementos de login/pagamento, destinos de formulários observáveis sem submissão, chamadas de recursos, imagens estáticas para comparação de marcas. Limitar páginas, downloads, recursos, duração e tráfego. Não clicar em ações financeiras nem preencher credenciais.

## 4. Matriz de sinais

| Sinal | Peso isolado | Contexto necessário |
|---|---|---|
| Phishing confirmado por feed confiável e atual | forte | validade, falsos positivos, correspondência exata |
| Domínio recente | fraco | idade de marca, credenciais, conteúdo, contexto |
| HTTPS válido | neutro para legitimidade | apenas segurança da conexão |
| Captura de senha em site imitador | forte | marca, domínio, autorização e finalidade |
| Similaridade visual | moderado | templates legítimos e parceiros |
| Redirecionamento opaco | variável | destino e sequência |
| Mesmo ASN/IP de campanha | fraco | hospedagem multi-tenant e disponibilidade |
| Mesmo identificador público de pagamento em múltiplas fraudes confirmadas | potencialmente forte | verificar legitimidade e eventual fraude de terceiros |
| Mesmo telefone comercial em sites suspeitos | variável | reutilização por atendimento, parceiros ou falsificação |
| Ausência de dados empresariais | fraco | legislação/setor e combinação com outros sinais |

## 5. Proveniência e validade

Cada sinal deve registrar observador, coletor, fonte, licença, timestamp, hash do artefato quando permitido, janela de validade, métricas de confiança e motivo de influência no score. Indisponibilidade de fonte = desconhecido.

## 6. Política de links fornecidos por usuários

URLs podem conter credenciais ou tokens efêmeros. Exibir endereço sanitizado, usar hash e armazenar o mínimo. Não submeter URLs sensíveis automaticamente a serviços públicos; requer perfil privado compatível ou recusar análise profunda. Validar destino em **cada conexão** para impedir SSRF e rebinding.

## 7. Critérios de aceite

- Captura passiva opera sem visitar página suspeita.
- Evidências de API incluem data, fonte e restrição de uso.
- Receitas de score não confundem falta de registros com fraudes.
- Falhas geram partial/inconclusive com detalhes de cobertura.
- Conteúdo hostil nunca alcança rede interna nem logs com segredos.
