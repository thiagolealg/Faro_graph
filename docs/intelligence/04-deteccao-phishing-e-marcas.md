# Detecção de phishing, lojas falsas e clonagem de marcas

## 1. Taxonomia

Credential phishing, brand impersonation, website spoofing, typosquatting/homograph, lojas falsas, payment phishing, scam financeiro, redirect abuse e malware delivery. Uma análise pode apresentar várias classes, sem presunção penal.

## 2. Motor lexical

Comparar FQDN e domínio registrável com marcas verificadas: edit distance, keyboard adjacency, token reorder, combosquatting, subdomínio enganoso, caracteres Unicode confusáveis, caracteres ocultos e termos como “verificação”, “suporte” ou “promoção”. Aplicar controles contra nomes legitimamente parecidos e domínios de parceiros.

## 3. Motor de identidade

Comparar título, texto, logos, metadados, favicon e palavras de marca com referências verificadas. Distinguir site oficial, franqueado, marketplace, white-label, integrador e conta usurpada. Fonte principal de domínios oficiais: cadastro com verificação, não suposição de buscador.

## 4. Inspeção de comportamento

- Cadeia de redirects; destino de submit de formulário observado sem submissão.
- Campos de usuário, senha, OTP, cartão e dados pessoais.
- Scripts externos e download sugerido ou automático.
- Overlays urgentes, contadores e alegações promocionais.
- Padrões que pedem ações fora do domínio aparente.
- Alterações relevantes de conteúdo por sessão ou tempo.

Captura dinâmica deverá abortar tentativas proibidas e registrar somente sinais observacionais.

## 5. Comparação visual

Screenshot em sandbox, fingerprints perceptuais, embeddings de layout/identidade, correspondência de logos e similaridade de DOM. Registrar score de similaridade e exemplos de sobreposição **sem concluir fraude apenas por semelhança**. Marcas licenciadas e templates comerciais são casos negativos fundamentais.

## 6. Análise comercial Brasil

Sinais: dados da empresa publicamente declarados, informações de atendimento, políticas comerciais, contexto de ofertas extremas, redirecionamentos de checkout, solicitação de PIX/boleto, beneficiário **apenas quando exposto legitimamente**, inconsistências de marca. Não tentar pagamento nem consultar titulares privados.

## 7. Avaliação

Datasets: phishing confirmado, páginas comprometidas, sites legítimos novos, pequenos e-commerces, governo, bancos, clones licenciados, parceiros, páginas internacionais e sites adversariais. Métricas: precision, recall, FPR, AUPRC, cobertura e falsos positivos por segmento.

## 8. Requisitos de saída

`threat_categories[]`, `brand_candidate`, `brand_evidence`, `lexical_signals[]`, `form_observations[]`, `redirect_chain`, `visual_similarity`, `confidence`, `coverage`, `limitations`, com acessos redigidos conforme regras de privacidade.
