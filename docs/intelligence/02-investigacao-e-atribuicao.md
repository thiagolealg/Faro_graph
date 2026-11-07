# Núcleo de investigação de envolvidos e atribuição de redes de fraude

**Código:** FARO-ATTR-001 | **Prioridade:** P0 (estrutura essencial), P1–P2 (expansão) | **Público:** analista autorizado e equipe de compliance.

## 1. Finalidade e limites

O módulo investiga **quais recursos, entidades, organizações, perfis públicos e possíveis operadores estão ligados a um website ou campanha**. O produto não garante descobrir todos os autores e não pode atribuir crime com base somente em coincidências técnicas. O objetivo é mapear relacionamentos verificáveis, formular hipóteses testáveis e gerar dossiês aptos à avaliação humana, jurídica ou comunicação adequada às autoridades competentes.

### Perguntas que deve responder
1. Quais páginas, URLs, domínios e marcas estão envolvidos na operação digital analisada?
2. Quais provedores de DNS, CDN, hospedagem, emissão de certificados e registro dão suporte técnico?
3. Quais canais de contato comerciais, perfis públicos e identidades empresariais aparecem nos sites?
4. Quais identificadores públicos de atendimento ou pagamento são divulgados e reaparecem em outros casos?
5. Quais sites parecem fazer parte da mesma campanha, com que evidências e grau de certeza?
6. Existe indicação robusta de controle comum, ou somente infraestrutura compartilhada?
7. Quem é *possível operador* vs. *provedor legítimo neutro*, *vítima de impersonação*, *terceiro citado* ou *identidade indeterminada*?
8. Quais evidências suportam e quais contradizem cada hipótese?

## 2. Taxonomia rigorosa de papéis

| Papel | Significado | Tratamento |
|---|---|---|
| Vítima / marca imitada | organização cuja imagem foi possivelmente abusada | proteger reputação; nunca marcar como cúmplice por citação |
| Plataforma/infraestrutura neutra | registrar, cloud, CDN, gateway, rede social, provedor | relação de serviço, **não suspeita penal** |
| Entidade citada | nome, endereço comercial, empresa, perfil ou contato mostrado por site | pode ser falso, clonado ou usurpado |
| Identidade reivindicada | quem o website diz ser | afirmar apenas o que foi declarado pelo site |
| Titular de recurso verificado | titular cuja relação com domínio/canal se confirmou por evidência autorizada | titularidade ≠ autoria de fraude |
| Possível operador | entidade com conjunto de sinais fortes de controle/gestão da campanha | hipótese restrita e sujeita a revisão |
| Operador confirmado | evidências independentes e revisão robusta permitem atribuição operacional contextual | evitar qualificar juridicamente como criminoso |
| Identidade desconhecida | dados insuficientes ou contraditórios | preservar como desconhecida |

**Nunca confundir** proprietário aparente do domínio, operador efetivo da página, provedor de serviço, proprietário de conta falsificada e responsável pela fraude. Cada papel requer evidências específicas.

## 3. Categorias de coleta permitida

### Técnicas
- Domínios e subdomínios, DNS e mudanças históricas disponíveis.
- IPs, ASNs, registradores, servidores de nomes e prestadores de serviço.
- Certificados e transparência de certificados.
- Cadeias de redirecionamento e recursos referenciados.
- Padrões de formulários e scripts observados sem submissão invasiva.
- Identificadores públicos presentes no HTML (por exemplo, IDs de analytics e tags), respeitando ambiguidade de agências/terceiros.
- Semelhança de páginas, imagens, estilos e layout.

### Identidades públicas contextuais
- Razão social, nome fantasia e cadastro público legitimamente consultável.
- Domínios oficiais verificados e marcas registradas publicamente.
- Contatos comerciais publicados no próprio website.
- Perfis públicos explicitamente vinculados por canais oficiais.
- Telefones de atendimento comerciais e emails públicos relevantes.
- Identificadores de pagamento **expressamente exibidos** na página, com mascaramento e política de acesso; não executar pagamentos.

### Fontes de inteligência
- Indicadores divulgados por provedores licenciados.
- Relatórios públicos confiáveis, boletins e alertas oficiais.
- Casos anteriores do próprio tenant, conforme contrato.
- Dados de transparência e registros públicos acessíveis legalmente.

### Não coletar por padrão
- Dados vazados, senhas, hashes de credenciais, documentos pessoais e endereços residenciais.
- Informações de perfis privados, familiares, contatos pessoais sem relação justificável.
- Conteúdo obtido burlando autenticação, CAPTCHA ou proteção de acesso.
- Dados bancários privados, titularidade privada de contas ou informações obtidas por pretexto.

## 4. Método de atribuição — oito etapas

**A1 · Definição de caso.** Registrar finalidade, cliente, autorização, hipótese inicial, período, marcas e escopo permitido. Impedir consultas irrestritas sobre pessoas sem relação justificada.

**A2 · Coleta técnica.** Reunir indicadores e snapshots com timestamps, integridade, provedor, condições e limite de preservação.

**A3 · Extração de entidades.** Distinguir texto “a empresa X” do fato “o operador é X”; rotular entidades como alegadas até verificação.

**A4 · Resolução de identidade.** Normalizar nomes e identificadores. Para fusão de dois registros, exigir critérios independentes e permitir ambiguidade. Preferir entidades separadas quando existe dúvida.

**A5 · Correlação de campanhas.** Comparar recursos, marcas, layout, certificados, redirects, tempo e infraestrutura. Evitar concluir controle comum apenas por compartilhamento de provedor.

**A6 · Hipóteses concorrentes.** Registrar: operador único, plataforma de hospedagem comum, integrador/agência compartilhado, template comercial comum, identidade usurpada, evidência plantada ou coincidência temporal. Avaliar suporte e contraevidências.

**A7 · Revisão humana.** Promover para atribuição verificável somente após revisão por analista treinado e, se envolver pessoa identificável ou denúncia, aprovação adicional conforme política.

**A8 · Dossiê e divulgação.** Exportar evidências com classificações, lacunas e redaction apropriada. Não publicar nomes de pessoas em painel aberto.

## 5. Hierarquia de força probatória (orientativa)

**Indicadores geralmente fracos, isoladamente:** IP compartilhado; ASN; nameserver comum; registrar; certificado Let's Encrypt; tema de loja; palavra-chave; domínio recente; TLD; geolocalização IP.

**Indicadores intermediários que precisam de verificação contextual:** mesma estrutura DOM muito específica; asset hash coincidente; mesmo identificador de analytics (pode ser agência); telefone de atendimento público repetido; mesmos redirects incomuns; temporalidade e domínio em clusters conhecidos.

**Conjuntos mais fortes, sujeitos a falsificação/comprometimento:** combinação independente de indicadores operacionais únicos em múltiplos sites, evidências temporalmente consistentes de controle de canal oficial e vínculos empresariais corroborados por registros legítimos. Ainda assim, **controle operacional ≠ responsabilidade penal**.

## 6. Classes de alegação

- `OBSERVED`: um registro ou comportamento foi observado na fonte.
- `DECLARED`: o site ou fonte declara uma identidade/relacionamento.
- `INFERRED`: algoritmo ou analista deduz uma conexão, com hipóteses alternativas.
- `VERIFIED`: controle/afiliação corroborados por critérios documentados.
- `DISPUTED`: contestado por terceiro e em reavaliação.
- `REJECTED`: hipótese invalidada ou insuficiente.
- `UNKNOWN`: atribuição não estabelecida.

Exemplo de afirmação permitida: “Os domínios A e B exibiram o mesmo identificador público de analytics no período observado; isso **pode** refletir gestão comum ou um prestador compartilhado.”

Afirmação proibida sem prova independente: “A pessoa associada ao domínio A criou os dois golpes.”

## 7. Matriz de confiança e divulgação

| Classe | Uso interno | Relatório cliente | Divulgação pública |
|---|---|---|---|
| Observação técnica com fonte | sim | sim, sanitizada | conforme política |
| Correlação fraca | sim | sim, rotulada | evitar referência nominativa |
| Hipótese de operador | restrita | apenas com revisão/contexto | não automaticamente |
| Identidade de pessoa física | acesso excepcional | justificativa e aprovação | não por padrão |
| Atribuição verificada | sim | aprovação humana + base legal | somente avaliação específica e jurídico |
| Hipótese contestada | sim | com ressalva ou suspensa | suspensa por padrão |

## 8. Dossiê investigativo

Deverá conter:
1. Identificação do caso e finalidade.
2. Síntese executiva em linguagem não acusatória.
3. Itens analisados, janelas e escopo.
4. Inventário de nós e relações, por categoria.
5. Timeline de observações e redirecionamentos.
6. Fontes, consultas, integridade e condições de coleta.
7. Relações fortes, médias e fracas — cada uma com contraexplicações.
8. Hipóteses, alternativas e avaliação de confiança.
9. Pessoas/empresas citadas somente quando estritamente necessário e permitido.
10. Revisões, responsáveis internos, data e versão.
11. Lacunas conhecidas, informações ausentes e recomendações de encaminhamento.
12. Registro de redaction e público autorizado do documento.

## 9. Workflow de revisão e auditoria

Estados: `draft` → `under_investigation` → `pending_review` → `approved_for_internal_use` / `rejected` / `disputed` → `closed`.

Critérios de revisão: no mínimo duas linhas de evidência independentes para alegações de controle comum (não necessariamente suficientes), validação de qualidade de fonte, análise de alternativas, adequação jurídica, exposição proporcional e ausência de dados desnecessários.

## 10. Antierros de atribuição

- **Shared hosting fallacy:** múltiplos domínios no IP não comprovam mesmo dono.
- **Registrar fallacy:** usar mesmo registrador é comum e benigno.
- **Contact injection:** adversário pode publicar nome de terceiro para incriminá-lo.
- **Stolen identity:** documentos e empresas legítimas podem ser usurpados.
- **Compromised site:** site oficial pode distribuir conteúdo malicioso sem intenção do proprietário.
- **Reseller / Agency:** vários sites podem usar mesma agência, tema ou tags.
- **Temporal drift:** infraestrutura e contas mudam de controle; observar janelas.
- **Base-rate neglect:** indicadores raros podem ser comuns em certo setor.
- **Provider guilt:** processador de pagamento e CDN não são cúmplices por operar serviço.

## 11. Requisitos de segurança, ética e privacidade

- Case access mínimo e auditado; controles reforçados para dados pessoais.
- Sem consulta massiva para identificar pessoas por curiosidade, vigilância ou assédio.
- Sem revelar endereços particulares, números de documentos, parentes e contatos pessoais.
- Sem automação de abordagens a possíveis envolvidos.
- Integração com autoridades apenas por processo legítimo; preservar documentos sem presunção de culpa.
- Equipe de revisão e correção independente de modelo de ML; explicar correções e impactos.

## 12. Requisitos e aceitação do módulo

| ID | Requisito | Critério testável |
|---|---|---|
| ATR-001 | Coleta de entidades públicas com fonte | 100% de nós extraídos ligados a observação |
| ATR-002 | Resolução conservadora | homônimos não mesclados sem base |
| ATR-003 | Grafo temporal e tipado | todas as arestas incluem período e evidência |
| ATR-004 | Distinção provedor/operador | CDN/host neutro não recebe imputação |
| ATR-005 | Hipóteses concorrentes | campo de alternativas obrigatório para inferências |
| ATR-006 | Revisão de pessoas identificáveis | bloqueio de exportação nominativa sem aprovação |
| ATR-007 | Cadeia de custódia | hashes, coleta e alterações auditáveis |
| ATR-008 | Contestação | disputa preserva histórico e suspende divulgação aplicável |
| ATR-009 | Gestão de lacunas | dossiê expõe entidades não identificadas |
| ATR-010 | Comunicação precisa | nenhum relatório promete “todos os envolvidos” |
