# Risk score, confiança, cobertura e explicabilidade

## 1. Variáveis independentes

- **Risk score (0–100):** intensidade agregada de evidências de risco; não é probabilidade calibrada por padrão.
- **Confidence:** confiabilidade da conclusão dado o número, frescor, independência e qualidade das evidências.
- **Coverage:** fração de classes de verificação previstas que foi efetivamente realizada, ajustada ao modo de análise.
- **Attribution confidence:** confiança específica de cada hipótese de vínculo/operador, independente do score de phishing.

## 2. Composição candidata de score

| Família | Peso inicial |
|---|---:|
| Reputação confirmada/licenciada | 25% |
| Domínio e lexical | 20% |
| Conteúdo/comportamento | 20% |
| Marca e similaridade visual | 15% |
| Infraestrutura/histórico | 10% |
| Contexto e correlação | 10% |

Pesos iniciais são hipóteses; treinar/calibrar com dataset representativo. Dedupe de fontes relacionadas e controle para dados ausentes.

## 3. Faixas iniciais

0–19 mínimo detectado; 20–39 baixo; 40–59 moderado; 60–79 alto; 80–100 crítico. Estado **inconclusivo** prevalece quando a cobertura/qualidade não sustenta classificação. Limiares serão calibrados em validação.

## 4. Evidências especiais

- Feed confirmado recente pode promover a crítico após verificação de correspondência e validade.
- Certificado HTTPS válido não “desconta” fraude.
- Idade do domínio isoladamente não pode implicar alto risco.
- Provedor compartilhado e IP não implicam autoria comum.
- Ausência de registro e timeout não são sinal de benignidade.
- Conflitos e sinais obsoletos aumentam incerteza.

## 5. Explicação

O motor gera contribuição por **família independente de evidência**, IDs de origem, tempo e peso efetivo. Explicação ao consumidor deve dizer o que foi visto e ação recomendada; ao analista deve incluir detalhes, limites e alternativas. Texto gerado por LLM deve ser construído de dados estruturados autorizados, com validação para não inventar fontes, vítimas ou envolvidos.

## 6. Atribuição separada do risco

Site pode ter risco crítico e autoria desconhecida. Dois sites podem compartilhar infraestrutura sem operador comum. Não fundir score de phishing com score de autoria. Hipóteses possuem `confidence`, `support`, `counter_evidence`, `alternatives`, `review_state` próprios.

## 7. Validação e monitoramento

Usar corte temporal, deduplicação de campanhas, validação out-of-domain e análise de falsos positivos. Medir calibration error se score for interpretado probabilisticamente; até lá não rotular como percentual de chance de golpe. Monitorar drift, reversões humanas e divergência por marca/região/tipo de site.
