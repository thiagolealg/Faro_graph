# ADR-001 — Monólito modular com workers isolados

**Status:** Proposto · **Contexto:** arquitetura inicial SaaS e serviço hostil de navegação.

## Decisão

Monólito modular para API, domínio transacional e operações de negócio; workers separados e isolados para OSINT, navegador dinâmico, correlação e inferência. Não criar microsserviço por domínio sem métricas de necessidade.

## Motivo

Menor custo de implantação/teste e segurança de fronteira clara para conteúdo malicioso. Favorece evolução para serviços dedicados quando houver volume.

## Consequências

Implantação API acoplada parcialmente; exige organização disciplinada por módulos. Browsers não compartilham rede/segredos com API. Revisitar quando custo/escala ou requisitos regulatórios justificarem.
