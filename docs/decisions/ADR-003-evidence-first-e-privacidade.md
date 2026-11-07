# ADR-003 — Evidence-first, passive-first e privacidade

**Status:** Proposto.

## Decisão

Priorizar evidências passivas, permitir análise dinâmica só com sandbox/egress seguro, manter origem e data de evidência e aplicar minimização de dados desde a entrada.

## Motivo

Reduz exposição a conteúdo hostil, vazamentos de URLs privadas, conclusões opacas e uso impróprio de fornecedores externos.

## Consequências

Algumas análises retornarão inconclusivo; isso é preferível a uma falsa certificação de segurança.
