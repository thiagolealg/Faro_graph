# WORKERS — Mapa de módulos

Diretórios reservados para implementação futura. **Nenhum código está presente.**

| Módulo | Responsabilidade |
|---|---|
| [passive-osint](passive-osint/) | Coleta OSINT passiva. DNS, RDAP, CT, reputação, metadados autorizados. |
| [dynamic-browser](dynamic-browser/) | Navegação dinâmica isolada. Redirects, DOM, screenshots e logs sanitizados em sandbox. |
| [visual-analysis](visual-analysis/) | Similaridade de marca e páginas. Embeddings, fingerprints, marca, layout e DOM. |
| [entity-extraction](entity-extraction/) | Extração de entidades observáveis. Domínios, serviços, contatos comerciais públicos e alegações. |
| [correlation](correlation/) | Correlação temporal e de campanha. Vínculos, hubs, filtros anticorrelação espúria, clusters. |
| [ml-inference](ml-inference/) | Inferência versionada. Modelos aprovados, explicabilidade e métricas de drift. |
| [continuous-monitoring](continuous-monitoring/) | Monitoramento recorrente. Atualizações de marca, DNS/CT e triagem de novidades. |
| [report-builder](report-builder/) | Montagem de relatórios. Dossiês, relatórios por público, manifest de evidências. |
