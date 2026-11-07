# INFRA — Mapa de módulos

Diretórios reservados para implementação futura. **Nenhum código está presente.**

| Módulo | Responsabilidade |
|---|---|
| [environments](environments/) | Ambientes de deployment. Separação de desenvolvimento, homologação e produção. |
| [network](network/) | Topologia de rede. Egress, DNS seguro, segmentação e firewall de sandbox. |
| [sandbox](sandbox/) | Isolamento de navegador. MicroVM/container hardened, limites e destruição efêmera. |
| [observability](observability/) | Padrões de telemetria. Logs, métricas, tracing, alertas de abuso. |
| [storage](storage/) | Bancos e object storage. Isolamento, backups, retenção e criptografia. |
| [queues](queues/) | Filas e jobs. QoS, deduplicação, retries e dead-letter. |
| [deployments](deployments/) | Entrega e releases. Gates de segurança, canary, rollback e change control. |
