"""Grafo explicavel de indicadores. Nao faz atribuicao de pessoas ou culpabilidade."""
from .schemas import GraphNode, GraphEdge, GraphResult, DNSObservation, RDAPObservation, ThreatIntelObservation


def build_graph(analysis_id: str, normalized_url: str, hostname: str, registrable_domain: str, evidence: list[dict], extra: dict, passive_dns: DNSObservation | None = None, rdap: RDAPObservation | None = None, threat_intel: ThreatIntelObservation | None = None) -> GraphResult:
    nodes = [
        GraphNode(id="url:"+normalized_url, kind="url", label=normalized_url, status="observed"),
        GraphNode(id="domain:"+hostname, kind="hostname", label=hostname, status="observed"),
    ]
    edges = [GraphEdge(source=nodes[0].id, target=nodes[1].id, relationship="has_hostname", certainty="observed")]
    if registrable_domain != hostname:
        nodes.append(GraphNode(id="domain:"+registrable_domain, kind="registrable_domain", label=registrable_domain, status="observed"))
        edges.append(GraphEdge(source="domain:"+hostname, target="domain:"+registrable_domain, relationship="within_domain", certainty="observed"))
    brand_ev = next((e["id"] for e in evidence if e["code"] == "possible_brand_impersonation"), None)
    for brand in extra.get("brand_candidates", []):
        nodes.append(GraphNode(id="brand:"+brand, kind="brand_reference", label=brand, status="reference"))
        edges.append(GraphEdge(source="domain:"+hostname, target="brand:"+brand, relationship="resembles_brand", certainty="hypothesis", evidence_id=brand_ev))
    form_ev = next((e["id"] for e in evidence if e["code"] == "cross_domain_sensitive_form"), None)
    for ext in extra.get("form_action_hosts", []):
        if ext != hostname:
            nodes.append(GraphNode(id="domain:"+ext, kind="form_target_hostname", label=ext, status="observed"))
            edges.append(GraphEdge(source="domain:"+hostname, target="domain:"+ext, relationship="form_target_in_submitted_html", certainty="observed", evidence_id=form_ev))
    if passive_dns is not None:
        for record in passive_dns.records:
            if record.type in {"A", "AAAA"}:
                node_id = "ip:" + record.value
                kind = "ip_address"
                relationship = "resolved_to_at_scan"
            else:
                node_id = "dns:" + record.value
                kind = "dns_provider_hostname"
                relationship = "advertised_" + record.type.lower() + "_at_scan"
            if not any(node.id == node_id for node in nodes):
                nodes.append(GraphNode(id=node_id, kind=kind, label=record.value, status="observed"))
            edges.append(GraphEdge(source="domain:" + hostname, target=node_id, relationship=relationship, certainty="observed", evidence_id="ev-dns-001"))
    if rdap is not None and rdap.status == "observed":
        domain_source = "domain:" + (registrable_domain if registrable_domain != hostname else hostname)
        for nameserver in rdap.nameservers:
            node_id = "dns:" + nameserver
            if not any(node.id == node_id for node in nodes):
                nodes.append(GraphNode(id=node_id, kind="dns_provider_hostname", label=nameserver, status="observed"))
            if not any(edge.source == domain_source and edge.target == node_id and edge.relationship == "rdap_nameserver_at_scan" for edge in edges):
                edges.append(GraphEdge(source=domain_source, target=node_id, relationship="rdap_nameserver_at_scan",
                    certainty="observed", evidence_id="ev-rdap-001"))
    if threat_intel is not None:
        for index, match in enumerate(threat_intel.matches):
            source_id = "feed:" + match.source
            if not any(node.id == source_id for node in nodes):
                nodes.append(GraphNode(id=source_id, kind="threat_intel_source", label=match.source, status="reference"))
            target_node = "url:" + normalized_url if match.indicator_type == "url" else "domain:" + hostname
            edges.append(GraphEdge(source=target_node, target=source_id,
                relationship="reported_in_reputation_snapshot", certainty="observed", evidence_id=f"ev-ti-{index+1:03d}"))
    return GraphResult(analysis_id=analysis_id, nodes=nodes, edges=edges, notice="Relacionamentos tecnicos nao provam identidade, participacao ou autoria criminosa. Dados RDAP e CT representam registros publicos e historicos, nao controle atual ou identidade verificada.")
