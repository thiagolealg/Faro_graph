"""Investigation case aggregation and integrity-checked dossiers.

All derived relationships remain technical observations. Identical infrastructure
across scans is context, NOT evidence of shared ownership or criminal authorship.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone


# Only actual technical indicators are correlated. References such as threat feed
# names and generic brands must NOT become evidence of a common operator.
CORRELATABLE_KINDS = {
    "url", "hostname", "registrable_domain", "form_target_hostname",
    "ip_address", "dns_provider_hostname",
}
WEAK_KINDS = {"ip_address", "dns_provider_hostname"}


def canonical_bytes(value: dict) -> bytes:
    """Versioned canonicalization for local integrity checking (not a signature)."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def aggregate_case_graph(case_id: str, records: list[tuple[dict, dict]]) -> dict:
    """Merge per-analysis graphs without implying unproven relationships."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    memberships: dict[str, set[str]] = defaultdict(set)
    for result, graph in records:
        analysis_id = result["analysis_id"]
        for node in graph["nodes"]:
            node_id = node["id"]
            nodes[node_id] = node
            if node["kind"] in CORRELATABLE_KINDS:
                memberships[node_id].add(analysis_id)
        for edge in graph["edges"]:
            edges.append({**edge, "analysis_id": analysis_id})
    correlated = [
        {
            "node_id": node_id,
            "kind": nodes[node_id]["kind"],
            "analysis_ids": sorted(ids),
            "interpretation": (
                "weak_shared_infrastructure_only"
                if nodes[node_id]["kind"] in WEAK_KINDS else "same_observed_indicator_only"
            ),
        }
        for node_id, ids in sorted(memberships.items()) if len(ids) > 1
    ]
    return {
        "case_id": case_id,
        "nodes": [nodes[k] for k in sorted(nodes)],
        "edges": sorted(edges, key=lambda e: (e["analysis_id"], e["source"], e["target"], e["relationship"])),
        "shared_indicators": correlated,
        "notice": "Coincidencias tecnicas nao comprovam mesma campanha, controle, identidade ou autoria. IP, CDN e DNS compartilhados sao sinais especialmente fracos.",
    }


def build_dossier(case: dict, records: list[tuple[dict, dict]]) -> dict:
    """Create a deterministic, redacted JSON dossier with local integrity digest.

    The storage layer has already sanitized all URLs before saving them.
    Hashing is not cryptographic signing and does not establish chain of custody.
    """
    graph = aggregate_case_graph(case["id"], records)
    analyses = []
    for result, _ in records:
        analyses.append({
            "analysis_id": result["analysis_id"],
            "created_at": result["created_at"],
            "normalized_url": result["normalized_url"],
            "hostname": result["hostname"],
            "assessment": result["assessment"],
            "evidence": result["evidence"],
            "source_observations": {
                "passive_dns": result.get("passive_dns"),
                "rdap": result.get("rdap"),
                "certificate_transparency": result.get("certificate_transparency"),
                "threat_intel": result.get("threat_intel"),
            },
            "limitations": result["limitations"],
        })
    body = {
        "format": "faro-investigative-dossier-v1",
        "case": case,
        "analyses": analyses,
        "graph": graph,
        "limitations": [
            "Dossie local de evidencias com hash, nao documento assinado digitalmente ou prova de custodia forense.",
            "Revisoes representam opinioes humanas registradas, nao verificacoes independentes ou condenacoes.",
            "Vinculos tecnicos e dados publicos nao permitem identificar automaticamente envolvidos ou autores.",
            "A cobertura permanece limitada as analises efetivamente executadas e as fontes disponiveis.",
        ],
    }
    digest = hashlib.sha256(canonical_bytes(body)).hexdigest()
    return {
        "dossier": body,
        "integrity": {
            "algorithm": "sha256",
            "digest": digest,
            "canonicalization": "json-sorted-keys-utf8-v1",
            "digitally_signed": False,
            "warning": "Hash detecta alteracoes neste documento, mas nao atesta autor, autenticidade nem custodia.",
        },
    }
