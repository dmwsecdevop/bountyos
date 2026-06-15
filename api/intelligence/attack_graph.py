"""Attack-surface knowledge graph for BountyOS.

Builds a durable graph from target metadata, scan events, findings and hunter
hypotheses.  The graph is evidence-oriented: it records what was observed and
how objects relate, but it never executes network actions itself.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import networkx as nx
from sqlmodel import Session, select, delete

from api.models import (
    AttackEdge, AttackNode, BugHypothesis, Finding, Scan, ScanEvent, Target,
)

URL_RE = re.compile(r"https?://[^\s\]\[\)\(\"'<>]+", re.I)
HOST_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])", re.I)
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
PATH_RE = re.compile(r"(?<![\w])/(?:api/|v\d+/|graphql|admin|auth|login|reset|users?|accounts?|orders?|payments?|uploads?)[^\s\"'<>]*", re.I)
TECH_HINTS = {
    "wordpress": ["wordpress", "wp-content", "wp-json"],
    "graphql": ["graphql", "__schema"],
    "nextjs": ["next.js", "_next/", "nextjs"],
    "react": ["react"],
    "django": ["django", "csrftoken"],
    "laravel": ["laravel", "laravel_session"],
    "rails": ["ruby on rails", "rails"],
    "spring": ["spring boot", "spring"],
    "nodejs": ["node.js", "express"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "cloudflare": ["cloudflare", "cf-ray"],
    "aws": ["amazonaws.com", "aws", "s3"],
}


def _json(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return default


class AttackGraphService:
    def _upsert_node(
        self,
        session: Session,
        scan_id: str,
        node_type: str,
        key: str,
        label: str,
        attributes: Optional[dict] = None,
        risk_score: float = 0.0,
        confidence: float = 0.5,
    ) -> AttackNode:
        node = session.exec(
            select(AttackNode)
            .where(AttackNode.scan_id == scan_id)
            .where(AttackNode.node_type == node_type)
            .where(AttackNode.key == key)
        ).first()
        if node:
            existing = _json(node.attributes_json, {})
            existing.update(attributes or {})
            node.label = label or node.label
            node.attributes_json = json.dumps(existing, default=str)
            node.risk_score = max(float(node.risk_score or 0), float(risk_score or 0))
            node.confidence = max(float(node.confidence or 0), float(confidence or 0))
            node.updated_at = datetime.utcnow()
            session.add(node)
            return node
        node = AttackNode(
            scan_id=scan_id,
            node_type=node_type,
            key=key[:500],
            label=(label or key)[:500],
            attributes_json=json.dumps(attributes or {}, default=str),
            risk_score=float(risk_score or 0),
            confidence=float(confidence or 0.5),
        )
        session.add(node)
        session.flush()
        return node

    def _edge(
        self,
        session: Session,
        scan_id: str,
        source: AttackNode,
        target: AttackNode,
        relation: str,
        confidence: float = 0.5,
        evidence: Optional[List[str]] = None,
    ) -> AttackEdge:
        edge = session.exec(
            select(AttackEdge)
            .where(AttackEdge.scan_id == scan_id)
            .where(AttackEdge.source_node_id == source.id)
            .where(AttackEdge.target_node_id == target.id)
            .where(AttackEdge.relation == relation)
        ).first()
        if edge:
            prior = _json(edge.evidence_json, [])
            for item in evidence or []:
                if item not in prior:
                    prior.append(item)
            edge.evidence_json = json.dumps(prior[-20:])
            edge.confidence = max(float(edge.confidence or 0), float(confidence or 0))
            session.add(edge)
            return edge
        edge = AttackEdge(
            scan_id=scan_id,
            source_node_id=source.id,
            target_node_id=target.id,
            relation=relation,
            confidence=float(confidence or 0.5),
            evidence_json=json.dumps((evidence or [])[-20:]),
        )
        session.add(edge)
        return edge

    def _extract(self, text: str) -> Dict[str, List[str]]:
        text = text or ""
        urls = sorted(set(u.rstrip(".,;:") for u in URL_RE.findall(text)))
        hosts = set(HOST_RE.findall(text))
        for url in urls:
            try:
                if urlparse(url).hostname:
                    hosts.add(urlparse(url).hostname or "")
            except Exception:
                pass
        paths = sorted(set(p.rstrip(".,;:") for p in PATH_RE.findall(text)))
        ips = sorted(set(IP_RE.findall(text)))
        techs: List[str] = []
        low = text.lower()
        for tech, hints in TECH_HINTS.items():
            if any(h in low for h in hints):
                techs.append(tech)
        return {
            "urls": urls[:250], "hosts": sorted(h for h in hosts if h)[:250],
            "paths": paths[:250], "ips": ips[:100], "technologies": techs,
        }

    def build(self, session: Session, scan_id: str, reset: bool = False) -> Dict[str, Any]:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise ValueError("Scan not found")
        target = session.get(Target, scan.target_id)
        if not target:
            raise ValueError("Target not found")

        if reset:
            session.exec(delete(AttackEdge).where(AttackEdge.scan_id == scan_id))
            session.exec(delete(AttackNode).where(AttackNode.scan_id == scan_id))
            session.commit()

        root = self._upsert_node(
            session, scan_id, "target", target.domain, target.name or target.domain,
            {"domain": target.domain, "scope": target.scope, "out_of_scope": target.out_of_scope},
            risk_score=15, confidence=1.0,
        )

        findings = session.exec(select(Finding).where(Finding.scan_id == scan_id)).all()
        events = session.exec(select(ScanEvent).where(ScanEvent.scan_id == scan_id)).all()
        hypotheses = session.exec(select(BugHypothesis).where(BugHypothesis.scan_id == scan_id)).all()

        # Target and configured scope nodes.
        for raw_scope in (target.scope or "").split(","):
            scope = raw_scope.strip().replace("https://", "").replace("http://", "").strip("/")
            if not scope:
                continue
            asset = self._upsert_node(session, scan_id, "asset", scope, scope, {"source": "scope"}, 10, 0.95)
            self._edge(session, scan_id, root, asset, "contains", 0.95, ["program scope"])

        all_text_parts: List[str] = []
        for ev in events:
            all_text_parts.extend([ev.message or "", ev.raw or ""])
        for f in findings:
            all_text_parts.extend([f.title or "", f.description or "", f.evidence or "", f.url or ""])
        extracted = self._extract("\n".join(all_text_parts))

        node_by_key: Dict[Tuple[str, str], AttackNode] = {}
        for host in extracted["hosts"]:
            n = self._upsert_node(session, scan_id, "asset", host, host, {"source": "scan"}, 12, 0.7)
            node_by_key[("asset", host)] = n
            self._edge(session, scan_id, root, n, "contains", 0.75, ["scan evidence"])
        for ip in extracted["ips"]:
            n = self._upsert_node(session, scan_id, "asset", ip, ip, {"kind": "ip"}, 14, 0.75)
            node_by_key[("asset", ip)] = n
            self._edge(session, scan_id, root, n, "resolves_to", 0.55, ["scan output"])
        for url in extracted["urls"]:
            parsed = urlparse(url)
            n = self._upsert_node(session, scan_id, "endpoint", url, parsed.path or url, {"url": url}, 18, 0.75)
            node_by_key[("endpoint", url)] = n
            host = parsed.hostname
            parent = node_by_key.get(("asset", host)) if host else None
            self._edge(session, scan_id, parent or root, n, "exposes", 0.78, [url])
        for path in extracted["paths"]:
            n = self._upsert_node(session, scan_id, "endpoint", path, path, {"path": path}, 18, 0.65)
            node_by_key[("endpoint", path)] = n
            self._edge(session, scan_id, root, n, "exposes", 0.62, [path])
        for tech in extracted["technologies"]:
            n = self._upsert_node(session, scan_id, "technology", tech, tech, {"source": "fingerprint"}, 8, 0.7)
            node_by_key[("technology", tech)] = n
            self._edge(session, scan_id, root, n, "uses", 0.7, [tech])

        severity_risk = {"critical": 100, "high": 82, "medium": 58, "low": 32, "info": 10}
        for f in findings:
            sev = getattr(f.severity, "value", str(f.severity))
            fn = self._upsert_node(
                session, scan_id, "finding", f.id, f.title,
                {"finding_id": f.id, "severity": sev, "url": f.url, "tool": f.tool, "cwe": f.cwe_id},
                severity_risk.get(sev, 40), 0.9 if not f.false_positive else 0.2,
            )
            parent = root
            if f.url:
                parent = self._upsert_node(session, scan_id, "endpoint", f.url, f.url, {"url": f.url}, 20, 0.8)
                self._edge(session, scan_id, root, parent, "exposes", 0.75, [f.url])
            self._edge(session, scan_id, parent, fn, "indicates", 0.9, [f.title])

        for h in hypotheses:
            hn = self._upsert_node(
                session, scan_id, "hypothesis", h.id, h.title,
                {"hypothesis_id": h.id, "bug_class": h.bug_class, "status": h.status, "target": h.target},
                h.priority_score, h.confidence,
            )
            self._edge(session, scan_id, root, hn, "supports", h.confidence, _json(h.evidence_json, []))

        session.commit()
        return self.snapshot(session, scan_id)

    def snapshot(self, session: Session, scan_id: str) -> Dict[str, Any]:
        nodes = session.exec(select(AttackNode).where(AttackNode.scan_id == scan_id)).all()
        edges = session.exec(select(AttackEdge).where(AttackEdge.scan_id == scan_id)).all()
        type_counts: Dict[str, int] = {}
        for node in nodes:
            type_counts[node.node_type] = type_counts.get(node.node_type, 0) + 1
        return {
            "scan_id": scan_id,
            "nodes": [
                {
                    **n.model_dump(mode="json"),
                    "attributes": _json(n.attributes_json, {}),
                } for n in nodes
            ],
            "edges": [
                {
                    **e.model_dump(mode="json"),
                    "evidence": _json(e.evidence_json, []),
                } for e in edges
            ],
            "summary": {"node_count": len(nodes), "edge_count": len(edges), "types": type_counts},
        }

    def priority_paths(self, session: Session, scan_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        snap = self.snapshot(session, scan_id)
        graph = nx.DiGraph()
        by_id = {n["id"]: n for n in snap["nodes"]}
        for n in snap["nodes"]:
            graph.add_node(n["id"], **n)
        for e in snap["edges"]:
            graph.add_edge(e["source_node_id"], e["target_node_id"], relation=e["relation"], confidence=e["confidence"])
        roots = [n["id"] for n in snap["nodes"] if n["node_type"] == "target"]
        candidates = sorted(
            [n for n in snap["nodes"] if n["node_type"] in {"finding", "hypothesis", "endpoint"}],
            key=lambda n: (n.get("risk_score", 0) * n.get("confidence", 0)), reverse=True,
        )[:limit]
        out: List[Dict[str, Any]] = []
        for candidate in candidates:
            path: List[str] = []
            for root in roots:
                try:
                    path = nx.shortest_path(graph, root, candidate["id"])
                    break
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
            out.append({
                "score": round(candidate.get("risk_score", 0) * candidate.get("confidence", 0), 2),
                "target": candidate,
                "path": [by_id[p] for p in path if p in by_id],
            })
        return out


attack_graph = AttackGraphService()
