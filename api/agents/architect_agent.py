"""
BountyOS Architect Agent.

Implements ORTA:
Observe -> Reason -> Think -> Act

Narrow upgrade: command routing into existing BountyOS actions. This does not add
new scope hardening or replace the existing scanner safety layer.
"""

from __future__ import annotations

import os
import json
import logging
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlmodel import Session, select

from api.models import Target, Scan, ScanMode, ScanStatus, ScanPhase, Finding, ScanEvent, Approval, ApprovalStatus, BountyProgram, BountyAccount
from api.realtime import publish_sync, set_agent_state
from api.agents.model_router import router as model_router
from api.agents.live_data_agent import live_data_agent
from api.integrations.gemini_client import GeminiClient

logger = logging.getLogger(__name__)


@dataclass
class ArchitectDecision:
    action: str
    needs_approval: bool = False
    confidence: float = 0.75
    target_id: Optional[str] = None
    scan_id: Optional[str] = None
    notes: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ArchitectAgent:
    @staticmethod
    def _sanitize_error(exc: Exception) -> str:
        """Sanitize exception message to prevent information disclosure.
        
        Removes or masks sensitive patterns like credentials, paths, and API keys.
        Only exposes safe, user-facing error messages.
        """
        error_msg = str(exc)
        
        # Strip sensitive patterns
        patterns = [
            r'password\s*[=:]\s*[^\s,;]+',
            r'token\s*[=:]\s*[^\s,;]+',
            r'key\s*[=:]\s*[^\s,;]+',
            r'api[_-]?key\s*[=:]\s*[^\s,;]+',
            r'secret\s*[=:]\s*[^\s,;]+',
            r'authorization\s*[=:]\s*[^\s,;]+',
            r'bearer\s+[^\s]+',
            r'/[a-zA-Z0-9_/.]+',  # File paths
        ]
        
        for pattern in patterns:
            error_msg = re.sub(pattern, '***', error_msg, flags=re.IGNORECASE)
        
        # Only expose message if it's reasonably short and doesn't look like internal noise
        if len(error_msg) > 200 or any(keyword in error_msg.lower() for keyword in ['traceback', 'line ', 'module ', 'import']):
            return "Internal processing error."
        
        return error_msg if error_msg.strip() else "Internal processing error."

    def observe(self, session: Session, transcript: str, selected_target_id: Optional[str], selected_scan_id: Optional[str]) -> Dict[str, Any]:
        target = session.get(Target, selected_target_id) if selected_target_id else None
        scan = session.get(Scan, selected_scan_id) if selected_scan_id else None

        if not target and scan:
            target = session.get(Target, scan.target_id)
        if not target:
            target = session.exec(select(Target).order_by(Target.created_at.desc())).first()
        if not scan:
            scan = session.exec(select(Scan).order_by(Scan.created_at.desc())).first()

        finding_count = 0
        pending_approvals = 0
        if scan:
            finding_count = len(session.exec(select(Finding).where(Finding.scan_id == scan.id)).all())
            pending_approvals = len(session.exec(
                select(Approval).where(Approval.scan_id == scan.id).where(Approval.status == ApprovalStatus.PENDING)
            ).all())

        obs = {
            "transcript": transcript,
            "target": {"id": target.id, "domain": target.domain, "name": target.name} if target else None,
            "scan": {"id": scan.id, "status": str(scan.status), "phase": str(scan.phase), "mode": str(scan.mode)} if scan else None,
            "finding_count": finding_count,
            "pending_approvals": pending_approvals,
            "timestamp": datetime.utcnow().isoformat(),
        }
        publish_sync("agent.observe", obs)
        return obs

    def reason(self, transcript: str, obs: Dict[str, Any]) -> ArchitectDecision:
        t = transcript.lower().strip()
        target_id = obs.get("target", {}).get("id") if obs.get("target") else None
        scan_id = obs.get("scan", {}).get("id") if obs.get("scan") else None

        if any(k in t for k in ["self evaluate", "evaluate agents", "evaluate agent work", "run quality loop", "quality check", "critic review", "verify work"]):
            return ArchitectDecision("evaluate_agent_work", False, 0.92, target_id, scan_id, "Agent Quality Loop requested.")
        if any(k in t for k in ["show quality", "quality scores", "agent performance", "model performance", "evaluation results"]):
            return ArchitectDecision("show_agent_quality", False, 0.88, target_id, scan_id, "Agent quality results requested.")
        if any(k in t for k in ["retry weak work", "retry failed work", "fix weak result", "retry low score"]):
            return ArchitectDecision("retry_weak_work", False, 0.86, target_id, scan_id, "Controlled retry requested for weakest agent output.")
        if any(k in t for k in ["full hunter", "run hunter workflow", "build attack graph", "generate hypotheses", "adaptive plan", "full hacker mindset", "hunt this scan"]):
            return ArchitectDecision("run_hunter_workflow", False, 0.93, target_id, scan_id, "Full Hunter lifecycle requested.")
        if any(k in t for k in ["generate report", "create report", "bounty report", "report agent"]):
            return ArchitectDecision("generate_hunter_report", False, 0.9, target_id, scan_id, "Bounty-ready report requested.")
        if any(k in t for k in ["show hypotheses", "bug hypotheses", "next attack ideas", "hunter hypotheses"]):
            return ArchitectDecision("show_hypotheses", False, 0.88, target_id, scan_id, "Hunter hypotheses requested.")
        if any(k in t for k in ["show attack graph", "attack surface graph", "knowledge graph"]):
            return ArchitectDecision("show_attack_graph", False, 0.88, target_id, scan_id, "Attack graph requested.")
        if any(k in t for k in ["analyze browser", "use browser", "browser mcp", "current page", "check browser"]):
            return ArchitectDecision("analyze_browser", False, 0.9, target_id, scan_id, "Browser MCP analysis job requested.")
        if any(k in t for k in ["check caido traffic", "use caido", "caido traffic", "analyze caido", "proxy traffic"]):
            return ArchitectDecision("check_caido_traffic", False, 0.9, target_id, scan_id, "Caido traffic import/analysis job requested.")
        if live_data_agent.detect(t):
            return ArchitectDecision("live_data_lookup", False, 0.91, target_id, scan_id, "Current/live-data question detected.")
        if any(k in t for k in ["sync bounty accounts", "sync accounts", "check my programs", "check my bugcrowd", "check my hackerone", "check my intigriti", "check my yeswehack", "private invitations"]):
            return ArchitectDecision("sync_bounty_accounts", False, 0.88, target_id, scan_id, "Connected Bounty Account Hub sync requested.")
        if any(k in t for k in ["show bounty accounts", "list bounty accounts", "connected accounts", "show accounts"]):
            return ArchitectDecision("show_bounty_accounts", False, 0.84, target_id, scan_id, "User asked to view connected bounty accounts.")
        if any(k in t for k in ["easy program", "easy scope", "easy bounty", "less effort", "more money", "make money", "profitable program", "opportunity score", "best program", "select easy"]):
            return ArchitectDecision("recommend_programs", False, 0.88, target_id, scan_id, "Program opportunity scoring requested.")
        if any(k in t for k in ["check bug bounty programs", "check programs", "program radar", "bounty radar", "find bounty programs", "online bug bounty", "new programs"]):
            return ArchitectDecision("check_programs", False, 0.86, target_id, scan_id, "Bounty Program Radar check requested.")
        if any(k in t for k in ["show programs", "list programs", "bounty programs", "programs list"]):
            return ArchitectDecision("show_programs", False, 0.84, target_id, scan_id, "User asked to view stored bounty programs.")
        if any(k in t for k in ["import program", "add program targets", "program targets"]):
            return ArchitectDecision("add_program_targets", False, 0.78, target_id, scan_id, "User asked to import program scope as targets.")
        if any(k in t for k in ["cancel", "stop scan", "stop running"]):
            return ArchitectDecision("cancel_scan", False, 0.88, target_id, scan_id, "Cancel requested.")
        if any(k in t for k in ["passive", "recon", "osint"]):
            return ArchitectDecision("start_passive_scan", False, 0.9, target_id, scan_id, "Passive recon requested.")
        if any(k in t for k in ["aggressive", "nuclei", "sqlmap", "ffuf", "active scan", "vulnerability scan"]):
            return ArchitectDecision("start_aggressive_scan", True, 0.86, target_id, scan_id, "Active/aggressive tooling requested.")
        if any(k in t for k in ["summarize scan", "summary", "summarize this scan", "scan summary", "recon summary"]):
            return ArchitectDecision("summarize_scan", False, 0.86, target_id, scan_id, "Gemini scan summary requested.")
        if any(k in t for k in ["exploit reasoning", "exploit plan", "poc", "proof of concept", "validate exploit"]):
            return ArchitectDecision("exploit_reasoning", False, 0.84, target_id, scan_id, "Gemini exploit reasoning requested.")
        if any(k in t for k in ["analyze findings", "analyze finding", "finding analysis", "bug reasoning"]):
            return ArchitectDecision("analyze_findings", False, 0.84, target_id, scan_id, "Gemini findings analysis requested.")
        if any(k in t for k in ["analyze", "bug brain", "mindset", "find bugs", "think like hacker", "finding bugs"]):
            return ArchitectDecision("run_ai_analysis", False, 0.82, target_id, scan_id, "Post-scan bug reasoning requested.")
        if any(k in t for k in ["show findings", "findings", "bugs found", "vulnerabilities found"]):
            return ArchitectDecision("show_findings", False, 0.85, target_id, scan_id, "User asked to view findings.")
        if any(k in t for k in ["show scans", "list scans", "scan status", "status"]):
            return ArchitectDecision("show_scans", False, 0.78, target_id, scan_id, "User asked for scan status.")
        if any(k in t for k in ["targets", "show targets", "list targets"]):
            return ArchitectDecision("show_targets", False, 0.78, target_id, scan_id, "User asked for targets.")
        if any(k in t for k in ["parse target", "target page", "pasted scope", "extract scope"]):
            return ArchitectDecision("parse_target_page", False, 0.95, target_id, scan_id, "Bug bounty target page parsing requested.")

        return ArchitectDecision("general_chat", False, 0.62, target_id, scan_id, "No direct tool command detected; reply as assistant.")

    def think(self, transcript: str, decision: ArchitectDecision, obs: Dict[str, Any]) -> Dict[str, Any]:
        route = model_router.route(transcript, decision.action, has_scan_context=bool(obs.get("scan")), target_context=obs.get("target"))
        thought = {
            "model_route": route.as_dict(),
            "plan": [
                "Use current target/scan context.",
                "Choose workload expert using Mixture-of-Models router.",
                "Call existing BountyOS action only; no raw shell from chat.",
                "For live-data questions, call deterministic public API connectors instead of guessing.",
                "For account hub commands, sync connected API/OAuth bounty accounts where permissions allow.",
                "For program radar commands, fetch public/JSON program feeds and store scope metadata.",
                "For easy-money requests, rank stored programs using Program Opportunity Scorer; never promise a guaranteed bounty.",
                "Return action result and publish realtime event.",
            ],
        }
        publish_sync("agent.think", thought)
        return thought

    @staticmethod
    def _structured_ai_result(action: str, ai: Any, route: Any, *, requires_approval: bool = False, approval_reason: str = "") -> Dict[str, Any]:
        route_dict = route.as_dict() if hasattr(route, "as_dict") else dict(route or {})
        return {
            "action": action,
            "ok": True,
            "summary": ai.text,
            "provider": ai.provider,
            "response": ai.text,
            "next_actions": route_dict.get("next_actions", []),
            "requires_approval": bool(requires_approval or route_dict.get("requires_approval", False)),
            "approval_reason": approval_reason or route_dict.get("approval_reason", ""),
            "selected_tools": route_dict.get("selected_tools", []),
            "model_used": ai.model,
            "model_route": route_dict,
            "logs": [],
            "raw": {"provider": ai.provider, "route": ai.route, "target_profile": route_dict.get("target_profile")},
        }

    async def act(self, session: Session, background_tasks: Any, decision: ArchitectDecision, approve: bool = False, transcript: str = "", obs: Dict[str, Any] | None = None) -> Dict[str, Any]:
        action = decision.action
        result: Dict[str, Any] = {"action": action, "ok": True}

        if decision.needs_approval and not approve:
            route = model_router.route(transcript, action, has_scan_context=bool(decision.scan_id), target_context=(obs or {}).get("target") if obs else None)
            result.update({
                "ok": False,
                "summary": "Approval required before active validation can run.",
                "next_actions": route.next_actions,
                "requires_approval": True,
                "approval_reason": route.approval_reason or "This action is active/aggressive. Send again with approve=true to run.",
                "selected_tools": route.selected_tools,
                "model_used": route.model,
                "logs": [],
                "raw": {"decision": decision.as_dict(), "model_route": route.as_dict()},
                "message": "Approval required before active validation can run.",
                "decision": decision.as_dict(),
            })
            publish_sync("approval.required", result)
            return result

        if action == "evaluate_agent_work":
            if not decision.scan_id:
                raise ValueError("No scan selected or available for evaluation.")
            from api.quality import quality_engine
            evaluation = quality_engine.evaluate_scan(session, decision.scan_id)
            result.update({
                "message": f"Agent Quality Loop evaluated {evaluation['summary']['total']} outputs. Average score: {evaluation['summary']['average_score']}/100.",
                "scan_id": decision.scan_id,
                "quality": evaluation,
            })

        elif action == "show_agent_quality":
            from api.quality import quality_engine
            result.update({
                "message": "Agent quality and model performance loaded.",
                "scan_id": decision.scan_id,
                "quality": {
                    "summary": quality_engine.summary(session, decision.scan_id),
                    "evaluations": quality_engine.list(session, decision.scan_id)[:50],
                    "performance": quality_engine.performance(session),
                },
            })

        elif action == "retry_weak_work":
            if not decision.scan_id:
                raise ValueError("No scan selected or available for retry.")
            from api.models import AgentEvaluation
            from api.quality import retry_manager
            weak = session.exec(
                select(AgentEvaluation).where(
                    AgentEvaluation.scan_id == decision.scan_id,
                    AgentEvaluation.status.in_(["rejected", "retry"]),
                ).order_by(AgentEvaluation.overall_score.asc(), AgentEvaluation.created_at.desc())
            ).first()
            if not weak:
                result.update({"message": "No rejected or retry-required agent work was found.", "quality_ok": True})
            else:
                retried = retry_manager.retry(session, weak.id)
                result.update({"message": retried.get("message", "Retry processed."), "retry": retried})

        elif action == "run_hunter_workflow":
            if not decision.scan_id:
                raise ValueError("No scan selected or available for Hunter workflow.")
            from api.intelligence import attack_graph, hypothesis_engine, adaptive_planner, shared_memory
            graph = attack_graph.build(session, decision.scan_id)
            hypotheses = hypothesis_engine.generate(session, decision.scan_id)
            graph = attack_graph.build(session, decision.scan_id)
            plans = adaptive_planner.plan(session, decision.scan_id)
            from api.quality import quality_engine
            quality = quality_engine.evaluate_scan(session, decision.scan_id, task_types=["hypothesis", "plan"])
            result.update({
                "message": "Full Hunter workflow completed: graph, hypotheses, adaptive plan and self-evaluation are ready.",
                "scan_id": decision.scan_id,
                "graph_summary": graph["summary"],
                "hypotheses": hypotheses[:8],
                "plans": plans[:8],
                "quality": quality,
                "memory": shared_memory.summary(session, decision.scan_id),
            })

        elif action == "generate_hunter_report":
            if not decision.scan_id:
                raise ValueError("No scan selected or available for report generation.")
            from api.reporting import report_agent
            report = report_agent.generate(session, decision.scan_id)
            from api.models import BountyReport
            from api.quality import quality_engine
            report_row = session.get(BountyReport, report["id"])
            evaluation = quality_engine.evaluate_report(session, report_row)
            result.update({"message": f"Report generated with quality score {report['quality_score']}/100 and critic score {evaluation['overall_score']}/100.", "report": report, "quality_evaluation": evaluation})

        elif action == "show_hypotheses":
            if not decision.scan_id:
                raise ValueError("No scan selected or available.")
            from api.models import BugHypothesis
            from api.intelligence import hypothesis_engine
            rows = session.exec(select(BugHypothesis).where(BugHypothesis.scan_id == decision.scan_id).order_by(BugHypothesis.priority_score.desc())).all()
            result.update({"message": f"Found {len(rows)} Hunter hypotheses.", "hypotheses": [hypothesis_engine.serialize(h) for h in rows[:20]]})

        elif action == "show_attack_graph":
            if not decision.scan_id:
                raise ValueError("No scan selected or available.")
            from api.intelligence import attack_graph
            graph = attack_graph.snapshot(session, decision.scan_id)
            result.update({"message": f"Attack graph has {graph['summary']['node_count']} nodes and {graph['summary']['edge_count']} edges.", "graph": graph})

        elif action == "start_passive_scan":
            if not decision.target_id:
                raise ValueError("No target selected or available.")
            target = session.get(Target, decision.target_id)
            scan = Scan(target_id=target.id, mode=ScanMode.PASSIVE, config=json.dumps({"source":"architect_agent"}))
            session.add(scan); session.commit(); session.refresh(scan)
            from api.routes.scans import _run_passive_scan
            background_tasks.add_task(_run_passive_scan, scan.id, target.domain, {"source":"architect_agent"}, target)
            result.update({"message": "Passive scan started.", "scan_id": scan.id, "target": target.domain})

        elif action == "start_aggressive_scan":
            if not decision.target_id:
                raise ValueError("No target selected or available.")
            target = session.get(Target, decision.target_id)
            scan = Scan(target_id=target.id, mode=ScanMode.AGGRESSIVE, config=json.dumps({"source":"architect_agent", "approved_from_chat": True}))
            session.add(scan); session.commit(); session.refresh(scan)
            from api.routes.scans import _run_aggressive_scan
            background_tasks.add_task(_run_aggressive_scan, scan.id, target.domain, {"source":"architect_agent", "approved_from_chat": True}, target)
            result.update({"message": "Aggressive scan started after approval.", "scan_id": scan.id, "target": target.domain})

        elif action == "run_ai_analysis":
            if not decision.scan_id:
                raise ValueError("No scan selected or available for analysis.")
            scan = session.get(Scan, decision.scan_id)
            target = session.get(Target, scan.target_id)
            from api.agents.coordinator import run_ai_coordinator
            scan.phase = ScanPhase.EXPLOIT
            scan.status = ScanStatus.RUNNING
            session.add(scan); session.commit()
            background_tasks.add_task(run_ai_coordinator, scan_id=scan.id, target_domain=target.domain, scope=target.scope, out_of_scope=target.out_of_scope, max_iterations=20)
            result.update({"message": "AI bug reasoning started.", "scan_id": scan.id})

        elif action == "cancel_scan":
            if not decision.scan_id:
                raise ValueError("No scan selected or available to cancel.")
            from api.routes.scans import _cancelled_scans
            _cancelled_scans.add(decision.scan_id)
            result.update({"message": "Cancellation requested.", "scan_id": decision.scan_id})

        elif action == "sync_bounty_accounts":
            from api.agents.bounty_account_hub import account_hub
            sync_result = account_hub.sync_all_accounts(session, max_items=200)
            result.update({"message": "Connected bounty accounts sync complete.", **sync_result})

        elif action == "show_bounty_accounts":
            from api.agents.bounty_account_hub import account_hub
            accounts = session.exec(select(BountyAccount).order_by(BountyAccount.created_at.desc())).all()
            result.update({"message": f"Found {len(accounts)} connected bounty accounts.", "accounts": [account_hub.safe_account(a) for a in accounts[:25]]})

        elif action == "check_programs":
            from api.agents.program_radar import radar
            radar_result = radar.check_sources(session, max_programs=500)
            result.update({"message": "Bounty Program Radar check complete.", **radar_result})

        elif action == "show_programs":
            programs = session.exec(select(BountyProgram).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())).all()
            result.update({"message": f"Found {len(programs)} bounty programs.", "programs": [p.model_dump(mode="json") for p in programs[:40]]})

        elif action == "recommend_programs":
            from api.agents.opportunity_scorer import opportunity_scorer
            platform = None
            low = transcript.lower()
            for name in ["hackerone", "bugcrowd", "intigriti", "yeswehack"]:
                if name in low:
                    platform = name
                    break
            programs = session.exec(select(BountyProgram).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())).all()
            if not programs:
                from api.agents.program_radar import radar
                radar.check_sources(session, max_programs=500)
                programs = session.exec(select(BountyProgram).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())).all()
            recommendations = opportunity_scorer.rank(programs, platform=platform, bounty_only=True, limit=8)
            result.update({
                "message": "I ranked stored bounty programs by likely reward vs effort. No program is guaranteed money; this is probability scoring.",
                "platform": platform,
                "recommendations": recommendations,
            })

        elif action == "add_program_targets":
            from api.agents.program_radar import radar
            program = session.exec(select(BountyProgram).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())).first()
            if not program:
                raise ValueError("No program found yet. Run 'check programs' first.")
            imported = radar.add_program_targets(session, program.id, limit=25)
            result.update({"message": f"Imported targets from {program.name}.", **imported})

        elif action == "analyze_browser":
            if not decision.target_id:
                raise ValueError("No target selected or available for browser analysis.")
            target = session.get(Target, decision.target_id)
            from api.integrations.browser_mcp import BrowserMCPClient
            snapshot = await BrowserMCPClient().collect_snapshot(target.model_dump(mode="json"))
            data = snapshot.as_dict()
            if decision.scan_id:
                event = ScanEvent(scan_id=decision.scan_id, phase=ScanPhase.RECON, tool="browser-mcp", level="info", message="Browser MCP evidence imported", raw=json.dumps(data)[:8000])
                session.add(event); session.commit()
            route = model_router.route(transcript, action, has_scan_context=bool(decision.scan_id), target_context=target.model_dump(mode="json"))
            result.update({
                "summary": "Browser MCP evidence imported for in-scope analysis.",
                "next_actions": route.next_actions,
                "requires_approval": False,
                "approval_reason": "",
                "selected_tools": route.selected_tools,
                "model_used": route.model,
                "logs": [],
                "evidence": data,
                "raw": {"model_route": route.as_dict(), "browser": data},
            })

        elif action == "check_caido_traffic":
            if not decision.target_id:
                raise ValueError("No target selected or available for Caido analysis.")
            target = session.get(Target, decision.target_id)
            from api.integrations.caido_client import CaidoClient
            caido = CaidoClient()
            requests = await caido.import_history(limit=100)
            in_scope = []
            target_data = target.model_dump(mode="json")
            for request in requests:
                try:
                    caido.assert_request_in_scope(request, target_data)
                    in_scope.append(request)
                except Exception:
                    continue
            if decision.scan_id:
                event = ScanEvent(scan_id=decision.scan_id, phase=ScanPhase.RECON, tool="caido", level="info", message=f"Imported {len(in_scope)} in-scope Caido requests", raw=json.dumps({"request_count": len(in_scope)})[:8000])
                session.add(event); session.commit()
            route = model_router.route(transcript, action, has_scan_context=bool(decision.scan_id), target_context=target_data)
            result.update({
                "summary": f"Imported {len(in_scope)} in-scope Caido requests for analysis.",
                "next_actions": route.next_actions,
                "requires_approval": False,
                "approval_reason": "",
                "selected_tools": route.selected_tools,
                "model_used": route.model,
                "logs": [],
                "evidence": in_scope[:25],
                "raw": {"model_route": route.as_dict(), "request_count": len(in_scope)},
            })

        elif action == "live_data_lookup":
            live_result = live_data_agent.answer(transcript)
            result.update(live_result.as_dict())
            result["message"] = live_result.answer

        elif action == "general_chat":
            route = model_router.route(transcript, action, has_scan_context=bool(decision.scan_id), target_context=(obs or {}).get("target") if obs else None)
            gemini = GeminiClient()
            ai = await gemini.chat(transcript, context={"observation": obs or {}, "route": route.as_dict()}, model=route.model)
            result = self._structured_ai_result(action, ai, route)

        elif action == "summarize_scan":
            route = model_router.route(transcript, action, has_scan_context=bool(decision.scan_id), target_context=(obs or {}).get("target") if obs else None)
            gemini = GeminiClient()
            ai = await gemini.summarize_scan(transcript, context={"observation": obs or {}, "route": route.as_dict()}, model=route.model)
            result = self._structured_ai_result(action, ai, route)

        elif action in {"analyze_findings", "exploit_reasoning"}:
            route = model_router.route(transcript, action, has_scan_context=bool(decision.scan_id), target_context=(obs or {}).get("target") if obs else None)
            gemini = GeminiClient()
            try:
                ai = await gemini.analyze_findings(transcript, context={"observation": obs or {}, "route": route.as_dict()}, model=route.model)
            except Exception:
                if not getattr(route, "fallback_model", ""):
                    raise
                ai = await gemini.analyze_findings(transcript, context={"observation": obs or {}, "route": route.as_dict(), "fallback": True}, model=route.fallback_model)
            result = self._structured_ai_result(action, ai, route)

        elif action == "show_findings":
            q = select(Finding)
            if decision.scan_id:
                q = q.where(Finding.scan_id == decision.scan_id)
            findings = session.exec(q.order_by(Finding.created_at.desc())).all()
            result.update({"message": f"Found {len(findings)} findings.", "findings": [f.model_dump(mode="json") for f in findings[:30]]})

        elif action == "show_scans":
            scans = session.exec(select(Scan).order_by(Scan.created_at.desc())).all()
            result.update({"message": f"Found {len(scans)} scans.", "scans": [s.model_dump(mode="json") for s in scans[:25]]})

        elif action == "show_targets":
            targets = session.exec(select(Target).order_by(Target.created_at.desc())).all()
            result.update({"message": f"Found {len(targets)} targets.", "targets": [t.model_dump(mode="json") for t in targets[:25]]})

        elif action == "parse_target_page":
            route = model_router.route(transcript, action, has_scan_context=bool(decision.scan_id), target_context=(obs or {}).get("target") if obs else None)
            model = route.model

            prompt = (
                "Extract the following information from the bug bounty target page content:\n"
                "- Scope (In-scope domains/assets)\n"
                "- Out-of-scope assets\n"
                "- Rewards (bounty ranges if available)\n"
                "- Rules (important rules of engagement)\n"
                "- Technologies (detected or mentioned)\n"
                "- Recommended scan profile (e.g. passive-only, web-heavy, mobile, etc.)\n\n"
                "Format the output as a clear Markdown report. Be technical and precise."
            )

            try:
                gemini = GeminiClient()
                ai = await gemini.summarize_scan(f"{prompt}\n\nCONTENT:\n{transcript}", context=obs or {}, model=model)
                text = ai.text
                result.update({
                    "summary": text,
                    "message": "Target page parsed successfully.",
                    "response": text,
                    "next_actions": route.next_actions,
                    "requires_approval": False,
                    "approval_reason": "",
                    "selected_tools": route.selected_tools,
                    "model_used": ai.model,
                    "logs": [],
                    "raw": {"target_profile": route.target_profile},
                })
            except Exception as e:
                result.update({"ok": False, "message": "Parsing failed: Target page could not be processed.", "error": self._sanitize_error(e)})

        else:
            result.update({"message": "I can run passive recon, check public bug bounty programs, sync connected bounty accounts, import program targets, approved aggressive scans, AI analysis, summarize scans, analyze findings, and more. What would you like to do?"})

        publish_sync("agent.act", result)
        return result

    async def handle(self, session: Session, background_tasks: Any, transcript: str, selected_target_id: Optional[str] = None, selected_scan_id: Optional[str] = None, approve: bool = False) -> Dict[str, Any]:
        set_agent_state(status="observing", stage="observe", last_action=transcript)
        obs = self.observe(session, transcript, selected_target_id, selected_scan_id)
        set_agent_state(status="reasoning", stage="reason")
        decision = self.reason(transcript, obs)
        set_agent_state(status="thinking", stage="think")
        thought = self.think(transcript, decision, obs)
        set_agent_state(status="acting", stage="act", model_expert=thought["model_route"]["expert"], last_action=decision.action)
        try:
            result = await self.act(session, background_tasks, decision, approve=approve, transcript=transcript, obs=obs)
        except Exception as exc:
            if decision.action in {"general_chat", "summarize_scan", "analyze_findings", "exploit_reasoning", "parse_target_page"}:
                logger.exception("Architect agent action failed: action=%s", decision.action)
                result = {"ok": False, "provider": "gemini", "summary": "Gemini request failed.", "error": self._sanitize_error(exc), "next_actions": [], "requires_approval": False, "approval_reason": "", "selected_tools": [], "model_used": "", "logs": [], "raw": {}}
            else:
                raise
        finally:
            set_agent_state(status="idle", stage="observe")
        return {
            "observe": obs,
            "reason": decision.as_dict(),
            "think": thought,
            "act": result,
        }
