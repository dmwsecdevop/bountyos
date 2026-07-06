"""
BountyOS - Core database models
SQLModel ORM over SQLite (swap to Postgres by changing DATABASE_URL)
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
import uuid


# ─── Enums ────────────────────────────────────────────────────────────────────

class ScanMode(str, Enum):
    PASSIVE    = "passive"     # zero-touch OSINT only — no packets to target
    AGGRESSIVE = "aggressive"  # full exploit chain — active payloads, WAF bypass

class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    PAUSED    = "paused"
    DONE      = "done"
    FAILED    = "failed"

class ScanPhase(str, Enum):
    RECON     = "recon"
    VULNSCAN  = "vulnscan"
    EXPLOIT   = "exploit"

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

class ApprovalStatus(str, Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


# ─── Target ───────────────────────────────────────────────────────────────────

class Target(SQLModel, table=True):
    id:          str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name:        str
    domain:      str
    scope:       str                          # comma-separated in-scope patterns
    out_of_scope: Optional[str] = None       # comma-separated OOS patterns
    notes:       Optional[str] = None
    created_at:  datetime = Field(default_factory=datetime.utcnow)

    scans: List["Scan"] = Relationship(back_populates="target")


# ─── Scan ─────────────────────────────────────────────────────────────────────

class Scan(SQLModel, table=True):
    id:          str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    target_id:   str = Field(foreign_key="target.id")
    status:      ScanStatus = ScanStatus.PENDING
    phase:       ScanPhase  = ScanPhase.RECON
    mode:        ScanMode   = ScanMode.PASSIVE
    config:      Optional[str] = None        # JSON blob: enabled tools, stealth level, etc.
    started_at:  Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at:  datetime = Field(default_factory=datetime.utcnow)

    target:   Optional[Target]   = Relationship(back_populates="scans")
    findings: List["Finding"]    = Relationship(back_populates="scan")
    events:   List["ScanEvent"]  = Relationship(back_populates="scan")
    approvals: List["Approval"]  = Relationship(back_populates="scan")


# ─── Finding ──────────────────────────────────────────────────────────────────

class Finding(SQLModel, table=True):
    id:          str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id:     str = Field(foreign_key="scan.id")
    title:       str
    severity:    Severity
    cvss_score:  Optional[float] = None
    description: Optional[str]  = None
    evidence:    Optional[str]  = None       # raw tool output / PoC snippet
    url:         Optional[str]  = None
    tool:        Optional[str]  = None       # which tool found it
    cwe_id:      Optional[str]  = None
    remediation: Optional[str]  = None
    false_positive: bool = False
    is_priority: bool = False
    created_at:  datetime = Field(default_factory=datetime.utcnow)

    scan: Optional[Scan] = Relationship(back_populates="findings")


# ─── ScanEvent (audit / live stream log) ─────────────────────────────────────

class ScanEvent(SQLModel, table=True):
    id:        str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id:   str = Field(foreign_key="scan.id")
    phase:     ScanPhase
    tool:      Optional[str] = None
    level:     str = "info"                  # info | warn | error | finding
    message:   str
    raw:       Optional[str] = None          # raw stdout chunk
    created_at: datetime = Field(default_factory=datetime.utcnow)

    scan: Optional[Scan] = Relationship(back_populates="events")


# ─── Approval Gate ────────────────────────────────────────────────────────────

class Approval(SQLModel, table=True):
    id:         str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id:    str = Field(foreign_key="scan.id")
    phase:      ScanPhase
    action:     str                          # e.g. "run sqlmap on /login"
    context:    Optional[str] = None         # AI reasoning that prompted this
    status:     ApprovalStatus = ApprovalStatus.PENDING
    decided_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    scan: Optional[Scan] = Relationship(back_populates="approvals")




# ─── Bounty Program Radar ─────────────────────────────────────────────────────

class BountyProgram(SQLModel, table=True):
    id:             str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name:           str
    platform:       str = "custom"          # projectdiscovery | hackerone | bugcrowd | intigriti | yeswehack | custom
    url:            Optional[str] = None
    offers_bounty:  bool = False
    reward_hint:    Optional[str] = None
    domains_json:   str = "[]"              # JSON array of domains/scope roots
    scope_raw:      Optional[str] = None     # raw platform/feed object for review
    status:         str = "active"          # active | paused | unknown
    value_score:    int = 0                  # 0-100 sorting score for bug bounty focus
    first_seen_at:  datetime = Field(default_factory=datetime.utcnow)
    last_seen_at:   datetime = Field(default_factory=datetime.utcnow)
    last_changed_at: Optional[datetime] = None
    created_at:     datetime = Field(default_factory=datetime.utcnow)




# ─── Connected Bounty Accounts ────────────────────────────────────────────────

class BountyAccount(SQLModel, table=True):
    id:               str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    platform:         str                         # hackerone | bugcrowd | intigriti | yeswehack | custom
    display_name:     str
    username:         Optional[str] = None        # token id / handle / account label, not a password
    auth_type:        str = "api_token"           # api_token | oauth_bearer | basic_token | custom
    token_label:      Optional[str] = None        # masked label so UI can identify token
    token_encrypted:  Optional[str] = None        # encrypted locally; never returned by routes
    api_base_url:     Optional[str] = None
    status:           str = "created"             # created | connected | error | disabled
    last_error:       Optional[str] = None
    last_sync_at:     Optional[datetime] = None
    notes:            Optional[str] = None
    created_at:       datetime = Field(default_factory=datetime.utcnow)
    updated_at:       datetime = Field(default_factory=datetime.utcnow)


# ─── Pydantic response schemas (no table=True) ────────────────────────────────

class TargetCreate(SQLModel):
    name:         str
    domain:       str
    scope:        str
    out_of_scope: Optional[str] = None
    notes:        Optional[str] = None

class ScanCreate(SQLModel):
    target_id: str
    mode:      str = "passive"
    config:    Optional[str] = None          # JSON string

class FindingUpdate(SQLModel):
    false_positive: Optional[bool] = None
    is_priority:    Optional[bool] = None
    remediation:    Optional[str]  = None
    notes:          Optional[str]  = None

class ApprovalDecision(SQLModel):
    status: ApprovalStatus                   # approved | rejected

# ─── Autonomous Hunter Intelligence ─────────────────────────────────────────

class AttackNode(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    node_type: str = Field(index=True)  # target | asset | endpoint | service | technology | finding | hypothesis
    key: str = Field(index=True)
    label: str
    attributes_json: str = "{}"
    risk_score: float = 0.0
    confidence: float = 0.5
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class AttackEdge(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    source_node_id: str = Field(foreign_key="attacknode.id", index=True)
    target_node_id: str = Field(foreign_key="attacknode.id", index=True)
    relation: str = Field(index=True)  # exposes | calls | contains | indicates | supports | validates
    confidence: float = 0.5
    evidence_json: str = "[]"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AgentMemory(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: Optional[str] = Field(default=None, foreign_key="scan.id", index=True)
    agent: str = Field(index=True)
    kind: str = Field(index=True)  # observation | reasoning_summary | plan | result | lesson
    content: str
    metadata_json: str = "{}"
    confidence: float = 0.5
    created_at: datetime = Field(default_factory=datetime.utcnow)


class BugHypothesis(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    title: str
    bug_class: str = Field(index=True)
    target: Optional[str] = None
    confidence: float = 0.5
    priority_score: float = 0.0
    bounty_value: str = "medium"
    reasoning_summary: str
    evidence_json: str = "[]"
    safe_next_steps_json: str = "[]"
    approval_required: bool = False
    status: str = "proposed"  # proposed | planned | validating | confirmed | rejected | inconclusive
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class PlannerDecision(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    hypothesis_id: Optional[str] = Field(default=None, foreign_key="bughypothesis.id", index=True)
    action_type: str = Field(index=True)
    action_name: str
    target: Optional[str] = None
    expected_value: float = 0.0
    effort: str = "medium"
    noise: str = "low"
    approval_required: bool = False
    rationale: str
    status: str = "queued"  # queued | approved | running | completed | skipped
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ValidationAttempt(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    hypothesis_id: str = Field(foreign_key="bughypothesis.id", index=True)
    planner_decision_id: Optional[str] = Field(default=None, foreign_key="plannerdecision.id")
    validation_type: str
    status: str = "planned"  # planned | awaiting_approval | approved | running | confirmed | likely | inconclusive | false_positive | blocked
    plan_json: str = "{}"
    result_summary: Optional[str] = None
    evidence_json: str = "[]"
    requests_sent: int = 0
    approved: bool = False
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EvidenceArtifact(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    validation_attempt_id: Optional[str] = Field(default=None, foreign_key="validationattempt.id", index=True)
    finding_id: Optional[str] = Field(default=None, foreign_key="finding.id", index=True)
    artifact_type: str = "text"  # request | response | screenshot | log | text | json
    title: str
    content: str
    sha256: str
    redacted: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class BountyReport(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    finding_id: Optional[str] = Field(default=None, foreign_key="finding.id", index=True)
    validation_attempt_id: Optional[str] = Field(default=None, foreign_key="validationattempt.id")
    title: str
    status: str = "draft"  # draft | needs_evidence | ready
    content_markdown: str
    content_json: str = "{}"
    quality_score: int = 0
    missing_items_json: str = "[]"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ExperienceRecord(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: Optional[str] = Field(default=None, foreign_key="scan.id", index=True)
    context_json: str = "{}"
    action: str = Field(index=True)
    result: str
    utility: float = 0.0
    novelty_reward: float = 0.0
    impact_reward: float = 0.0
    cost_penalty: float = 0.0
    false_positive_penalty: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)

# ─── Agent Quality Loop ───────────────────────────────────────────────────────

class AgentEvaluation(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: Optional[str] = Field(default=None, foreign_key="scan.id", index=True)
    task_type: str = Field(index=True)  # hypothesis | plan | validation | report
    task_id: Optional[str] = Field(default=None, index=True)
    producer_agent: str = Field(index=True)
    evaluator_agent: str = "critic_verifier"
    model_expert: str = Field(default="quality_critic", index=True)
    status: str = Field(default="retry", index=True)  # accepted | accepted_with_warnings | retry | rejected
    overall_score: int = 0
    evidence_quality: int = 0
    accuracy: int = 0
    reproducibility: int = 0
    impact_confidence: int = 0
    efficiency: int = 0
    safety: int = 0
    calibrated_confidence: float = 0.0
    findings_json: str = "[]"
    recommendations_json: str = "[]"
    metadata_json: str = "{}"
    retry_count: int = 0
    parent_evaluation_id: Optional[str] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AgentPerformanceRecord(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: Optional[str] = Field(default=None, foreign_key="scan.id", index=True)
    evaluation_id: str = Field(foreign_key="agentevaluation.id", index=True)
    agent: str = Field(index=True)
    model_expert: str = Field(index=True)
    task_type: str = Field(index=True)
    outcome: str = Field(index=True)
    quality_score: int = 0
    confirmed: bool = False
    latency_ms: float = 0.0
    estimated_cost: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)

# ─── Remote Tool Runners ──────────────────────────────────────────────────────

class ToolRunner(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name: str = Field(index=True)
    token_hash: str
    status: str = Field(default="created", index=True)  # created | online | offline | disabled
    platform: Optional[str] = None
    hostname: Optional[str] = None
    labels_json: str = "[]"
    tools_json: str = "{}"
    enabled: bool = True
    connected_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    last_error: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ToolJob(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    runner_id: Optional[str] = Field(default=None, foreign_key="toolrunner.id", index=True)
    scan_id: Optional[str] = Field(default=None, foreign_key="scan.id", index=True)
    tool_name: str = Field(index=True)
    target: Optional[str] = None
    argv_json: str = "[]"
    metadata_json: str = "{}"
    execution_location: str = Field(default="remote", index=True)
    status: str = Field(default="queued", index=True)  # queued | running | completed | failed | timeout | cancelled
    timeout_seconds: int = 300
    output: Optional[str] = None
    exit_code: Optional[int] = None
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class SystemSetting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str
    updated_at: datetime = Field(default_factory=datetime.utcnow)
