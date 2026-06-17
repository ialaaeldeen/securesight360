from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


EmailThreatVerdict = Literal[
    "Safe / No obvious threat detected",
    "Suspicious",
    "Malicious",
    "Impersonation Attempt",
    "Credential Theft Attempt",
    "Business Email Compromise Attempt",
    "Payment or Invoice Fraud Attempt",
    "Link-Based Phishing Attempt",
    "Attachment-Based Threat Suspicion",
]

EmailThreatConfidence = Literal["Low", "Medium", "High"]
EmailEvidenceStrength = Literal["Limited", "Moderate", "Strong"]


class EmailAttachmentInput(BaseModel):
    """
    Safe attachment context.

    Important:
    - This model does not execute attachments.
    - Future upload handling should extract metadata safely and pass it here.
    - Full file content should not be stored by default.
    """

    file_name: str = Field(default="", max_length=255)
    content_type: str | None = Field(default=None, max_length=150)
    size_bytes: int | None = Field(default=None, ge=0)
    sha256: str | None = Field(default=None, max_length=128)
    text_preview: str | None = Field(
        default=None,
        max_length=12000,
        description="Optional safely extracted text preview. Do not store full attachment body by default.",
    )


class EmailThreatAnalysisRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    sender: str = Field(default="", max_length=500)
    reply_to: str | None = Field(default=None, max_length=500)
    body: str = Field(
        default="",
        max_length=50000,
        description="User-submitted email body. Do not store by default.",
    )
    links: list[str] = Field(default_factory=list, max_length=100)
    headers: str | None = Field(
        default=None,
        max_length=30000,
        description="Optional user-submitted raw headers.",
    )
    attachments: list[EmailAttachmentInput] = Field(default_factory=list, max_length=20)


class EmailBehaviorFinding(BaseModel):
    behavior: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    explanation: str
    evidence: str | None = None


class EmailAttachmentAnalysis(BaseModel):
    file_name: str
    content_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    risk_indicators: list[str] = Field(default_factory=list)
    safe_handling: list[str] = Field(default_factory=list)


class EmailThreatAnalysisResponse(BaseModel):
    verdict: EmailThreatVerdict
    confidence: EmailThreatConfidence
    evidence_strength: EmailEvidenceStrength
    summary: str
    verdict_reasoning: str
    confidence_rationale: str
    key_indicators: list[str] = Field(default_factory=list)
    detected_behaviors: list[EmailBehaviorFinding] = Field(default_factory=list)
    structured_analysis: dict[str, Any] = Field(default_factory=dict)
    attachment_analysis: list[EmailAttachmentAnalysis] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    privacy_and_safety_notes: list[str] = Field(default_factory=list)
    technical_evidence: dict[str, Any] = Field(default_factory=dict)
    evaluation_metadata: dict[str, Any] = Field(default_factory=dict)
    analyzer_version: str = "email-threat-analyzer-mvp-1.1"


class EmailThreatCompactResponse(BaseModel):
    verdict: EmailThreatVerdict
    confidence: EmailThreatConfidence
    evidence_strength: EmailEvidenceStrength
    summary: str
    key_indicators: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    attachment_alerts: list[str] = Field(default_factory=list)
    link_alerts: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    analyzer_version: str = "email-threat-analyzer-mvp-1.1"
    ml_email_signal: dict[str, Any] | None = None

class EmailThreatHistoryItem(BaseModel):
    id: int
    created_at: str
    subject_preview: str | None = None
    sender_preview: str | None = None
    verdict: EmailThreatVerdict
    confidence: EmailThreatConfidence
    evidence_strength: EmailEvidenceStrength
    summary: str
    key_indicators: list[str] = Field(default_factory=list)
    attachment_alerts: list[str] = Field(default_factory=list)
    links_count: int = 0
    attachments_count: int = 0
    headers_provided: bool = False
    analyzer_version: str | None = None
    ml_email_signal: dict[str, Any] | None = None

class EmailThreatHistoryDetailResponse(EmailThreatHistoryItem):
    ml_email_signal: dict[str, Any] | None = None
    recommended_actions: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)

class EmailThreatHistoryListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    history: list[EmailThreatHistoryItem] = Field(default_factory=list)


class EmailThreatHistoryItem(BaseModel):
    id: int
    created_at: str
    subject_preview: str | None = None
    sender_preview: str | None = None
    verdict: EmailThreatVerdict
    confidence: EmailThreatConfidence
    evidence_strength: EmailEvidenceStrength
    summary: str
    key_indicators: list[str] = Field(default_factory=list)
    attachment_alerts: list[str] = Field(default_factory=list)
    links_count: int = 0
    attachments_count: int = 0
    headers_provided: bool = False
    analyzer_version: str | None = None


class EmailThreatHistoryDetailResponse(EmailThreatHistoryItem):
    recommended_actions: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)


class EmailThreatHistoryListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    history: list[EmailThreatHistoryItem] = Field(default_factory=list)

