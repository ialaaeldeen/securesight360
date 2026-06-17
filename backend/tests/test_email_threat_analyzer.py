from app.schemas.email_threat import EmailAttachmentInput, EmailThreatAnalysisRequest
from app.services.email_threat_analyzer import analyze_email_threat


def test_email_analyzer_detects_credential_theft_attempt():
    payload = EmailThreatAnalysisRequest(
        subject="Urgent: verify your account now",
        sender="Microsoft Support <support@microsoft-secure-login.example>",
        reply_to="security-team@random-mail.example",
        body=(
            "Your account will be suspended within 24 hours. "
            "Login to continue and confirm your password: https://bit.ly/fake-login"
        ),
        links=["https://bit.ly/fake-login"],
        headers=(
            "Authentication-Results: mx.example; "
            "spf=fail smtp.mailfrom=random-mail.example; dmarc=fail"
        ),
    )

    result = analyze_email_threat(payload)

    assert result.verdict == "Credential Theft Attempt"
    assert result.confidence in {"Medium", "High"}
    assert result.evidence_strength in {"Moderate", "Strong"}
    assert result.verdict_reasoning
    assert result.confidence_rationale
    assert result.key_indicators
    assert result.structured_analysis["primary_verdict"] == result.verdict
    assert result.structured_analysis["language_and_intent_analysis"]["credential_harvesting_detected"] is True
    assert result.structured_analysis["link_analysis"]["links_opened"] is False
    assert any(item.behavior == "Credential harvesting language" for item in result.detected_behaviors)
    assert any(item.behavior == "Reply-To mismatch" for item in result.detected_behaviors)
    assert result.technical_evidence["numeric_score_used"] is False
    assert result.evaluation_metadata["numeric_risk_score_used"] is False


def test_email_analyzer_detects_attachment_based_threat_suspicion():
    payload = EmailThreatAnalysisRequest(
        subject="Review attached document",
        sender="Documents <documents@example-supplier.com>",
        body="Please see attached document and review it today.",
        attachments=[
            EmailAttachmentInput(
                file_name="secure_document.html",
                content_type="text/html",
                size_bytes=20480,
                text_preview="<html>Verify your account password at https://example.com/login</html>",
            )
        ],
    )

    result = analyze_email_threat(payload)

    assert result.verdict == "Attachment-Based Threat Suspicion"
    assert result.confidence in {"Medium", "High"}
    assert result.evidence_strength in {"Moderate", "Strong"}
    assert result.attachment_analysis
    assert result.attachment_analysis[0].risk_indicators
    assert result.structured_analysis["attachment_safety_analysis"]["attachments_detected"] == 1
    assert result.structured_analysis["attachment_safety_analysis"]["attachments_executed"] is False
    assert any(item.behavior == "Attachment-based threat suspicion" for item in result.detected_behaviors)
    assert any("Attachments are not executed" in note for note in result.privacy_and_safety_notes)


def test_email_analyzer_detects_payment_or_invoice_fraud_attempt():
    payload = EmailThreatAnalysisRequest(
        subject="Invoice payment request",
        sender="Accounts <accounts@supplier-example.com>",
        reply_to="payments@new-bank-details.example",
        body=(
            "Please process the overdue invoice today. "
            "Use the updated bank details and send remittance confirmation."
        ),
    )

    result = analyze_email_threat(payload)

    assert result.verdict == "Payment or Invoice Fraud Attempt"
    assert result.confidence in {"Medium", "High"}
    assert result.structured_analysis["language_and_intent_analysis"]["payment_or_invoice_theme_detected"] is True
    assert any(item.behavior == "Fake invoice or payment request" for item in result.detected_behaviors)
    assert result.evaluation_metadata["numeric_risk_score_used"] is False


def test_email_analyzer_safe_message_has_no_numeric_score():
    payload = EmailThreatAnalysisRequest(
        subject="Meeting notes",
        sender="Alaa <alaa@example.com>",
        body="Hi, these are the meeting notes from today. Regards.",
    )

    result = analyze_email_threat(payload)

    assert result.verdict == "Safe / No obvious threat detected"
    assert result.confidence == "Low"
    assert result.evidence_strength == "Limited"
    assert result.verdict_reasoning
    assert result.confidence_rationale
    assert "security_score" not in result.model_dump()
    assert "risk_score" not in result.model_dump()
    assert result.technical_evidence["numeric_score_used"] is False
    assert result.evaluation_metadata["numeric_risk_score_used"] is False
    assert result.structured_analysis["link_analysis"]["links_opened"] is False
    assert result.structured_analysis["attachment_safety_analysis"]["attachments_executed"] is False
