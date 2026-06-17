from __future__ import annotations

import os
import threading
from dataclasses import asdict, dataclass
from typing import Any

# Avoid noisy Windows symlink cache warning from huggingface_hub.
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")

EMAIL_ML_MODEL_NAME = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

# Local validation from Phase 16.2 smoke test:
# LABEL_0 behaved as safe/legitimate.
# LABEL_1 behaved as phishing/suspicious.
SAFE_LABEL = "LABEL_0"
PHISHING_LABEL = "LABEL_1"

_PIPELINE: Any | None = None
_PIPELINE_LOCK = threading.Lock()


@dataclass(frozen=True)
class EmailMLPrediction:
    enabled: bool
    model_name: str
    predicted_label: str | None
    mapped_verdict: str
    confidence: float
    phishing_score: float
    safe_score: float
    signal_strength: str
    is_phishing_signal: bool
    explanation: str
    raw_scores: list[dict[str, Any]]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _disabled_prediction(reason: str) -> EmailMLPrediction:
    return EmailMLPrediction(
        enabled=False,
        model_name=EMAIL_ML_MODEL_NAME,
        predicted_label=None,
        mapped_verdict="ML Unavailable",
        confidence=0.0,
        phishing_score=0.0,
        safe_score=0.0,
        signal_strength="Unavailable",
        is_phishing_signal=False,
        explanation=reason,
        raw_scores=[],
        error=reason,
    )


def _normalize_text(value: str | None) -> str:
    return " ".join(str(value or "").split())


def build_email_ml_text(
    *,
    subject: str | None = None,
    sender: str | None = None,
    body: str | None = None,
) -> str:
    parts: list[str] = []

    if subject:
        parts.append(f"Subject: {_normalize_text(subject)}")

    if sender:
        parts.append(f"Sender: {_normalize_text(sender)}")

    if body:
        parts.append(f"Body: {_normalize_text(body)}")

    return "\n".join(parts).strip()


def _load_pipeline() -> Any:
    global _PIPELINE

    if _PIPELINE is not None:
        return _PIPELINE

    with _PIPELINE_LOCK:
        if _PIPELINE is not None:
            return _PIPELINE

        try:
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
                pipeline,
            )
        except Exception as exc:  # pragma: no cover - dependency fallback
            raise RuntimeError(
                "ML dependencies are not installed. Install torch, transformers, "
                "safetensors, and huggingface_hub."
            ) from exc

        try:
            # Fast path after the first successful download: use the cached local files.
            model = AutoModelForSequenceClassification.from_pretrained(
                EMAIL_ML_MODEL_NAME,
                local_files_only=True,
            )
            tokenizer = AutoTokenizer.from_pretrained(
                EMAIL_ML_MODEL_NAME,
                local_files_only=True,
            )
        except Exception:
            # Fallback for a fresh machine where the model is not cached yet.
            model = AutoModelForSequenceClassification.from_pretrained(EMAIL_ML_MODEL_NAME)
            tokenizer = AutoTokenizer.from_pretrained(EMAIL_ML_MODEL_NAME)

        _PIPELINE = pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            truncation=True,
            max_length=512,
            top_k=None,
        )

        return _PIPELINE


def _extract_scores(result: Any) -> list[dict[str, Any]]:
    # transformers pipeline with top_k=None usually returns:
    # [[{"label": "...", "score": ...}, ...]]
    if isinstance(result, list) and result and isinstance(result[0], list):
        rows = result[0]
    elif isinstance(result, list):
        rows = result
    else:
        rows = []

    scores: list[dict[str, Any]] = []

    for item in rows:
        if not isinstance(item, dict):
            continue

        label = str(item.get("label") or "")
        score = float(item.get("score") or 0.0)

        scores.append({"label": label, "score": score})

    scores.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
    return scores


def _score_for(scores: list[dict[str, Any]], label: str) -> float:
    for item in scores:
        if item.get("label") == label:
            return float(item.get("score") or 0.0)

    return 0.0


def _signal_strength(phishing_score: float) -> str:
    if phishing_score >= 0.90:
        return "High"
    if phishing_score >= 0.70:
        return "Medium"
    if phishing_score >= 0.40:
        return "Low"
    return "Minimal"


def classify_email_text(text: str | None) -> EmailMLPrediction:
    normalized_text = _normalize_text(text)

    if not normalized_text:
        return _disabled_prediction("No email text was provided for ML classification.")

    try:
        classifier = _load_pipeline()
        result = classifier(normalized_text)
        scores = _extract_scores(result)
    except Exception as exc:
        return _disabled_prediction(f"Email ML classifier failed: {exc}")

    if not scores:
        return _disabled_prediction("Email ML classifier returned no scores.")

    top = scores[0]
    predicted_label = str(top.get("label") or "")
    confidence = float(top.get("score") or 0.0)
    phishing_score = _score_for(scores, PHISHING_LABEL)
    safe_score = _score_for(scores, SAFE_LABEL)

    is_phishing = phishing_score >= 0.70 and phishing_score > safe_score
    strength = _signal_strength(phishing_score)

    if is_phishing:
        mapped_verdict = "Phishing ML Signal"
        explanation = (
            "The local ML model found phishing-like language patterns in the email text. "
            "This is used as an additional signal together with SecureSight360 rule-based evidence."
        )
    else:
        mapped_verdict = "No Strong ML Phishing Signal"
        explanation = (
            "The local ML model did not find a strong phishing signal in the email text. "
            "SecureSight360 should still consider sender, links, attachments, headers, and rule-based indicators."
        )

    return EmailMLPrediction(
        enabled=True,
        model_name=EMAIL_ML_MODEL_NAME,
        predicted_label=predicted_label,
        mapped_verdict=mapped_verdict,
        confidence=round(confidence, 6),
        phishing_score=round(phishing_score, 6),
        safe_score=round(safe_score, 6),
        signal_strength=strength,
        is_phishing_signal=is_phishing,
        explanation=explanation,
        raw_scores=scores,
        error=None,
    )


def classify_email_parts(
    *,
    subject: str | None = None,
    sender: str | None = None,
    body: str | None = None,
) -> EmailMLPrediction:
    text = build_email_ml_text(subject=subject, sender=sender, body=body)
    return classify_email_text(text)


def warm_up_email_ml_classifier() -> dict[str, Any]:
    """Load the email ML model early so the first user analysis is faster."""
    try:
        _load_pipeline()
        return {
            "enabled": True,
            "model_name": EMAIL_ML_MODEL_NAME,
            "warmed_up": True,
            "error": None,
        }
    except Exception as exc:
        return {
            "enabled": False,
            "model_name": EMAIL_ML_MODEL_NAME,
            "warmed_up": False,
            "error": str(exc),
        }
