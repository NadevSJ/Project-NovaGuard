# ANALYSIS: New module — no prior feedback collection existed.
# CHANGES:  Adds log_feedback / get_feedback_stats / export_as_dataset
#           backed by logs/feedback.jsonl. Raw content is never stored,
#           only a sha256 hash + 60-char preview.
"""
Human-in-the-Loop Feedback Manager.
Collects user corrections to build a real-world evaluation dataset.
These corrections are more valuable than synthetic data because they
come from real users encountering real scams.
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime

FEEDBACK_LOG = Path("logs/feedback.jsonl")
LABELS = ["SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"]


def log_feedback(
    user_input: str,
    predicted_label: str,
    feedback_type: str,
    correct_label: str = None,
    input_type: str = "unknown",
):
    """
    Log user feedback.
    feedback_type: "correct" | "incorrect"
    correct_label: only required when feedback_type == "incorrect"

    Input is hashed for privacy — raw content never stored.
    """
    FEEDBACK_LOG.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now().isoformat(),
        "input_hash": hashlib.sha256(user_input.encode()).hexdigest()[:16],
        "input_preview": (
            user_input[:60] + "..." if len(user_input) > 60 else user_input
        ),
        "input_length": len(user_input),
        "input_type": input_type,
        "predicted_label": predicted_label,
        "feedback_type": feedback_type,
        "correct_label": correct_label,
        "is_false_negative": (
            (predicted_label in ["SAFE", "LIKELY_SAFE"]
             and correct_label == "SCAM")
            if correct_label else None
        ),
    }

    with open(FEEDBACK_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def get_feedback_stats() -> dict:
    """Returns aggregate feedback statistics for the dashboard."""
    if not FEEDBACK_LOG.exists():
        return {
            "total": 0,
            "correct": 0,
            "incorrect": 0,
            "false_negatives": 0,
            "accuracy_from_feedback": None,
        }

    entries = []
    with open(FEEDBACK_LOG, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entries.append(json.loads(line.strip()))
            except Exception:
                continue

    total = len(entries)
    correct = sum(1 for e in entries if e["feedback_type"] == "correct")
    incorrect = sum(1 for e in entries if e["feedback_type"] == "incorrect")
    false_negatives = sum(1 for e in entries if e.get("is_false_negative"))

    return {
        "total": total,
        "correct": correct,
        "incorrect": incorrect,
        "false_negatives": false_negatives,
        "accuracy_from_feedback": round(correct / total * 100, 1) if total > 0 else None,
        "false_negative_rate": round(false_negatives / max(incorrect, 1) * 100, 1),
    }


def export_as_dataset(
    output_path: str = "evaluation/dataset/feedback_dataset.json",
) -> int:
    """
    Exports confirmed incorrect predictions as labeled samples
    for the evaluation dataset. Only exports cases where user
    provided the correct label.
    Returns count of exported samples.
    """
    if not FEEDBACK_LOG.exists():
        return 0

    samples = []
    with open(FEEDBACK_LOG, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            try:
                e = json.loads(line.strip())
                if e["feedback_type"] == "incorrect" and e.get("correct_label"):
                    samples.append({
                        "id": f"FEEDBACK-{i:04d}",
                        "input_type": e["input_type"],
                        "input": e["input_preview"],
                        "ground_truth_label": e["correct_label"],
                        "ground_truth_score_range": {
                            "SCAM": [75, 100], "SUSPICIOUS": [40, 74],
                            "LIKELY_SAFE": [15, 39], "SAFE": [0, 14],
                        }.get(e["correct_label"], [0, 100]),
                        "source": "user_feedback",
                        "original_prediction": e["predicted_label"],
                    })
            except Exception:
                continue

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"samples": samples, "total": len(samples)}, f, indent=2)

    return len(samples)
