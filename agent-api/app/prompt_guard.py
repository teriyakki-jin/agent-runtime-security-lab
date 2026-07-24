from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any


SIGNALS: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        45,
        re.compile(r"\b(ignore|disregard|override)\b.{0,48}\b(previous|system|developer|instruction)s?\b"),
    ),
    (
        "tool_invocation_directive",
        35,
        re.compile(r"\b(call|invoke|execute|use)\b.{0,40}\b(tool|function|mock_http_request)\b"),
    ),
    (
        "external_transfer_directive",
        35,
        re.compile(r"\b(upload|exfiltrate|transfer|send)\b.{0,60}\b(https?://|external|remote)"),
    ),
    (
        "consent_bypass",
        25,
        re.compile(r"\b(do not|don't|without)\b.{0,32}\b(ask|confirm|consent|user)\b"),
    ),
    (
        "role_or_instruction_delimiter",
        20,
        re.compile(r"(<\/?(system|assistant|tool)>|\b(begin|end)\s+(automation\s+)?instruction)"),
    ),
)


@dataclass(frozen=True)
class PromptAssessment:
    source_id: str
    source_fingerprint: str
    trust: str
    risk_score: int
    action: str
    signals: tuple[str, ...]

    def to_evidence(self) -> dict[str, Any]:
        result = asdict(self)
        result["signals"] = list(self.signals)
        return result


def fingerprint(value: Any) -> str:
    if isinstance(value, str):
        serialized = value.encode()
    else:
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(serialized).hexdigest()[:16]


def assess_untrusted_content(content: str, source_id: str) -> PromptAssessment:
    if not content or len(content) > 65536:
        raise ValueError("Untrusted content must be between 1 and 65536 characters.")
    normalized = unicodedata.normalize("NFKC", content).casefold()
    matched = [(name, weight) for name, weight, pattern in SIGNALS if pattern.search(normalized)]
    risk_score = min(sum(weight for _, weight in matched), 100)
    action = "deny" if risk_score >= 60 else "review" if risk_score >= 30 else "allow"
    return PromptAssessment(
        source_id=source_id,
        source_fingerprint=fingerprint(content),
        trust="untrusted_external_content",
        risk_score=risk_score,
        action=action,
        signals=tuple(name for name, _ in matched),
    )


def guard_tool_calls(
    tool_calls: list[dict[str, Any]], assessment: PromptAssessment
) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    for call in tool_calls:
        function = call.get("function", {})
        name = str(function.get("name", "unknown"))[:64]
        arguments = function.get("arguments", {})
        decisions.append(
            {
                "tool": name,
                "arguments_fingerprint": fingerprint(arguments),
                "source_fingerprint": assessment.source_fingerprint,
                "action": "deny" if assessment.action == "deny" else "review",
                "reason": "tool request derived from untrusted injected instructions",
                "executed": False,
            }
        )
    return decisions
