# Phase 10 — Local LLM Indirect Prompt Injection Defense

## Executive summary

Phase 10 moves prompt-injection testing from static strings to an actual local model. A CPU-only Qwen3 model reads an untrusted business document containing hidden operational instructions and proposes a sensitive tool call. The runtime guard preserves source provenance, scores injection indicators, propagates taint to the proposed action, and denies it before any tool can run.

![Phase 10 local LLM prompt injection validation](screenshots/phase10-local-llm-injection.png)

## Why this phase matters

Prompt injection is not only a content-moderation problem. In an agent, model output can become a privileged action. External documents, retrieved pages, email, and tool output must remain data even when they contain convincing instructions.

This phase tests four boundaries:

- the model may be influenced by untrusted content;
- untrusted provenance must survive model processing;
- a proposed tool call must pass a deterministic policy boundary;
- forensic evidence must not leak the malicious document or arguments.

## Architecture

```mermaid
flowchart LR
    DOC["Untrusted report"] --> VULN["Intentionally vulnerable prompt assembly"]
    VULN --> LLM["Local Qwen3-0.6B via llama.cpp"]
    LLM --> CALL["Proposed mock_http_request call"]
    DOC --> ASSESS["NFKC + weighted signal detector"]
    ASSESS --> TAINT["Source provenance / taint"]
    CALL --> GUARD["Deterministic tool-call guard"]
    TAINT --> GUARD
    GUARD -->|"deny"| EVIDENCE["Sanitized fingerprints + finding"]
    GUARD -. "never executed" .-> TOOL["External tool"]
```

## Implementation

### Local inference

- `ghcr.io/ggml-org/llama.cpp:server` runs in the optional `llm` Compose profile.
- The runtime image is pinned by OCI digest and each run fingerprints the downloaded GGUF with SHA-256.
- The official `Qwen/Qwen3-0.6B-GGUF:Q8_0` model runs locally on CPU.
- The API is bound only to `127.0.0.1:18081`.
- A fresh 256-bit bearer key protects the inference API for each replay.
- The model cache is retained in a named volume for repeatable offline replay.

### Injection detector

The detector applies Unicode NFKC normalization and case folding before matching weighted signals:

| Signal | Weight |
|---|---:|
| instruction override | 45 |
| direct tool invocation | 35 |
| external transfer | 35 |
| consent bypass | 25 |
| role/instruction delimiter | 20 |

Scores of 60 or more are denied, 30–59 require review, and lower scores are allowed. Detection is deliberately deterministic and independent of the model.

### Provenance-aware tool guard

The document receives a source fingerprint before inference. Any proposed tool call derived from that source inherits its assessment. The guard records the tool name, document fingerprint, and argument fingerprint but does not retain raw arguments. The experiment contains no tool dispatcher, so a model proposal cannot cause network access.

## Attack replay

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-llm-injection.ps1
```

The first run downloads the container and model. Subsequent runs reuse the cache.

| Check | Expected |
|---|---|
| local model inference | completed |
| vulnerable path | injected tool proposed |
| malicious document | denied |
| safe document | allowed |
| tainted tool call | blocked |
| external tool execution | false |

The sanitized machine-readable result is stored in [Phase 10 evidence](evidence/phase10-local-llm-injection.json).

## Threat mapping

- OWASP Agentic Top 10: `ASI01` Agent Goal Hijack
- OWASP Top 10 for LLM Applications 2025: `LLM01` Prompt Injection
- MITRE ATLAS: `AML.T0051` LLM Prompt Injection
- Finding: `Critical / indirect_prompt_injection_tool_attempt`

## Privacy and safety

- No external tool is implemented or invoked by the replay harness.
- The malicious URL, raw document, complete prompt, and model response are excluded from evidence.
- Only 16-character SHA-256 fingerprints support correlation.
- The model endpoint is loopback-only and the runtime stays on the lab bridge.
- Untrusted content is capped at 65,536 characters.
- The optional LLM profile does not affect the deterministic CI lab.

## Validation

- prompt-guard unit tests cover malicious, safe, sanitized, and oversized inputs;
- Python compilation and PowerShell parsing are checked;
- all Compose profiles are validated;
- CI verifies evidence invariants and threat mappings without downloading the model;
- the existing full integration suite remains the regression gate.

## References

- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [MITRE ATLAS AML.T0051](https://atlas.mitre.org/techniques/AML.T0051)
- [llama.cpp Docker documentation](https://github.com/ggml-org/llama.cpp/blob/master/docs/docker.md)
- [Qwen3-0.6B-GGUF model card](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF)
