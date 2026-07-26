# Phase 15 통합 공격 데모

영상 길이: **2분 20초**

| 구간 | 내용 |
|---|---|
| 00:00–00:20 | 프로젝트 목표와 공격 경로 |
| 00:20–00:40 | 실행 전 공급망·프롬프트·OAuth 통제 |
| 00:40–01:00 | delegated agent와 공격 fixture |
| 01:00–01:20 | OPA·runtime identity·causal detection |
| 01:20–01:40 | OAuth token 폐기와 MCP 격리 |
| 01:40–02:00 | TTL 복구·OCSF·감사 증거 |
| 02:00–02:20 | p95/p99·MTTR·recall·FPR·teardown 결과 |

영상의 수치는 [`phase15-portfolio-release.json`](../evidence/phase15-portfolio-release.json)에서 가져왔다. 공격은 로컬 격리 환경에서만 재현하며 실제 외부 대상, shell execution, credential 원문을 포함하지 않는다.

전체 실습을 직접 재현하려면 다음 명령을 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase15-portfolio.ps1
```
