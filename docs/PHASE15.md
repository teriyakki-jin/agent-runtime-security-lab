# Phase 15 — Portfolio Release & Measured Security

Phase 15는 새로운 탐지 기능을 추가하는 단계가 아니다. Phase 1~14에서 만든 공급망, 프롬프트, OAuth, 정책, 런타임, Kubernetes, SOC, 대응 통제를 하나의 재현 가능한 포트폴리오 릴리스로 묶고 실제 수치로 검증한다.

## 최종 스토리

| 시점 | 통제 | 검증 증거 |
|---|---|---|
| 실행 전 | Cosign keyless admission, Rekor, SBOM 정책, signed tool manifest, prompt provenance, OAuth scope | Phase 10·13 evidence |
| 실행 중 | OPA execution boundary, intent/runtime correlation, Tetragon, Kubernetes identity, causal graph | Phase 3·4·6·7·8·14 evidence |
| 실행 후 | OCSF, Elastic alert, OAuth revocation, reversible isolation, audit trail | Phase 5·11·14 evidence |

## 원클릭 실행

```powershell
Set-Location D:\develop\agent-runtime-security-lab
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase15-portfolio.ps1
```

이 명령은 다음 순서로 동작한다.

1. 기본 정책·OAuth·MCP·OCSF·runtime correlation 회귀 검증
2. 정상 6건과 공격 6건 fixture 실행
3. OPA 정책 지연시간 60회 측정
4. Docker CPU·메모리 측정
5. 실제 delegated token 폐기와 MCP network/container 격리·복구
6. Phase 15 테스트와 branch coverage 검증
7. 모든 Compose 컨테이너·네트워크·볼륨 제거
8. teardown 상태를 독립적으로 다시 확인한 뒤 evidence 확정

실패가 발생해도 `finally` 경로에서 teardown을 실행한다. 이미지를 함께 지우려면 다음 명령을 별도로 사용할 수 있다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop-phase15.ps1 -RemoveImages
```

## 측정 결과

| 지표 | 결과 | SLO | 판정 |
|---|---:|---:|---|
| 정책 지연 p50 | 5.796 ms | 관측값 | PASS |
| 정책 지연 p95 | 21.211 ms | ≤ 250 ms | PASS |
| 정책 지연 p99 | 27.964 ms | ≤ 500 ms | PASS |
| 공격 탐지 p95 | 26.179 ms | ≤ 1,000 ms | PASS |
| detect-to-block MTTR | 2,900 ms | ≤ 5,000 ms | PASS |
| recall | 100% | ≥ 95% | PASS |
| FPR | 0% | ≤ 5% | PASS |
| peak container CPU | 1.5% | ≤ 200% | PASS |
| peak container memory | 64.06 MiB | ≤ 1,024 MiB | PASS |
| Phase 15 branch coverage | 81.33% | ≥ 80% | PASS |

호스트 부하에 따라 latency와 resource 수치는 달라질 수 있다. SLO와 계산 방식은 [`portfolio_release/metrics.py`](../portfolio_release/metrics.py)에 있고, 원시 샘플은 Git에서 제외된 `runtime/phase15-raw.json`에 기록된다. 정적 evidence는 비밀정보나 container ID 없이 집계값만 포함한다.

## 정상/공격 fixture

[`scenarios.json`](../portfolio_release/fixtures/phase15/scenarios.json)은 정상 6건과 공격 6건을 동일한 방식으로 실행한다.

- 정상: 허용된 문서 읽기, intent와 일치하는 runtime file access
- 공격: indirect prompt injection, shell tool misuse, deny 이후 process 실행, 승인 전 network activity
- 판정: TP 6, FP 0, TN 6, FN 0
- 결과: precision 100%, recall 100%, FPR 0%

fixture는 외부 시스템을 공격하지 않는다. shell과 network 공격은 격리된 lab의 정책 거부 또는 시뮬레이션 경로에서만 재현한다.

## 데모

- [2분 20초 통합 공격 영상](demo/phase15-integrated-attack.mp4)
- [영상 챕터와 재현 절차](demo/PHASE15_DEMO.md)
- [최종 실행 화면](screenshots/phase15-portfolio-release.png)
- [기계 판독형 evidence](evidence/phase15-portfolio-release.json)

## 운영 전환 시 남은 한계

- in-memory intent·revocation·response state는 공유 영속 저장소로 교체해야 한다.
- Docker 단일 호스트 격리는 Kubernetes admission·NetworkPolicy·workload quarantine controller로 확장해야 한다.
- 로컬 HTTP와 비활성화된 Elastic security는 TLS, 인증, RBAC, secret manager 구성이 필요하다.
- 이 벤치마크는 로컬 lab의 회귀 기준이며 독립적인 보안 인증이나 운영 부하 시험을 의미하지 않는다.
