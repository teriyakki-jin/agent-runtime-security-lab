# Phase 8 진행 상황 — Kubernetes Audit/RBAC Attack Chain

작성 시점: 2026-07-24

진행률: **96%**

## 목표

Kubernetes API Audit Log와 Tetragon 커널 이벤트를 결합해 다음 공격 흐름을 하나의 Critical 탐지로 연결한다.

```text
ServiceAccount 권한 오용
  → cluster-admin RoleBinding 생성
  → Shadow Pod 생성
  → pods/exec 호출
  → Tetragon process_exec 관측
  → OCSF Detection Finding
```

## 완료 체크리스트

- [x] `agent/phase-8-audit-attack-chain` 브랜치 생성
- [x] Kubernetes Audit 정책과 Audit-enabled Kind 클러스터 구성 작성
- [x] 의도적으로 제한된 RBAC escalation 실습 경계 작성
- [x] `compromised-agent` ServiceAccount 공격 시나리오 작성
- [x] Kubernetes Audit + Tetragon 상관분석기 구현
- [x] 인증 사용자와 impersonated/effective 사용자 구분 처리
- [x] OWASP Agentic `ASI03`, MITRE ATT&CK `T1098.006`·`T1610` 매핑
- [x] OCSF 1.8 Detection Finding 변환
- [x] 실제 `RoleBinding → Pod → pods/exec → process_exec` 체인 재현
- [x] 정적 evidence JSON과 포트폴리오 스크린샷 생성
- [x] `docs/PHASE8.md`, README, GitHub Actions 갱신
- [x] Agent API 27개, sensor 8개, Kubernetes chain 4개, detection 3개 테스트 통과
- [x] 전체 Docker Compose 회귀 검증 통과
- [x] ServiceAccount token, 원본 명령 인자, Audit request body 비저장 확인
- [ ] 커밋·푸시·Draft PR·GitHub Actions 확인

## 실제 검증 환경

| 구성요소 | 값 |
|---|---|
| Kind | 0.32.0 |
| Kubernetes | 1.36.1 |
| Tetragon | 1.7.0 |
| Cluster | `arsl-phase8` |
| Namespace | `arsl-lab` |
| Effective identity | `system:serviceaccount:arsl-lab:compromised-agent` |
| Shadow workload | `audit-shadow` |

## 검증 결과

- 유효 신원: `system:serviceaccount:arsl-lab:compromised-agent`
- Audit 이벤트: 6,379개
- Tetragon 이벤트: 13개
- 상관분석 시간차: 17,124ms
- 탐지 결과: `Critical / kubernetes_privilege_escalation_chain`
- `pods/exec`: Kubernetes 1.36 실제 형식인 `verb=get`, `subresource=exec`, HTTP `101` 반영

## 안전 범위

- 인터넷 공격이나 외부 시스템 접근 없음
- 전용 로컬 Kind 클러스터만 사용
- 실제 ServiceAccount 토큰 발급·탈취 없음
- `kubectl --as` impersonation으로 유효 신원만 재현
- Shadow Pod는 non-root, read-only filesystem, capability drop, seccomp 제한 유지
- 원본 Audit Log와 Tetragon 원본은 Git에서 제외된 `runtime/phase8`에만 저장
