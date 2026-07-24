# Agent Runtime Security Lab

AI Agent가 **허가받은 행동(intent)** 과 컨테이너에서 **실제로 관측된 행동(runtime observation)** 을 비교해 정책 우회와 도구 오용을 탐지하는 로컬 보안 실습 프로젝트입니다.

> Current: **Phase 7 — Kubernetes Workload Identity Correlation**

![Phase 7 Kubernetes workload identity correlation](docs/screenshots/phase7-kubernetes-identity.png)

- [Phase 2: Runtime Approval Control Plane](docs/PHASE2.md)
- [Phase 3: Intent / Runtime Correlation](docs/PHASE3.md)
- [Phase 4: Live Tetragon eBPF Validation](docs/PHASE4.md)
- [Phase 5: OCSF SOC Pipeline](docs/PHASE5.md)
- [Phase 6: Detection-as-Code & Threat Mapping](docs/PHASE6.md)
- [Phase 7: Kubernetes Workload Identity Correlation](docs/PHASE7.md)

## Why this project

일반적인 AI 보안 데모는 프롬프트 문자열 또는 모델 응답만 검사합니다. 이 프로젝트는 판단 지점을 MCP 도구 실행 경계와 Linux 런타임까지 확장합니다.

- OPA가 도구 요청을 `allow / review / deny`로 분류
- 위험 작업은 사람의 승인과 1회성 HMAC capability 요구
- 실행 전 agent intent를 별도 원장에 기록
- Tetragon 이벤트를 프로세스·파일·네트워크 observation으로 정규화
- Docker container ID와 event timestamp로 intent를 자동 상관분석
- intent와 observation이 다르면 Critical/High finding 생성
- 원본 인자와 관측 대상을 OCSF 내보내기에서 fingerprint로 비식별화
- Jaeger에서 `invoke_agent`와 `execute_tool` span 추적
- ES|QL detection-as-code로 OCSF finding을 경보화하고 OWASP Agentic 2026 / MITRE ATT&CK에 매핑
- Kubernetes Pod UID·Namespace·ServiceAccount를 intent와 eBPF event에 바인딩해 workload identity 도용 탐지

## Architecture

```mermaid
flowchart LR
    TEST["Attack scenarios"] --> API["Agent Gateway"]
    API -->|"policy input"| OPA["OPA"]
    OPA -->|"allow / review / deny"| API
    API --> INTENT["Intent ledger"]
    API -->|"allow or signed approval"| MCP["MCP Tool Server"]
    HUMAN["Human reviewer"] -->|"one-time capability"| API
    MCP --> RUNTIME["Linux runtime"]
    RUNTIME --> TETRAGON["Tetragon eBPF"]
    TETRAGON --> ADAPTER["Signed JSON adapter"]
    ADAPTER --> OBS["Runtime observations"]
    INTENT --> CORRELATOR["Intent correlator"]
    OBS --> CORRELATOR
    CORRELATOR --> FINDING["OCSF Detection Finding"]
    API --> JAEGER["Jaeger / OpenTelemetry"]
    API -->|"OCSF API Activity"| LOGSTASH["Logstash"]
    FINDING -->|"OCSF Detection Finding"| LOGSTASH
    LOGSTASH --> ES["Elasticsearch"]
    ES --> KIBANA["Kibana SOC Dashboard"]
    RULES["Versioned ES|QL Rules"] --> DETECT["Detection Runner"]
    ES --> DETECT
    DETECT --> ALERTS["Idempotent Alert Index"]
    ALERTS --> THREAT["Threat Mapping Dashboard"]
    K8S["Kubernetes Pod Inventory"] --> IDENTITY["Workload Identity Resolver"]
    TETRAGON --> IDENTITY
    IDENTITY --> CORRELATOR
```

기본 Compose와 GitHub Actions는 결정론적 시뮬레이터로 회귀 검증합니다. 별도 Phase 4 검증은 Windows Docker Desktop의 WSL2 Linux 커널에 Tetragon v1.7.0 eBPF 프로그램을 실제로 attach해 커널 이벤트를 수집합니다.

## Detection scenarios

| Layer | Scenario | Policy intent | Runtime observation | Result |
|---|---|---|---|---|
| Policy | Public document read | `allow` | MCP execution | Allowed |
| Policy | `../../etc/shadow` path traversal | `deny` | None | Blocked |
| Policy | Shell tool misuse | `deny` | None | Blocked |
| Approval | External transfer request | `review` | None until approval | Pending |
| Runtime | Public document file access | `allow + file_access` | Expected path | Match |
| Runtime | Process execution after deny | No runtime activity | `process_exec` | Critical mismatch |
| Runtime | Network connection before approval | No runtime activity | `network_connect` | Critical mismatch |
| Runtime | Observation without intent | No matching intent | Any event | High orphan finding |

## Quick start

Requirements:

- Windows 10/11 + WSL2 or Linux
- Docker Desktop / Docker Engine with Compose
- PowerShell 5.1+

```powershell
Set-Location D:\develop\agent-runtime-security-lab
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-lab.ps1
```

Services:

- Security dashboard: <http://127.0.0.1:8080>
- OpenAPI: <http://127.0.0.1:8080/docs>
- Runtime OCSF: <http://127.0.0.1:8080/api/runtime/ocsf>
- Jaeger: <http://127.0.0.1:16686>
- OPA: <http://127.0.0.1:8181>

MCP는 호스트 포트를 공개하지 않으며 전용 Docker bridge 안에서만 접근됩니다.

## Try Phase 3

정상 file observation과 intent를 비교합니다.

```powershell
Invoke-RestMethod `
    -Method Post `
    -Uri http://127.0.0.1:8080/api/runtime/scenarios/matched_file_read
```

정책이 거부한 뒤 프로세스가 실행된 우회 상황을 재현합니다.

```powershell
Invoke-RestMethod `
    -Method Post `
    -Uri http://127.0.0.1:8080/api/runtime/scenarios/denied_process_bypass
```

```powershell
Invoke-RestMethod http://127.0.0.1:8080/api/runtime/intents
Invoke-RestMethod http://127.0.0.1:8080/api/runtime/observations
Invoke-RestMethod http://127.0.0.1:8080/api/runtime/findings
Invoke-RestMethod http://127.0.0.1:8080/api/runtime/ocsf
```

## Try Phase 4 — live eBPF

기본 Lab을 실행한 뒤 관리자 권한이 아닌 일반 PowerShell에서 실센서 검증을 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-tetragon.ps1
```

스크립트가 수행하는 작업:

1. 공식 `quay.io/cilium/tetragon:v1.7.0` 이미지를 privileged sensor로 실행
2. 커널 BTF와 eBPF base sensor attach 확인
3. monitor-only TracingPolicy 적용
4. 실제 `security_file_permission` event를 정상 intent와 자동 연결
5. 정책 거부 직후 발생시킨 실제 `process_exec`를 Critical mismatch로 탐지

Tetragon만 커널 관측을 위해 privileged로 실행됩니다. Agent Gateway와 MCP 컨테이너는 계속 non-root, read-only, `cap_drop: ALL` 상태입니다. 검증 후 센서를 중지하려면 `-StopSensor`를 사용합니다.

## Tetragon adapter

Linux/Kubernetes에서 [`deploy/tetragon/runtime-observation.yaml`](deploy/tetragon/runtime-observation.yaml)을 적용하고 Tetragon JSONL을 adapter에 전달합니다.

```bash
kubectl apply -f deploy/tetragon/runtime-observation.yaml

export RUNTIME_SENSOR_HMAC_KEY='<same key as agent-api>'
tetra getevents -o json | python sensor/tetragon_adapter.py \
  --container-alias '<docker-id>=arsl-mcp-server' \
  --container-name arsl-mcp-server \
  --gateway http://127.0.0.1:8080
```

`--intent-id`는 선택 사항입니다. 생략하면 Gateway가 container identity와 15초 event window로 자동 correlation합니다. 자세한 실센서 증거와 한계는 [Phase 4 문서](docs/PHASE4.md)를 참고하세요.

## Try Phase 5 — SOC pipeline

Elastic Stack은 기본 랩과 분리된 `soc` 프로필로 실행됩니다. 다른 로컬 Elastic 실습과 충돌하지 않도록 기본 포트는 19200/15601/19600을 사용합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-soc.ps1
```

- Kibana SOC dashboard: <http://127.0.0.1:15601/app/dashboards#/view/arsl-soc-overview>
- Elasticsearch API: <http://127.0.0.1:19200>
- Logstash monitoring API: <http://127.0.0.1:19600>

Logstash는 5초마다 두 OCSF 엔드포인트를 수집합니다. `metadata.uid`를 Elasticsearch document ID로 사용하므로 재수집해도 중복 문서가 생성되지 않습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-soc.ps1
```

실제 검증 결과와 운영 한계는 [Phase 5 문서](docs/PHASE5.md)와 [검증 증거](docs/evidence/phase5-soc-validation.json)에 기록했습니다.

## Try Phase 6 — threat detection

버전 관리되는 ES|QL 규칙을 실행하고 OWASP Agentic Top 10 / MITRE ATT&CK 대시보드를 설치합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-detections.ps1
```

- Threat dashboard: <http://127.0.0.1:15601/app/dashboards#/view/arsl-threat-mapping>
- 3 detection rules: denied process execution, network before approval, orphan runtime activity
- 결정론적 alert ID: 반복 실행해도 동일 source/rule 경보가 중복 생성되지 않음

기본 시나리오와 실 Tetragon 회귀에서 탐지 10건, Critical 8건, OWASP ASI02·ASI05·ASI10과 MITRE T1041·T1059 매핑 결과를 [Phase 6 문서](docs/PHASE6.md)와 [검증 증거](docs/evidence/phase6-threat-detection.json)에 기록했습니다.

## Try Phase 7 — Kubernetes identity

전용 Kind 클러스터에 Tetragon 1.7.0과 두 hardened workload를 배포하고 실제 `process_exec` event를 identity-aware correlator로 검증합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-kubernetes.ps1
```

- `approved-tool / agent-tools`: intent에 바인딩된 Pod UID와 일치
- `shadow-runner / untrusted-runner`: 동일 intent 재사용 시 Critical identity mismatch
- OWASP ASI03 Identity & Privilege Abuse / MITRE T1078 Valid Accounts 매핑

실제 Kind/Tetragon 검증 결과는 [Phase 7 문서](docs/PHASE7.md)와 [검증 증거](docs/evidence/phase7-kubernetes-identity.json)에 기록했습니다.

## Security controls

- **Default deny**: 정의되지 않은 도구와 권한은 기본 차단
- **Human in the loop**: 외부 전송은 자동 실행 대신 승인 대기
- **One-time capability**: 도구·인자 fingerprint·approval ID·만료 시각을 HMAC으로 바인딩하고 재사용 차단
- **Sensor authenticity**: observation 본문 전체를 별도 HMAC 키로 검증
- **Runtime correlation**: 허가되지 않은 process/network/file 행동 탐지
- **Privacy by design**: OCSF에는 원본 인자와 target 대신 SHA-256 fingerprint 기록
- **Network isolation**: 관리 포트는 loopback 전용, MCP는 내부 네트워크 전용
- **Container hardening**: non-root, read-only root filesystem, all capabilities dropped, `no-new-privileges`
- **Fail closed**: OPA 장애 또는 잘못된 sensor signature는 요청 거부

## Validation

```powershell
docker compose config --quiet
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-lab.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-tetragon.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-soc.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-detections.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-kubernetes.ps1
```

기본 검증은 OPA 5개 정책 테스트, Agent API 25개와 sensor 8개 단위 테스트, 정책 시나리오, 승인/replay 방어, runtime correlation, OCSF 비식별화를 확인합니다. Phase 4는 실제 커널 event, Phase 5/6는 SOC와 detection-as-code, Phase 7은 실제 Kind Pod UID·ServiceAccount·Tetragon event correlation을 검증합니다. GitHub Actions에서는 결정론적 통합 검증과 Phase 5~7 정적 자산 검증을 실행합니다.

## Tech stack

| Component | Role |
|---|---|
| FastAPI | Agent gateway, intent ledger, correlation API |
| MCP Python SDK | 격리된 tool server |
| Open Policy Agent 1.17 | Rego 기반 tool policy |
| Tetragon 1.7.0 | 실제 eBPF process/file/network runtime telemetry |
| OCSF 1.8 | API Activity, AI Operation, Detection Finding |
| OpenTelemetry + Jaeger 2.18 | Agent/tool distributed tracing |
| Elasticsearch 9.4.2 | OCSF index, mapping, 7-day retention |
| Logstash 9.4.2 | Idempotent OCSF collection and normalization |
| Kibana 9.4.2 | SOC metrics, severity and runtime hunt dashboard |
| ES|QL detection pack | Versioned agent runtime rules and idempotent alerts |
| Kind + Kubernetes 1.36 | Reproducible workload identity and ServiceAccount lab |
| Docker Compose | 격리·재현 가능한 로컬 환경 |

## Roadmap

- [x] OPA 기반 allow/review/deny policy
- [x] Human approval + one-time capability
- [x] OCSF 1.8 AI Operation evidence
- [x] Intent / runtime mismatch detection
- [x] Signed Tetragon JSON adapter
- [x] Docker Desktop WSL2 실센서 end-to-end 캡처 자동화
- [x] OCSF Logstash pipeline, Elasticsearch 보존 정책, Kibana hunt dashboard
- [x] OWASP Agentic Top 10 / MITRE ATT&CK 자동 매핑
- [x] ES|QL detection-as-code와 Kibana threat dashboard
- [x] Kind/Kubernetes Pod UID·ServiceAccount runtime correlation
- [ ] Kubernetes audit log와 RBAC privilege escalation correlation
- [ ] OAuth 2.1 기반 MCP 인증 및 tool scope
- [ ] Local LLM indirect prompt injection 재현
- [ ] Elastic native detection scheduling과 Slack/Teams alert connector

## References

- [Tetragon installation and requirements](https://tetragon.io/docs/installation/)
- [Tetragon TracingPolicy](https://tetragon.io/docs/concepts/tracing-policy/)
- [OCSF schema](https://github.com/ocsf/ocsf-schema)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [Elastic Stack installation](https://www.elastic.co/guide/en/elastic-stack/current/installing-elastic-stack.html)
- [Logstash HTTP poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [Elastic ES|QL detection rules](https://www.elastic.co/docs/solutions/security/detect-and-alert/esql)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [Tetragon Kubernetes deployment](https://tetragon.io/docs/installation/kubernetes/)
- [Kubernetes ServiceAccounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)

## Safety scope

이 저장소는 격리된 로컬 교육 환경용입니다. 공격 시나리오는 실제 외부 전송이나 셸 실행 없이 모의 처리합니다. Tetragon 정책은 관측 전용이며 운영 시스템에 적용하기 전에 대상 커널과 이벤트 부하를 별도로 검증해야 합니다. Phase 5/6 Elastic 보안 기능은 로컬 재현성을 위해 비활성화되어 있으므로 loopback 밖에 노출하지 말고 운영 환경에서는 TLS, 인증, Detection Engine 권한을 적용해야 합니다. Phase 7 Kind 클러스터는 전용 `arsl-phase7` 이름을 사용하며 테스트 workload의 ServiceAccount token automount를 비활성화합니다.
