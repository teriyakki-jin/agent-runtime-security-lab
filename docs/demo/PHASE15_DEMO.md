# Phase 15 통합 공격 데모

영상 길이: **2분 20초** · **1280×720 H.264, 25fps**

| 구간 | 내용 |
|---|---|
| 00:00–00:20 | 원클릭 실행과 control plane health 확인 |
| 00:20–00:49 | 실행 전 정책·서명·SBOM·`tools/list` 검증과 차단 |
| 00:49–01:19 | Tetragon eBPF attach와 실제 file/process observation 탐지 |
| 01:19–01:46 | delegated-agent 인과 탐지, OAuth token 폐기, MCP 격리·복구 |
| 01:46–02:10 | 실제 Kibana OCSF 이벤트와 Critical 경보 확인 |
| 02:10–02:20 | 전체 teardown과 잔여 container·network·volume·sensor 0 확인 |

영상은 실제 로컬 재검증 결과와 실행 중 캡처한 Kibana 화면을 사용했으며, 이미지 다운로드·빌드·health 대기 구간만 편집했다. 수치는 [`phase15-portfolio-release.json`](../evidence/phase15-portfolio-release.json), Phase 13·14 evidence와 실시간 Tetragon·OCSF 검증 결과에서 가져왔다. 공격은 로컬 격리 환경에서만 재현하며 실제 외부 대상, shell execution, credential 원문을 포함하지 않는다.

전체 실습을 직접 재현하려면 다음 명령을 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-phase15-portfolio.ps1
```
