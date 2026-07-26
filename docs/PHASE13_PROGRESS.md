# Phase 13 진행 기록

- [x] GitHub Actions 참조를 commit SHA로 고정
- [x] Docker base image를 digest로 고정
- [x] Python direct dependency exact pin 적용
- [x] transitive lockfile과 distribution hash 검증 적용
- [x] GitHub OIDC repository·workflow·ref identity 검증
- [x] Rekor inclusion proof를 생략하지 않는 keyless 검증
- [x] signed tool-manifest attestation 생성 및 검증
- [x] manifest schema v2에 MCP input schema hash 추가
- [x] 격리된 pre-admission 환경에서 실제 MCP `tools/list` 질의
- [x] 도구 추가·누락·중복·schema drift fail-closed 차단
- [x] SBOM vulnerability·license·required-component 정책 적용
- [x] 취약한 MCP SDK 1.27.2를 1.28.1로 갱신
- [x] gate·inventory·SBOM을 통과한 digest만 launcher로 실행
- [x] 실제 컨테이너의 `.Config.Image`가 admitted digest인지 검증
- [x] 공급망 테스트 26/26 및 커버리지 82% 통과
- [x] 로컬 end-to-end admission 검증
- [x] GitHub Keyless Supply Chain workflow 최종 통과
- [x] Draft PR 검증 완료

현재 진행률: **100%**
