# Phase 9 진행 상황 — OAuth 2.1 MCP Authorization

작성 시점: 2026-07-25

진행률: **100%**

## 완료 체크리스트

- [x] `agent/phase-9-mcp-oauth-scopes` 브랜치 생성
- [x] 로컬 OAuth Authorization Server 구현
- [x] Authorization Code + PKCE S256 구현
- [x] RS256 JWT와 JWKS 구현
- [x] RFC 8707 resource audience 제한
- [x] MCP RFC 9728 Protected Resource Metadata 적용
- [x] MCP bearer token 서명·issuer·audience·만료 검증
- [x] 도구별 least-privilege scope 적용
- [x] Agent Gateway client credentials와 token cache 적용
- [x] 미인증·wrong resource·under-scope 공격 시나리오 구현
- [x] OWASP ASI03 / MITRE T1550.001 매핑
- [x] 실제 Docker Compose end-to-end 검증 통과
- [x] 정적 evidence에서 bearer token 원문 제외
- [x] Phase 9 포트폴리오 스크린샷 완성
- [x] README·GitHub Actions 최종 갱신
- [x] 전체 Docker 회귀 검증 통과
- [x] 자체 보안 리뷰와 PKCE code-consumption 보완
- [x] 최종 재검증
- [x] 커밋·푸시·Draft PR #8·GitHub Actions 확인

Phase 9는 2026-07-25 기준으로 완료되었다. Draft PR: https://github.com/teriyakki-jin/agent-runtime-security-lab/pull/8

## 실제 검증 결과

- 미인증 MCP initialize: HTTP 401
- PKCE method: S256
- 잘못된 resource token 요청: HTTP 400
- under-scoped tool call: blocked
- correctly scoped tool call: allowed
- raw bearer token exported: false
- finding: `High / mcp_oauth_scope_violation`
- threat mapping: `OWASP ASI03 / MITRE T1550.001`
