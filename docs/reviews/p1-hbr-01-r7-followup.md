# P1-HBR-01 — 7차 리뷰(HBR-01~06) 후속 조치

- 관련 Ticket: P1-HBR-01
- 관련 Issue: fds-project-baseline#13
- 대상 리뷰 댓글: [7차 리뷰](https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5633336598)
- 검토 대상이었던 구현 댓글: [09-11 구현 절차](https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5627287809)

## 반영한 항목

| ID | 문제 | 조치 | 위치 |
|---|---|---|---|
| HBR-01 | Secret 참조 이후에 `set +x` 위치, NETRC `RETURN` trap으로 정리 미보장 | `set +x`를 Secret 참조 이전으로 이동, cleanup을 단일 `EXIT` trap으로 통합 | `scripts/verify/worker-push-deny-test.sh`, `scripts/verify/worker-pull-pod-start-test.sh` |
| HBR-02 | `TEST_IMAGE`를 `review-run.env` 로드 전에 조합해 빈 태그 가능 | 검증·로드 이후로 조합 순서 변경 | `scripts/verify/worker-pull-pod-start-test.sh` |
| HBR-03 | `denied\|unauthorized\|forbidden` 패턴이 이미지 참조 문자열(`:forbidden`)과 겹쳐 오탐 PASS 가능 | 판정 키워드를 태그명에서 제거, 정형 거부 문구로 매치 패턴 축소 | `scripts/verify/worker-push-deny-test.sh`, `scripts/verify/worker-pull-pod-start-test.sh` |
| HBR-04 | TLS 실패 판정이 `rc=60 OR 문자열` 이라 다른 원인과 혼재 가능 | `rc=60` 단독 판정으로 축소 | `scripts/verify/tls-negative-test.sh` |
| HBR-05 | Pod imageID와 Harbor Digest를 부분 문자열 포함으로 비교 | `sha256:...` 부분만 추출해 완전 일치 비교 | `scripts/verify/digest-traceability-check.sh` |

## HBR-06 관련 — 범위 협의 제안

AC-06(Credential 비노출·Evidence 무결성)의 목표는 유지하되, 아래와 같이 더 가벼운 방식으로 구현합니다. 상세 근거는 fds-project-baseline#13 코멘트로 별도 협의합니다.

| 원 요구 | 적용한 대체 구현 |
|---|---|
| Worker argv Credential 노출 (`ctr --user`) | `nerdctl --password-stdin`으로 교체 (반영 완료) |
| Credential Rotation/Fingerprint 체계 | Robot Account 생성일·만료정책·회전 여부를 evidence README에 1회 기록 |
| Secret Scan | 1회성 스캔(gitleaks 등) 결과 캡처로 대체 |
| SHA-256 검증 | 기존 관행인 `99_SHA256SUMS.txt`를 그대로 evidence 폴더에 적용 |
| commit/run/attempt/도구버전/timestamp/digest 전체 연결 인계표 | 생략 — AC-05(4/4 Digest 대조)가 이미지 신뢰성을 이미 증명하므로 중복. evidence README에 commit/run 링크 한 줄만 기록 |

## 미검증 항목 (변경 없음)

- AC-05 Digest Traceability: P1-CICD-01(#16)의 CI Scan Digest 제공 전까지 BLOCKED / NOT VERIFIED
- Worker 3대 각각의 Runtime 실행 증적은 실제 노드에서 재실행 필요
