# P1-HBR-01 — 8차 리뷰(HBR-01~06) 후속 조치

- 관련 Ticket: P1-HBR-01
- 관련 Issue: [321Team/fds-project-baseline#13](https://github.com/321Team/fds-project-baseline/issues/13)
- 대상 리뷰: [8차 리뷰](https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5644892615)
- 이전 조치: [7차 리뷰 후속 조치](./p1-hbr-01-r7-followup.md)
- 검토 대상이었던 HEAD: `7539e65c9d1ab21528391b44b44c836198b08b8e`

## 판정 대조표

| ID | 8차 리뷰 판정 | 조치 후 상태 | 대상 파일 |
|---|---|---|---|
| HBR-01 | OPEN — worker-pull의 `set +x`가 Secret 조건문 뒤, nerdctl 인증 저장소 격리·정리 없음 | ✅ 조치 | `worker-pull-pod-start-test.sh` |
| HBR-02 | PARTIAL — 조합 순서는 CLOSED, `review-run.env` source 실행 및 빈 필드 시 구값 상속 OPEN | ✅ 조치 | `worker-pull-pod-start-test.sh`, `worker-push-deny-test.sh` |
| HBR-03 | OPEN — 로그인 실패와 push 실패 판정이 합쳐져 로그인 실패만으로 DENY PASS 재현 | ✅ 조치 | `worker-pull-pod-start-test.sh`, `worker-push-deny-test.sh` |
| HBR-04 | CLOSED_STATIC | 변경 없음 (유지) | `tls-negative-test.sh` |
| HBR-05 | PARTIAL — Digest 부분 일치는 CLOSED, 실제 Pod apply/wait/cleanup·identity 인수 미완료 | ⚠️ 코드 반영 완료, Worker 3대 Runtime 실행은 별도 세션 필요 | `worker-pull-pod-start-test.sh`, `digest-traceability-check.sh` |
| HBR-06 | 간소화안 조건부 수용 / Robot Token `Never` 전제 정정 필요 | ✅ 문서 표현 정정 | `docs/reviews/p1-hbr-01-r8-followup.md` (본 파일) |

CLOSED_STATIC(HBR-04)은 이번 변경에서 건드리지 않았습니다.

## 항목별 조치 내용

### HBR-01 — Secret xtrace 노출 및 nerdctl 인증 저장소 격리

- `worker-pull-pod-start-test.sh`: `set +x`를 `WORKER_ROBOT_SECRET` 참조 이전(스크립트 최상단)으로 이동. 기존에는 Secret 존재 여부를 검사하는 `if` 문 자체가 호출자의 `bash -x` 트레이스에 찍혀 값이 노출될 수 있었습니다.
- 동일 파일의 `sudo nerdctl login/push/logout`에 격리된 임시 `DOCKER_CONFIG` 디렉터리(0700)를 적용하고, `trap ... EXIT INT TERM`으로 종료·오류·중단 시 항상 정리하도록 변경. 기존 root 공유 인증 저장소를 덮어쓰던 문제를 해소했습니다.
- `worker-push-deny-test.sh`의 `set +x` 위치는 7차 리뷰에서 이미 CLOSED로 확인된 상태라 변경하지 않았습니다.

### HBR-02 — `review-run.env` 실행(source) 및 값 상속 문제

- `source` 대신, 파일을 한 줄씩 읽어 허용 키(`TEST_TAG`, `REVIEW_RUN_ID`)만 값 형식을 검증(`^[A-Za-z0-9._:-]*$`)한 뒤 대입하는 파서로 교체. 허용되지 않은 키가 있으면 즉시 오류 처리합니다.
- 로드 직전 `unset TEST_TAG REVIEW_RUN_ID`를 실행해, 파일에 값이 없어도 쉘에 남아있던 이전 세션 값을 상속해 통과하던 문제를 차단했습니다.
- 이 로드 로직을 `worker-push-deny-test.sh`에도 동일하게 적용했습니다. 이 과정에서 **기존 `worker-push-deny-test.sh`가 `TEST_IMAGE` 변수를 어디서도 정의하지 않아 `set -u`에 의해 `unbound variable`로 항상 실패하던 잠재 결함**도 함께 발견·해소했습니다 (재현 결과는 아래 참고).

### HBR-03 — 로그인 실패와 Push 거부 판정 분리

- `worker-pull-pod-start-test.sh`: 기존에는 `login && push`를 하나의 커맨드 substitution 안에서 실행해, 로그인 자체가 `unauthorized: authentication required`로 실패해도(=push 미시도) 판정 grep 패턴과 우연히 일치해 "Push DENY PASS"로 오판할 수 있었습니다. 로그인과 push를 별도 단계·별도 exit code로 분리하고, 로그인 실패 시 즉시 `ERROR`로 중단하도록 수정했습니다.
- `worker-push-deny-test.sh`도 동일하게 로그인 단계의 exit code를 명시적으로 확인하도록 변경했습니다 (기존에도 login/push가 물리적으로 분리된 커맨드였으나, exit code를 확인하지 않고 넘어가는 경로가 있어 보강).

### HBR-05 — Pod Start 실제 검증 및 Digest 대상 명확화

- `worker-pull-pod-start-test.sh`에 실제 `kubectl run` → `kubectl wait --for=condition=Ready` → `imageID` 확인 → `trap`을 통한 Pod cleanup 로직을 추가했습니다. 기존에는 파일명(`pod-start-test`)과 달리 `crictl pull`까지만 수행하고 Pod 생성 자체를 하지 않았습니다.
- `NODE_NAME` 환경변수로 특정 Worker에 `nodeName`을 고정할 수 있게 해, Worker 3대(`.105/.107/.108`) 각각의 개별 실행 증적을 남길 수 있도록 했습니다.
- 최소 Restricted PSA 준수 오버라이드 템플릿(`scripts/verify/pod-restricted-psa-overrides.json`)을 추가했습니다. `non-root`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`를 기본값으로 둡니다.
- `digest-traceability-check.sh`: 첫 번째 `containerStatuses` 항목을 임의로 사용하지 않고 `container-name` 인자를 필수로 받도록 변경. `HARBOR_DIGEST`와 추출한 `POD_DIGEST` 모두 `^sha256:[0-9a-f]{64}$` 형식 검증을 추가해 index/manifest/config digest 혼동을 방지합니다.
- **Runtime 미실행 항목 (변경 없음)**: 이번 커밋은 코드 경로만 제공하며, Worker 3대 각각에서의 실제 실행·Pod Ready·Push DENY 증적은 노드 접근 승인 후 별도 Runtime 세션에서 수행합니다. AC-05 전체는 여전히 [P1-CICD-01 #16](https://github.com/321Team/fds-project-baseline/issues/16)의 CI Scan Digest 제공 전까지 BLOCKED입니다.

### HBR-06 — 문서 표현 정정 및 최소 기록 제안 (변경 없음 유지, 표현만 정정)

8차 리뷰는 "Robot Token `Never`는 승인된 예외"라는 전제가 발행 v3.1.18과 불일치한다고 지적했습니다. 이를 다음과 같이 정정합니다.

> Robot Token `Never`는 [발행 v3.1.18 Project Status](https://github.com/321Team/fds-project-baseline/blob/72599ae49342b0fb8dbd3d8ee60314afb9f907bb/baseline/FDS_Project_Implementation_Baseline_v3.1.18.md) 기준 **승인 대기 제안(Proposed / Approval Pending)** 상태입니다. 별도 승인 링크·범위·시점이 확보되기 전까지 완료 근거로 사용하지 않습니다.

7차 리뷰 후속 문서에서 제안한 간소화 방향(신규 provenance 플랫폼·체계 불필요, 기존 README·`99_SHA256SUMS.txt`·1회성 Secret scan 재사용)은 그대로 유지합니다.

## 재현 테스트 (리뷰어 제시 시나리오 기준, 모의시험)

로컬에서 `sudo/crictl/nerdctl/docker/kubectl`을 mock으로 대체해 재현했습니다. Harbor/Runner/Worker 실제 연결은 하지 않았습니다.

### #1 HBR-01 — xtrace를 통한 Secret 노출

```text
WORKER_ROBOT_SECRET="DUMMY_SECRET_SENTINEL_XYZ" bash -x worker-pull-pod-start-test.sh
수정 전: 기존 로직상 Secret 참조 조건문이 set +x보다 먼저 실행되어 노출 가능
수정 후: 트레이스 로그 내 DUMMY_SECRET_SENTINEL_XYZ 매치 0건, 스크립트 정상 종료(exit 0)
```

### #2 HBR-03 — 로그인 실패 시 Push DENY 오탐 PASS (worker-pull-pod-start-test.sh)

```text
mock: nerdctl login → exit 1 "unauthorized: authentication required" (push는 호출되지 않음)

수정 전(원본 7539e65): exit 0, "PASS: Worker Pull ALLOW 및 Push DENY(권한 거부) 확인 완료"
수정 후:               exit 1, "ERROR: 로그인 자체가 실패해 Push DENY 시험이 무효함"
```

### #3 HBR-03 — 동일 시나리오 (worker-push-deny-test.sh)

```text
mock: docker login → exit 1 "unauthorized: authentication required"

수정 후: exit 1, "ERROR: 로그인 자체가 실패해 Push DENY 시험이 무효함"
```

### #4 HBR-02 — TEST_TAG 누락 시 이전 세션 값 상속

```text
쉘에 TEST_TAG=stale-old-tag가 이미 export된 상태에서 review-run.env에 TEST_TAG가 없음

수정 전(source 방식 재현): TEST_TAG=stale-old-tag 그대로 사용 (빈 필드 감지 실패)
수정 후:                   "ERROR: TEST_TAG 또는 REVIEW_RUN_ID가 review-run.env에 비어 있습니다." (exit 1)
```

### #5 (부가 발견) worker-push-deny-test.sh의 `TEST_IMAGE` 미정의

HBR-02 로드 로직을 이식하는 과정에서 발견한 별도 결함입니다. 원본 `worker-push-deny-test.sh`는 `TEST_IMAGE` 변수를 어디서도 정의하지 않아, `docker tag "${TEST_IMAGE}" ...` 단계에서 `set -u`에 의해 항상 실패했습니다 (Push DENY가 사실상 한 번도 성공적으로 실행된 적이 없었을 가능성).

```text
수정 전: line 31: TEST_IMAGE: unbound variable (exit 1, 의도치 않은 실패)
수정 후: review-run.env에서 TEST_TAG를 로드해 TEST_IMAGE를 정상 구성, "PASS: 로그인 성공 후 Worker Push가 권한 거부로 정상 차단됨"
```

### #6 HBR-05 — Digest 대상 container 명시 및 형식 검증

```text
container-name 인자 누락:        "ERROR: ... 대상 container name을 명시하세요" (exit 1)
HARBOR_DIGEST 형식 오류(sha256 아님): "ERROR: HARBOR_DIGEST 형식이 올바르지 않음" (exit 1)
정상 일치:                       "PASS: Pod Digest가 Harbor Digest와 정확히 일치함" (exit 0)
```

## 미해결 / Runtime 미실행 (정직하게 명시)

- HBR-05: Worker 3대(`.105/.107/.108`) 실제 Pod Start·Push DENY 실행은 노드 접근 승인 후 별도 Runtime 세션에서 진행 예정. 이번 커밋은 실행 경로(코드)만 제공합니다.
- AC-05 전체: [P1-CICD-01 #16](https://github.com/321Team/fds-project-baseline/issues/16)의 CI Scan Digest 미제공으로 여전히 `BLOCKED / NOT VERIFIED`입니다.
- Root nerdctl 인증 저장소 실행 전후 `/root/.docker/config.json` 불변 확인은 실제 Worker 노드에서 재검증이 필요합니다 (mock 환경에서는 검증 불가).

## Secret 노출 여부

이번 변경 파일에는 평문 Secret/Credential이 포함되어 있지 않습니다. 재현 테스트에 사용한 값은 모두 더미(`DUMMY_SECRET_SENTINEL_XYZ`, `badsecret` 등)입니다.
