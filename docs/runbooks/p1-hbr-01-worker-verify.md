# P1-HBR-01 Worker 검증 스크립트 Runbook

`scripts/verify/` 아래 검증 스크립트를 Worker 3대(`k8s-worker01`/`.105`, `k8s-worker02`/`.107`, `k8s-worker03`/`.108`)에서 실행할 때 따르는 절차입니다. 대상 스크립트:

- `worker-pull-pod-start-test.sh` — 인증 Pull, Pod Start, Push DENY
- `worker-push-deny-test.sh` — Docker 단독 경로 Push DENY
- `digest-traceability-check.sh` — Pod Digest ↔ Harbor manifest Digest 일치
- `tls-negative-test.sh` — TLS 인증서 검증 거부(HBR-04)

## 1. 사전 준비

- `WORKER_ROBOT_USER`, `WORKER_ROBOT_SECRET` — Worker Robot Account 자격증명을 환경변수로 주입합니다 (파일에 평문 저장 금지).
- `review-run.env`, `review-run.env.sha256` — Runner가 전달한 실행 메타데이터와 그 체크섬 파일을 스크립트와 같은 작업 디렉터리에 둡니다.
- `CA_FILE` — Harbor Private CA 인증서 경로 (`tls-negative-test.sh`, `digest-traceability-check.sh`에서 사용).
- `pod-restricted-psa-overrides.json` — Restricted PSA Pod 템플릿.
- Worker 노드에 대한 `kubectl` context가 올바른 클러스터/네임스페이스를 가리키는지 먼저 확인합니다.

각 Worker에서 **개별적으로** 실행합니다. 한 Host의 결과로 나머지 2대를 대체하지 않습니다 (README 8절 원칙).

## 2. 실행

```bash
NAMESPACE=fds-verify NODE_NAME=k8s-worker01 \
  WORKER_ROBOT_USER=... WORKER_ROBOT_SECRET=... \
  ./worker-pull-pod-start-test.sh
```

worker02, worker03도 `NODE_NAME`만 바꿔 동일하게 실행합니다.

## 3. Pod Cleanup — 자동 삭제하지 않습니다

`worker-pull-pod-start-test.sh`는 검증용 Pod를 **자동으로 삭제하지 않습니다.** 과거(R9까지) 버전은 스크립트가 알아서 Pod를 지우려 시도했는데, 다음과 같은 상태를 `rc=0`(성공)으로 숨길 위험이 있다는 지적(R10 리뷰)에 따라 자동 삭제 로직 자체를 제거했습니다.

- 삭제 요청은 보냈지만 실제로는 실패한 경우
- 확인한 시점과 삭제를 실행하는 시점 사이에 Pod가 교체되어, 이 실행이 만든 Pod가 아닌 다른 Pod를 지우는 경우
- 중단 신호(SIGINT/SIGTERM)를 받았는데도 종료 코드가 0으로 기록되는 경우

대신 스크립트 종료 시 **이 실행이 실제로 만든 Pod의 이름과 UID를 화면에 출력**하고, 사람이 직접 확인 후 지우도록 안내합니다. 예:

```text
정리 필요: 이 실행이 만든 Pod가 아직 남아 있습니다. 아래로 UID를 다시 확인한 뒤 직접 삭제하세요.
  kubectl get pod p1-hbr-verify-<run-id> -n fds-verify -o jsonpath='{.metadata.uid}'   # <uid> 와 일치하는지 확인
  kubectl delete pod p1-hbr-verify-<run-id> -n fds-verify
```

**운영자는 반드시:**

1. 출력된 `kubectl get ... jsonpath='{.metadata.uid}'` 명령을 그대로 실행해, 안내에 적힌 UID와 실제 UID가 일치하는지 눈으로 확인합니다.
2. 일치할 때만 `kubectl delete pod ...`를 실행합니다.
3. 안내 메시지가 "다른 실행/다른 프로세스 소유일 수 있으니 삭제하지 마세요"라고 나오면, **자동으로도 수동으로도 지우지 않고** 담당자에게 확인을 요청합니다.

스크립트가 출력하는 Pod 이름/UID는 실행마다 달라지므로 이 문서에는 고정된 명령을 싣지 않습니다 — 실제 실행 시 터미널 출력을 그대로 따르세요.

## 4. 실패/중단 시 종료 코드

- `0`: 시험 성공 및 로컬 정리(nerdctl logout, 임시 인증 디렉터리 삭제) 완료.
- `1`: 시험 실패(`FAIL`/`ERROR`), 또는 시험은 성공했으나 로컬 정리가 실패해 잔여 상태가 있음.
- `130`: SIGINT(Ctrl+C)로 중단됨.
- `143`: SIGTERM으로 중단됨.

`0`이 아닌 경우 반드시 위 3절의 Pod 정리 안내를 확인하고, 임시 인증 디렉터리(`WARN`으로 경로가 출력됨)가 남아있지 않은지 확인합니다.

## 5. 관련 리뷰

- [R9 후속 검토](https://github.com/321Team/infra-harbor-trivy/pull/2#issuecomment-5647308804)
- [R10 딥리뷰](https://github.com/321Team/infra-harbor-trivy/pull/2#pullrequestreview-5217513542) — 자동 삭제 제거의 근거가 된 재현 사례(A~D)
