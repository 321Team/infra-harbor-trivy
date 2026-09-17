# P1-HBR-01 Worker 검증 스크립트 Runbook

이 절차는 Worker 3대(`k8s-worker01`/`.105`, `k8s-worker02`/`.107`, `k8s-worker03`/`.108`)에서 각각 수행합니다. 이 문서와 로컬 모의시험은 실제 실행 증적을 대체하지 않습니다.

## 1. 승인된 외부 입력과 사전 준비

| 입력 | 요구사항 |
| --- | --- |
| `KUBE_CONTEXT` | 승인된 클러스터 context. 모든 kubectl 호출에 명시적으로 사용 |
| `NAMESPACE` | 승인된 기존 namespace. `fds-verify`를 자동 생성/승인하지 않음 |
| `NODE_NAME` | 이번 실행 대상 Worker. 해당 Worker에서 직접 실행하고 호스트 증적도 수집 |
| `SERVICE_ACCOUNT_NAME` | 해당 namespace의 승인된 기존 ServiceAccount |
| `PULL_SECRET_NAME` | 같은 namespace의 기존 `kubernetes.io/dockerconfigjson` Secret. `auths["10.1.93.54"]`가 주입한 Worker Robot과 일치해야 함 |
| `WORKER_ROBOT_USER`, `WORKER_ROBOT_SECRET` | 승인된 주입 경로 사용. Secret을 CLI 인수·명령 이력·평문 증적 파일에 넣지 않음 |
| `EXPECTED_HARBOR_DIGEST` | 같은 review run/test tag에 대응하는 승인된 단일 플랫폼 Harbor manifest의 `sha256:...` |
| `CA_FILE` | Harbor Private CA 인증서 파일. TLS 검증을 우회하지 않음 |
| `review-run.env`, `review-run.env.sha256` | Runner가 전달한 원본 및 정확히 `review-run.env`를 대상으로 하는 체크섬 |
| `POD_OVERRIDES_FILE` | 승인된 Restricted PSA 템플릿. 기본값 `./pod-restricted-psa-overrides.json` |

필수 도구는 bash, jq, kubectl, curl, crictl, nerdctl, sudo입니다. kubectl은 `delete --raw <URI> -f -`로 DeleteOptions 본문을 전송할 수 있어야 합니다. 실행 주체에는 namespace/node/ServiceAccount 조회, 지정 Secret 조회, Pod create/get/watch/delete 권한이 필요합니다. 사전 조회가 거부되면 시험을 시작하지 않습니다. Secret 조회 권한을 줄 수 없다면 별도 승인된 검증 경로를 설계해야 하며 사전 검사를 생략하지 않습니다.

Secret의 자격증명은 파이프로만 검증하고 출력하거나 파일로 저장하지 않습니다. `--docker-password=<secret>` 같은 인수 전달 예시는 사용하지 않습니다. 스크립트는 namespace, ServiceAccount, Secret을 생성하거나 권한을 변경하지 않습니다.

기본 템플릿은 UID/GID 65532, Restricted 보안 설정과 `sleep 300`을 사용합니다. 승인된 시험 이미지가 해당 UID와 명령을 지원하는지 확인합니다. 300초는 Ready/Digest 확인과 정리에 여유를 주기 위한 시험 Pod 수명이며 보안 설정을 완화하지 않습니다.

Robot TTL은 승인된 30일 정책을 따릅니다. Scanner 유지 및 미해결 Critical/High의 Push/Deploy 차단 조건도 그대로 적용합니다. CI Scan Digest 생성은 #16 담당 범위입니다.

## 2. 실행과 판정 범위

위 입력을 승인된 경로로 준비한 뒤, 메타데이터/템플릿이 있는 작업 디렉터리에서 실행합니다.

```bash
# Secret 값을 여기에 입력하거나 명령줄 앞에 붙이지 않습니다.
# 해당 Worker에서 실행하며 worker02, worker03도 각각 반복합니다.
export KUBE_CONTEXT NAMESPACE NODE_NAME SERVICE_ACCOUNT_NAME PULL_SECRET_NAME
export EXPECTED_HARBOR_DIGEST CA_FILE WORKER_ROBOT_USER WORKER_ROBOT_SECRET
bash /path/to/infra-harbor-trivy/scripts/verify/worker-pull-pod-start-test.sh
```

직접 CRI Pull/Push DENY 검사는 `TEST_TAG`를 사용합니다. 검증 Pod는 `EXPECTED_HARBOR_DIGEST`로 고정하고 `imagePullPolicy: Always`, 지정 ServiceAccount/Secret, `automountServiceAccountToken: false`, 지정 Worker를 설정합니다. 따라서 실행 전 같은 run의 test tag와 승인 digest의 매핑 증적을 확보해야 합니다.

생성 응답에서 UID를 기록하고, 임의의 128비트 실행 nonce를 Pod 이름과 라벨에 넣습니다. Ready 이후 Digest 검증기를 실제로 실행하며 실패하면 부모 스크립트도 실패합니다. 한 Pod JSON 응답에서 UID·run·nonce·node·ServiceAccount·Secret·대상 container 이름·spec image·Ready 상태를 확인하고 Harbor manifest Digest와 imageID Digest를 완전 일치로 비교합니다. 컨테이너 상태 배열의 첫 항목에 의존하지 않습니다.

이 버전은 단일 플랫폼 manifest만 지원합니다. OCI index/Docker manifest list는 실패 처리합니다. 다중 플랫폼 이미지는 별도 child manifest 해석과 플랫폼 매핑 검증이 필요합니다.

## 3. UID 조건부 정리

정상·오류·INT·TERM 종료 모두 로컬 인증 디렉터리와 이 실행의 Pod 정리를 시도합니다. 생성 응답을 잃었어도 정확한 name/namespace/run/nonce가 일치하는 객체만 회수합니다. 생성 결과와 조회 모두 불확실하면 실패와 식별자를 남깁니다.

Pod 삭제는 Kubernetes API에 `DeleteOptions.preconditions.uid`를 본문으로 전달합니다. GET 후 이름만으로 삭제하는 절차는 사용하지 않습니다. DELETE 직전에 동명 Pod가 교체되면 API 서버가 UID 불일치 요청을 거부합니다. DELETE 요청 성공 뒤에도 실제 삭제 완료를 제한 시간 동안 확인합니다. 기본 완료 대기는 60초이며 각 API 호출 제한은 10초입니다.

GET 실패를 NotFound로 간주하지 않습니다. 조회 실패, UID 교체, DELETE 실패, 삭제 지연은 성공 종료를 차단합니다. 잔여 자원은 출력된 context/namespace/name/uid/invocation으로 조사하고, 수동 삭제가 필요해도 같은 UID precondition을 유지합니다. 로컬 이미지 캐시를 지우는 작업은 이 절차에 포함하지 않습니다.

## 4. 종료 코드와 승인 증적

- `0`: 스크립트 내 검사, Pod/Harbor Digest 결합 검사, 로컬/Pod 정리 성공.
- `130` / `143`: INT / TERM 중단. 중단 이후 Digest 검증의 후속 단계로 진행하지 않음.
- 그 밖의 nonzero: 검사·접근·정리 실패. curl/kubectl의 원래 오류 코드가 전파될 수 있음.

종료 코드 0만으로 AC-03/AC-05 전체 Runtime 완료를 선언하지 않습니다. Ready나 `Always` 정책도 실제 사용한 Robot의 단독 증명이 아닙니다. 승인 시에는 각 Worker의 동일 실행에 대해 다음을 확인합니다.

1. 실제 Worker 호스트, context, namespace, Pod UID/run/nonce, node, container, spec image 및 imageID 증적.
2. Harbor 측 같은 시각/저장소 요청과 Worker Robot actor, Pull 허용/Push 거부 및 인증·TLS·전송 오류가 섞이지 않았다는 증적. node/provider 등 다른 자격증명 사용 가능성을 구분.
3. #16에서 받은 CI Scan Digest, Harbor manifest, 배포 manifest, 실제 Pod의 동일 artifact 매핑. 이 스크립트의 2자 비교를 4/4로 표시하지 않음.
4. Worker 3대 결과, 정리 완료, Secret 미노출, 원본 체크섬. 필요한 TLS negative/allowlist 증적은 별도 해당 절차로 확인.

## 5. 관련 근거

- [R11 차단사항](https://github.com/321Team/infra-harbor-trivy/pull/2#pullrequestreview-5217739723)
- [Kubernetes DeleteOptions](https://kubernetes.io/docs/reference/kubernetes-api/definitions/delete-options-v1-meta/)
- [kubectl delete](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/)
- [Kubernetes image pull 동작](https://kubernetes.io/docs/concepts/containers/images/)
