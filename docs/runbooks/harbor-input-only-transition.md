# Harbor 동일 코드의 nft 입력 전환

CODEX_ASSISTED. `.50` 회수의 관리자 입력 전환을 위한 파일 전용 adapter다.
연계: [Ansible PR84](https://github.com/321Team/infra-ansible/pull/84),
[baseline#13](https://github.com/321Team/fds-project-baseline/issues/13).
작성·시험·리뷰·병합·실행·AC는 각각 별도 상태다. 이 문서나 시험용 fixture가
실제 package/request 또는 현장 실행 허용을 대신하지 않는다.

## 문제와 변경 범위

기존 `harbor_review_package_install.py`는 15개 대상이 모두 새 파일인 최초
설치용이다. 동일 bytes의 source/bootstrap/unit도 이미 존재하면 중단한다.
기존 파일을 삭제하거나 새 코드 revision을 꾸며 이 검사를 우회하지 않는다.

새 `scripts/preparation/harbor_input_transition.py`는 다음만 허용한다.

- 독립적으로 해시 검증한 기존/신규 16파일 패키지. 코드11개·bootstrap·unit
  13파일의 bytes/경로/owner/mode/context가 정확히 같아야 한다.
- v4 bundle의 `host_policy.nft_sha256`, 새 `store.path`, 파생 execution binding만
  변경한다. 그 외 신원·network·원본 pin·앱 ID/구성·예산·labels는 동일해야 한다.
- 새 bundle을 O_EXCL로 생성하고 검증한다. 기존 launch를 같은 부모 디렉터리의
  지정된 새 이름에 `renameat2(RENAME_NOREPLACE)`로 보존한다. 새 launch는 마지막에
  O_EXCL로 생성한다. syscall 미지원/실패 시 다른 rename 방법으로 대체하지 않는다.
- 기존 bundle, 코드, Store, claim은 보존한다. 새 Store는 미리 준비된 빈 디렉터리다.
  파일/디렉터리 생성·재라벨·기존권한수정, Store 초기화, 정책/서비스/nft 변경은 하지 않는다.

## 실제 실행의 선행조건과 순서

실행자: 운영 대상의 승인된 root 콘솔/검증된 관리 경로. adapter와 검증 의존성은
후보 패키지와 별도로 신뢰 가능한 검토 checkout에서 실행한다. 후보 Python은
bytes 검증·compile만 하며 import하지 않는다. 다른 root 작성자는 배제한다.

1. 정확 코드와 신규/기존 패키지 검토, 실제 경로/labels/예산·비중첩을 확정한다.
   기존 코드 revision은 유지한다. adapter PR revision을 runtime revision으로
   자동 치환하지 않는다. 실제 새 경로/boot/window를 이 문서에서 생성하지 않는다.
2. 기존 관리자에 명시적 HOLD를 적용하고 정상 정지·disable한다. 이후 봉인한
   `state.json`은 OPERATOR_HOLD·pending/health_wait 없음, 현재 boot/daemon 및
   기존 plan digest와 일치해야 한다. `.pending` 잔여가 있으면 진행하지 않는다.
3. 기존/새 Store와 모든 부모의 root 소유·mode·SELinux·ACL을 직접 대조한다.
   기존 Store는 전체 파일 이름/크기/SHA를 봉인한다(잠금 파일 포함). 새 Store는
   0700/지정 context이며 비어 있어야 한다. adapter는 기존 manager/controller
   잠금을 쓰기 없이 잡고 파일·디렉터리를 다시 대조한다.
4. Ansible 회수 절차에 따라 정확 5개 영구 source/kernel table을 먼저 적용·검증한다.
   새 bundle의 미리 검토한 nft 해시와 실제 값이 일치한 후에만 adapter를 실행한다.
   실제값을 가져와 자동으로 입력 해시를 갱신하지 않는다. guard/Docker restart는 없다.
5. 외부 SHA로 결속한 request로 adapter를 **한 번** 실행한다. 관리자 disabled/inactive/
   dead, PID/ControlPID0, Job 없음과 현행 host guard를 각 파일 변경 전후 조회한다.
   앱10개 ID/fingerprint/healthy/restart 정책, PID/StartedAt/restart count를 고정한다.
6. 성공은 `INPUT_FILES_TRANSITIONED_ONLY`이다. 이후 별도 검토된 writer 시험,
   기존 정책 전환과 새 Store 초기화·arm·manager 복귀 절차를 수행한다. adapter 성공을
   Runtime/서비스 가용성/AC 성공으로 표시하지 않는다.

## Request 계약

`fds.harbor.input-transition-request.v1`, operation `SAME_CODE_NFT_INPUT_ONLY`
(또는 아래 `SAME_CODE_NFT_ROUTE_INPUT` + `route_change`).
미정 값은 준비 목록에만 남기고 실제 request를 만들지 않는다.

| 필드 | 실제 값의 근거 |
|---|---|
| old_plan_sha256 / new_plan_sha256 | 검토할 각 INSTALL_PLAN.json의 외부 SHA |
| hostname / product_uuid / boot_id / daemon_invocation_id | 직전 실제 신원·boot·Docker InvocationID |
| not_before_epoch / expires_epoch | 확정한 유효기간을 실행 직전 시각에 결속 |
| directories | 모든 대상 부모·기존/새 Store의 정확 mode/gid0/SELinux; 추가 경로 거부 |
| receipt_path / receipt_context | 준비된0700 install-receipts 부모 아래 신규32hex.jsonl, 실제 상속 context |
| preserved_launch_path | /etc/fds-harbor-recovery/launch.32hex.preserved.json, 기존 파일 없어야 함 |
| old_store_files | 정상 HOLD/정지 이후 전체 목록: 이름별 bytes/sha256; root0600/기존 file context |
| containers | plan의10개 서비스별 실제 pid/started_at/restart_count |

실행 명세(변수는 실제 입력 검토를 마친 경로·값이며 예시 값으로 채우지 않는다):

```bash
/usr/bin/python3.12 -B -I -S "$TRUSTED/scripts/preparation/harbor_input_transition.py" \
  --old-package "$OLD_PACKAGE" --old-plan-sha256 "$OLD_PLAN_SHA" \
  --package "$NEW_PACKAGE" --plan-sha256 "$NEW_PLAN_SHA" \
  --request "$REQUEST" --request-sha256 "$REQUEST_SHA" \
  --timeout "$APPROVED_SECONDS" --execute
```

CLI는 root, Linux, Python>=3.10, isolated/no-site/-B, 최적화 비활성을 요구한다.
기존 확정 설치 상한을 자동 늘리지 않는다. 코드상의 600초 제한은 허용 최대치이며
승인된 현장 예산이 아니다. 전체 host 검증 비용도 실행 상한에 포함된다.

### P2 반환 경로 동작 `SAME_CODE_NFT_ROUTE_INPUT` (infra-rosa#12 C3)

ROSA cold-pull 창 B의 harbor01 반환 경로(`10.20.0.0/16 via 10.1.93.51 dev ens160`, runtime)는
host policy의 `network.routes_sha256`도 바꾼다. 기존 동작은 이를 `TRANSITION_SCOPE_CHANGED`로
거부하므로, 같은 코드·같은 순서에 다음만 더한 별도 동작을 쓴다. 기존 동작은 바뀌지 않는다.

- 패키지: `nft_sha256`·`network.routes_sha256`·Store 경로·파생 binding만 달라야 한다.
  routes 지문이 같으면 `TRANSITION_NEW_ROUTE_INPUT_REQUIRED`, 그 밖의 차이는 기존처럼 거부.
- request: 위 필드 + `route_change` = `ADD_P2_RETURN`(적용 전환) 또는 `REMOVE_P2_RETURN`(회수 전환).
- Preflight: 새 bundle host 검증의 처음·마지막 조회 때마다 `ip -j -4 route show table all`(정책 고정
  `ip`, host provider와 같은 제한 실행기)을 읽는다. ADD는 `dst=10.20.0.0/16`인 행이 **정확히 1개**이고
  `gateway=10.1.93.51`·`dev=ens160`·main table·unicast·다중 next-hop 없음이어야 한다. REMOVE는 그 행이
  없어야 한다. 그 밖의 경로·더 넓은 대역은 받지 않는다.
- 이 도구는 route도 nft도 적용하지 않는다. 운영자가 승인 절차로 route·guard를 먼저 바꾸고, 새 bundle의
  두 지문이 실제와 맞을 때만 실행한다. 실패 시 자기 추가분 정리·원상 readback은 운영 절차가 맡는다.
- 한계: 새 routes 지문이 "이전 + 이 1줄"과 같다는 것을 이 도구가 다시 계산해 증명하지는 않는다.
  그 증거는 운영 절차의 route 전후 원문(`ip -j route show table all`) 대조로 남긴다.

## 실패와 복구 경계

배타적 receipt를 먼저 만들고 각 변경 intent/fsync, 결과/readback을 기록한다.
중단 후 자동 삭제·재시도·resume·원복은 없다. receipt와 모든 부분 파일을 보존한다.

| 마지막 변경 | 보존/확인할 상태 |
|---|---|
| receipt만 생성 | 기존 launch/Store 유지; 미실행으로 단정하기 전에 실제 파일 확인 |
| 새 bundle 생성 | 기존 launch 유지; 새 bundle을 지우거나 재사용하지 않음 |
| launch 보존 | 고정 launch가 없을 수 있음; 관리자는 정지 유지, 보존 이름/bytes/inode 확인 |
| 새 launch 생성 | 내용·메타데이터/host/Store 최종 대조 실패 가능; 성공으로 간주하지 않음 |

기한/디스크 오류로 STOP 기록 자체도 실패할 수 있다. 마지막 durable intent와
실제 파일 상태를 함께 확인한다. 파일 전환은 여러 filesystem 연산이므로 전체를
하나의 원자적 transaction이라고 부르지 않는다. launch 보존은 덮어쓰기 없는 단일
rename이다. 별도 최소 복구안을 실제 부분 상태로 검토하며 다른 Store의 claim을
합치거나 기존 claim을 지우지 않는다. 기존 nft로 복구하려면 해당 launch/bundle의
nft 입력도 일치해야 하며, manager 복귀를 자동 수행하지 않는다.

## 검증

집중 시험은 새/기존 패키지 결속, 범위 초과, HOLD/세대, 기존 claim 변조,
새 Store 오염, 기존 대상, 각 변경 직후 실패, 기한, 디렉터리 교체, 재실행 차단,
GET-only host/container 검증을 다룬다. Linux 임시 파일 시험은 실제 renameat2,
inode 보존, 덮어쓰기 거부, 잠금 충돌·symlink/hardlink·mode/hash를 확인한다.
임시 시험의 SELinux 검사는 주입되므로 실제 서비스 writer/상속 label 검증을
대신하지 않는다. 실서버 설치/전환·트래픽 검증·AC는 별도로 남긴다.
